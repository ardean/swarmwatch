// Package watch ties collection, registry checks, vulnerability scans and findings together.
// Both the CLI and the long-running server use it.
package watch

import (
	"context"
	"sync"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/exposure"
	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/sshx"
	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/vuln"
)

// Checker looks up registry digests and remembers them for a while, so a
// frequently refreshing server does not hammer registries.
type Checker struct {
	TTL time.Duration

	mu      sync.Mutex
	entries map[key]entry
	client  *registry.Client
}

type key struct{ image, digest string }
type entry struct {
	res *registry.Result
	at  time.Time
}

func NewChecker(ttl time.Duration) *Checker {
	return &Checker{TTL: ttl, entries: map[key]entry{}, client: registry.New()}
}

// Apply sets Service.Update for every service with a known running digest.
func (c *Checker) Apply(ctx context.Context, snaps []*swarm.Snapshot) {
	for _, s := range snaps {
		c.client.AddDockerConfig(s.DockerConfig)
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, s := range snaps {
		for _, v := range s.Services {
			if v.Digest == "" {
				continue
			}
			k := key{v.Image, v.Digest}
			c.mu.Lock()
			e, ok := c.entries[k]
			fresh := ok && time.Since(e.at) < c.TTL
			if !fresh {
				// claim the lookup so the same image is not fetched twice
				c.entries[k] = entry{at: time.Now()}
			}
			c.mu.Unlock()
			if fresh {
				continue
			}
			wg.Add(1)
			go func(k key) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				r := c.client.Check(ctx, k.image, k.digest)
				c.mu.Lock()
				c.entries[k] = entry{res: &r, at: time.Now()}
				c.mu.Unlock()
			}(k)
		}
	}
	wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range snaps {
		for _, v := range s.Services {
			if e, ok := c.entries[key{v.Image, v.Digest}]; ok && e.res != nil {
				v.Update = e.res
			}
		}
	}
}

// Gather collects all swarms in parallel, works out service exposure, then adds cached
// vulnerability data and, if checker is non-nil, registry update status. external holds
// Traefik routes learned from peer instances.
func Gather(ctx context.Context, cfg *config.Config, cache *vuln.Cache, checker *Checker, external []swarm.Route) []*swarm.Snapshot {
	snaps := make([]*swarm.Snapshot, len(cfg.Swarms))
	var wg sync.WaitGroup
	for i, sw := range cfg.Swarms {
		wg.Add(1)
		go func(i int, sw config.Swarm) {
			defer wg.Done()
			snaps[i] = swarm.Collect(ctx, sw)
		}(i, sw)
	}
	wg.Wait()
	exposure.Analyze(ctx, cfg, snaps, external)
	for _, s := range snaps {
		for _, v := range s.Services {
			v.Vuln = cache.Get(vuln.Key(v.Image, v.Digest))
		}
	}
	if checker != nil {
		checker.Apply(ctx, snaps)
	}
	return snaps
}

func Findings(cfg *config.Config, snaps []*swarm.Snapshot) []swarm.Finding {
	var out []swarm.Finding
	for _, s := range snaps {
		out = append(out, s.Findings(cfg.Thresholds, cfg.Scan.MaxAge)...)
	}
	return out
}

// Event reports scan progress.
type Event struct {
	Swarm       string
	Image       string
	Done, Total int
	Err         error
	Summary     *vuln.Summary
}

// StaleImages counts distinct images in a swarm whose scan result is missing or older than maxAge.
func StaleImages(s *swarm.Snapshot, cache *vuln.Cache, maxAge time.Duration) int {
	return len(staleJobs(s, cache, maxAge, false))
}

type job struct{ key, image string }

func staleJobs(s *swarm.Snapshot, cache *vuln.Cache, maxAge time.Duration, force bool) []job {
	var jobs []job
	seen := map[string]bool{}
	for _, v := range s.Services {
		k := vuln.Key(v.Image, v.Digest)
		if seen[k] {
			continue
		}
		seen[k] = true
		if c := cache.Get(k); !force && c != nil && time.Since(c.ScannedAt) < maxAge {
			continue
		}
		jobs = append(jobs, job{k, v.Image})
	}
	return jobs
}

// ScanStale scans every stale image. Swarms run in parallel; images within a swarm one
// at a time because Trivy locks its cache directory.
func ScanStale(ctx context.Context, cfg *config.Config, snaps []*swarm.Snapshot, cache *vuln.Cache, force bool, on func(Event)) {
	var wg sync.WaitGroup
	for i, s := range snaps {
		if s.Err != "" {
			continue
		}
		jobs := staleJobs(s, cache, cfg.Scan.MaxAge, force)
		runner := sshx.Runner{Dest: cfg.Swarms[i].SSH}
		wg.Add(1)
		go func(name string, jobs []job) {
			defer wg.Done()
			for n, j := range jobs {
				if ctx.Err() != nil {
					return
				}
				sum, err := vuln.Scan(ctx, runner, cfg.Scan.TrivyImage, j.image)
				if err == nil {
					err = cache.Put(j.key, sum)
				}
				on(Event{Swarm: name, Image: j.image, Done: n + 1, Total: len(jobs), Err: err, Summary: sum})
			}
		}(s.Name, jobs)
	}
	wg.Wait()
}
