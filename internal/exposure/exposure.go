// Package exposure works out which services can be reached from the internet, only from the LAN,
// or not from outside at all — from the real Traefik configuration and published ports.
//
// Levels:
//
//	internet      a Traefik route without a LAN-only restriction (or the Traefik gateway itself)
//	internet-sso  the same, but every public route sits behind a forward-auth / basic-auth gate
//	lan           only Traefik routes restricted to private source ranges, or a published port
//	internal      no route and no published port: reachable only on the swarm's own networks
//
// "internet" means routed to the public: whether the router actually forwards ports 80/443 to
// Traefik cannot be seen from here.
package exposure

import (
	"context"
	"sort"
	"strings"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/sshx"
	"github.com/ardean/swarmwatch/internal/swarm"
)

const (
	Internet    = "internet"
	InternetSSO = "internet-sso"
	LAN         = "lan"
	Internal    = "internal"
)

// Rank orders levels by how exposed they are (higher is more exposed).
func Rank(level string) int {
	switch level {
	case Internet:
		return 4
	case InternetSSO:
		return 3
	case LAN:
		return 2
	case Internal:
		return 1
	}
	return 0
}

// Analyze sets Service.Exposure on every service of every reachable swarm and Snapshot.Routes.
// snaps must be index-aligned with cfg.Swarms. external holds routes learned from other
// instances (peers) whose Traefik proxies to services in these swarms.
func Analyze(ctx context.Context, cfg *config.Config, snaps []*swarm.Snapshot, external []swarm.Route) {
	defs := make([]map[string]mw, len(snaps))
	for i, s := range snaps {
		if s.Err != "" {
			continue
		}
		sw := cfg.Swarms[i]
		defs[i] = labelMiddlewares(s)
		for _, svc := range s.Services {
			if !isTraefik(svc.Image) {
				continue
			}
			files := readTraefikFiles(ctx, sshx.Runner{Dest: sw.SSH}, sw.HostRoot, svc)
			for _, f := range files {
				for name, m := range f.middlewares() {
					defs[i][name] = m
				}
			}
			for _, f := range files {
				s.Routes = append(s.Routes, f.routes(s.Name, defs[i])...)
			}
			break
		}
	}
	all := append([]swarm.Route(nil), external...)
	for _, s := range snaps {
		all = append(all, s.Routes...)
	}
	for i, s := range snaps {
		if s.Err != "" {
			continue
		}
		for _, svc := range s.Services {
			svc.Exposure = classify(s, svc, defs[i], all)
		}
	}
}

type hit struct {
	hosts         []string
	lanOnly, auth bool
}

func classify(s *swarm.Snapshot, svc *swarm.Service, defs map[string]mw, routes []swarm.Route) *swarm.Exposure {
	var hits []hit

	// Routes declared by labels on the service itself (Traefik's swarm provider).
	if svc.Labels["traefik.enable"] == "true" {
		for _, r := range labelRouters(svc.Labels) {
			m := resolve(r.mws, defs)
			if m.redirect {
				continue
			}
			hits = append(hits, hit{hostsFromRule(r.rule), m.lanOnly, m.auth})
		}
	}

	// Routes from file-provider configs that proxy to this service's published port.
	ports := map[int]bool{}
	var published []int
	for _, p := range svc.Ports {
		if !ports[p.Published] {
			ports[p.Published] = true
			published = append(published, p.Published)
		}
	}
	sort.Ints(published)
	local := map[string]bool{"localhost": true, "127.0.0.1": true}
	for _, a := range s.Host.Addrs {
		local[a] = true
	}
	_, short, hasStack := strings.Cut(svc.Name, svc.Stack+"_")
	if !hasStack {
		short = svc.Name
	}
	for _, r := range routes {
		if r.BackendPort == 0 {
			continue
		}
		byAddr := local[r.BackendHost] && ports[r.BackendPort]
		byDNS := r.Swarm == s.Name && (r.BackendHost == svc.Name || r.BackendHost == short)
		if byAddr || byDNS {
			hits = append(hits, hit{r.Hosts, r.LANOnly, r.Auth})
		}
	}

	e := &swarm.Exposure{Ports: published}
	var publicHosts, lanHosts []string
	publicRoutes, gated := 0, 0
	for _, h := range hits {
		if h.lanOnly {
			lanHosts = append(lanHosts, h.hosts...)
			continue
		}
		publicRoutes++
		if h.auth {
			gated++
		}
		publicHosts = append(publicHosts, h.hosts...)
	}
	switch {
	case isTraefik(svc.Image) && (ports[80] || ports[443]):
		e.Level, e.Gateway = Internet, true
	case publicRoutes > 0 && gated == publicRoutes:
		e.Level, e.Hosts = InternetSSO, uniq(publicHosts)
	case publicRoutes > 0:
		e.Level, e.Hosts = Internet, uniq(publicHosts)
	case len(hits) > 0:
		e.Level, e.Hosts = LAN, uniq(lanHosts)
	case len(published) > 0 || svc.HostNetwork:
		e.Level = LAN
	default:
		e.Level = Internal
	}
	return e
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
