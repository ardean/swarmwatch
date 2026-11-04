package swarm

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/sshx"
)

// UnusedImage is an image no container (running or stopped) uses and no service refers to.
type UnusedImage struct {
	ID      string    `json:"id"`
	Tags    []string  `json:"tags,omitempty"` // empty = dangling
	Size    uint64    `json:"size"`
	Created time.Time `json:"created,omitempty"`
	// Blockers are stopped swarm task containers that still pin the image; they go first when cleaning.
	Blockers []string `json:"blockers,omitempty"`
}

// StoppedContainer is a stopped container that is not a swarm task (swarm cleans its own).
type StoppedContainer struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Image   string    `json:"image"`
	Status  string    `json:"status"`
	Created time.Time `json:"created,omitempty"`
}

// Unused is what could be removed from the manager's Docker engine. Only the manager is looked at:
// images and containers on other swarm nodes are not visible from here.
type Unused struct {
	Images     []UnusedImage      `json:"images,omitempty"`
	Containers []StoppedContainer `json:"containers,omitempty"`
	ImageBytes uint64             `json:"image_bytes"` // upper bound: layers shared with other images stay
}

func (u *Unused) Empty() bool { return u == nil || (len(u.Images) == 0 && len(u.Containers) == 0) }

// commands whose output findUnused reads.
const (
	cmdImages  = `docker image ls --no-trunc --format '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}'`
	cmdAllPS   = `docker ps -a --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Label "com.docker.swarm.service.name"}}\t{{.Image}}\t{{.CreatedAt}}'`
	cmdUsedIDs = `docker ps -aq --no-trunc | xargs -r docker inspect -f '{{.Id}}	{{.Image}}'`
	cmdSvcImgs = `docker service ls --format '{{.Image}}'`
)

// normalizeRef makes "docker.io/library/nginx@sha256:..", "nginx" and "nginx:latest" comparable.
func normalizeRef(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	for _, p := range []string{"index.docker.io/", "docker.io/"} {
		ref = strings.TrimPrefix(ref, p)
	}
	ref = strings.TrimPrefix(ref, "library/")
	if i := strings.LastIndex(ref, "/"); !strings.Contains(ref[i+1:], ":") {
		ref += ":latest"
	}
	return ref
}

func parseDockerTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if len(s) >= 25 {
		if t, err := time.Parse("2006-01-02 15:04:05 -0700", s[:25]); err == nil {
			return t
		}
	}
	return time.Time{}
}

// findUnused decides what is unused. An image is in use when any container (even stopped) was created
// from it, or when a swarm service names one of its tags (a service scaled to 0 keeps its image).
// serviceImages are image references of the swarm's services.
func findUnused(images, ps, usedIDs []byte, serviceImages []string) *Unused {
	// Classify containers: stopped swarm tasks are leftovers swarm itself would drop, so they do not
	// keep an image alive; everything else (running, or any standalone container) does.
	ctrs := map[string]string{} // container id -> "task" | "live"
	u := &Unused{}
	for _, l := range strings.Split(string(ps), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 7 {
			continue
		}
		ctrs[f[0]] = "live"
		switch f[2] {
		case "exited", "created", "dead":
			if f[4] != "" {
				ctrs[f[0]] = "task"
			} else {
				u.Containers = append(u.Containers, StoppedContainer{ID: f[0], Name: f[1], Status: f[3], Image: f[5], Created: parseDockerTime(f[6])})
			}
		}
	}
	live := map[string]bool{}         // image id -> used by a live container
	blockers := map[string][]string{} // image id -> stopped swarm task containers
	for _, l := range strings.Split(string(usedIDs), "\n") {
		f := strings.Split(strings.TrimSpace(l), "\t")
		if len(f) != 2 {
			continue
		}
		if ctrs[f[0]] == "task" {
			blockers[f[1]] = append(blockers[f[1]], f[0])
		} else {
			live[f[1]] = true
		}
	}
	wanted := map[string]bool{}
	for _, r := range serviceImages {
		if r = strings.TrimSpace(r); r != "" {
			wanted[normalizeRef(r)] = true
		}
	}

	type img struct {
		UnusedImage
		inUse bool
	}
	var order []string
	byID := map[string]*img{}
	for _, l := range strings.Split(string(images), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 5 {
			continue
		}
		id, repo, tag := f[0], f[1], f[2]
		im := byID[id]
		if im == nil {
			im = &img{UnusedImage: UnusedImage{ID: id, Size: parseSize(f[3]), Created: parseDockerTime(f[4])}, inUse: live[id]}
			byID[id] = im
			order = append(order, id)
		}
		if repo != "<none>" && tag != "<none>" {
			ref := repo + ":" + tag
			im.Tags = append(im.Tags, ref)
			if wanted[normalizeRef(ref)] {
				im.inUse = true
			}
		}
	}
	for _, id := range order {
		if im := byID[id]; !im.inUse {
			im.Blockers = blockers[id]
			u.Images = append(u.Images, im.UnusedImage)
			u.ImageBytes += im.Size
		}
	}
	return u
}

var idRe = regexp.MustCompile(`^(sha256:)?[a-f0-9]{12,64}$`)

// CleanResult says what a Clean call did.
type CleanResult struct {
	Images     int      `json:"images"`
	Containers int      `json:"containers"`
	Freed      uint64   `json:"freed"` // upper bound, see Unused.ImageBytes
	Skipped    int      `json:"skipped"`
	Errors     []string `json:"errors,omitempty"`
}

// Clean removes the given images and stopped containers, but only those that are still unused right
// now. It never forces removal, so Docker refuses anything that turned out to be in use.
func Clean(ctx context.Context, h config.Swarm, imageIDs, containerIDs []string) CleanResult {
	var res CleanResult
	r := sshx.Runner{Dest: h.SSH}
	run := func(c string) []byte { out, _ := r.Run(ctx, c); return out }
	imgs, ps, used, svc := run(cmdImages), run(cmdAllPS), run(cmdUsedIDs), run(cmdSvcImgs)
	if len(imgs) == 0 && len(ps) == 0 {
		res.Errors = append(res.Errors, "could not list images and containers on "+h.Name)
		return res
	}
	now := findUnused(imgs, ps, used, strings.Split(string(svc), "\n"))

	byID := map[string]UnusedImage{}
	for _, i := range now.Images {
		byID[i.ID] = i
	}
	stopped := map[string]bool{}
	for _, c := range now.Containers {
		stopped[c.ID] = true
	}
	for _, id := range containerIDs {
		if !idRe.MatchString(id) || !stopped[id] {
			res.Skipped++
			continue
		}
		if _, err := r.Run(ctx, "docker container rm "+id); err != nil {
			res.Errors = append(res.Errors, err.Error())
			continue
		}
		res.Containers++
	}
	for _, id := range imageIDs {
		im, ok := byID[id]
		if !idRe.MatchString(id) || !ok {
			res.Skipped++
			continue
		}
		// an image with several tags cannot be removed by id without -f; untag them all instead
		targets := []string{id}
		if len(im.Tags) > 0 {
			targets = im.Tags
		}
		// leftover stopped swarm tasks pin the image; removing them is what `docker container prune` does
		for _, c := range im.Blockers {
			if idRe.MatchString(c) {
				if _, err := r.Run(ctx, "docker container rm "+c); err == nil {
					res.Containers++
				}
			}
		}
		cmd := "docker image rm"
		for _, t := range targets {
			cmd += " " + sshx.Quote(t)
		}
		if _, err := r.Run(ctx, cmd); err != nil {
			res.Errors = append(res.Errors, err.Error())
			continue
		}
		res.Images++
		res.Freed += im.Size
	}
	return res
}

// Summary is a one-line description such as "3 images (up to 1.2 GB), 1 stopped container".
func (u *Unused) Summary() string {
	var p []string
	if n := len(u.Images); n > 0 {
		p = append(p, fmt.Sprintf("%d unused image%s (up to %s)", n, plural(n), humanBytes(u.ImageBytes)))
	}
	if n := len(u.Containers); n > 0 {
		p = append(p, fmt.Sprintf("%d stopped container%s", n, plural(n)))
	}
	return strings.Join(p, ", ")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func humanBytes(b uint64) string {
	const k = 1024.0
	v := float64(b)
	for _, u := range []string{"B", "KiB", "MiB", "GiB", "TiB"} {
		if v < k || u == "TiB" {
			if u == "B" {
				return fmt.Sprintf("%d B", b)
			}
			return fmt.Sprintf("%.1f %s", v, u)
		}
		v /= k
	}
	return ""
}
