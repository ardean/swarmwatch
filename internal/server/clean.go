package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/cron"
	"github.com/ardean/swarmwatch/internal/report"
	"github.com/ardean/swarmwatch/internal/swarm"
)

// cleanNote is the result of the last clean-up, shown as a banner.
type cleanNote struct {
	Time time.Time
	Text string
	Bad  bool
}

// handleClean removes unused images and stopped containers. It is off unless serve.allow_clean is set,
// only accepts same-origin POSTs, and only removes items that are still unused at that moment.
func (s *Server) handleClean(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Serve.AllowClean {
		http.Error(w, "cleaning is disabled (deploy with --allow-clean / SWARMWATCH_ALLOW_CLEAN=1)", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	var host *config.Swarm
	for i := range s.cfg.Swarms {
		if s.cfg.Swarms[i].Name == r.PostForm.Get("swarm") {
			host = &s.cfg.Swarms[i]
		}
	}
	if host == nil {
		http.Error(w, "unknown swarm", http.StatusBadRequest)
		return
	}
	images, containers := r.PostForm["image"], r.PostForm["container"]
	if len(images)+len(containers) == 0 {
		http.Error(w, "nothing selected", http.StatusBadRequest)
		return
	}

	s.cleanMu.Lock()
	defer s.cleanMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	log.Printf("clean: swarm=%s from=%s requested images=%d containers=%d", host.Name, r.RemoteAddr, len(images), len(containers))
	res := swarm.Clean(ctx, *host, images, containers)
	log.Printf("clean: swarm=%s removed images=%d containers=%d skipped=%d errors=%d freed<=%d bytes",
		host.Name, res.Images, res.Containers, res.Skipped, len(res.Errors), res.Freed)
	note := cleanNote{Time: time.Now(), Text: fmt.Sprintf("%s: removed %d image(s) (up to %s freed) and %d container(s)",
		host.Name, res.Images, report.Size(res.Freed), res.Containers), Bad: len(res.Errors) > 0}
	if res.Skipped > 0 {
		note.Text += fmt.Sprintf(", skipped %d that are in use now", res.Skipped)
	}
	if len(res.Errors) > 0 {
		note.Text += "; errors: " + strings.Join(res.Errors, "; ")
	}
	s.mu.Lock()
	s.cleaned = note
	s.mu.Unlock()
	s.refresh(ctx)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// sameOrigin rejects browser requests started by another site. Non-browser clients send neither header.
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	}
	return true
}

// pickClean chooses what the schedule removes: images that no container or service uses and that were built
// before the keep window, and stopped containers older than theirs. An item whose age is unknown is kept.
func pickClean(u *swarm.Unused, now time.Time, keepImages, keepContainers time.Duration) (images, containers []string) {
	if u == nil {
		return nil, nil
	}
	for _, im := range u.Images {
		if !im.Created.IsZero() && now.Sub(im.Created) >= keepImages {
			images = append(images, im.ID)
		}
	}
	for _, c := range u.Containers {
		if !c.Created.IsZero() && now.Sub(c.Created) >= keepContainers {
			containers = append(containers, c.ID)
		}
	}
	return images, containers
}

// cleanLoop fires the clean schedule: it looks at the clock every 20 s and runs once per matching minute.
// A run missed because swarmwatch was down is not caught up; the next one removes the same things.
func (s *Server) cleanLoop(ctx context.Context, sched *cron.Schedule) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	var last time.Time
	for {
		select {
		case <-t.C:
			minute := time.Now().Truncate(time.Minute)
			if !sched.Match(minute) || !last.Before(minute) {
				continue
			}
			last = minute
			s.runScheduledClean(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) runScheduledClean(ctx context.Context) {
	// Not while services are being rolled: the old image of a service that is being updated must stay.
	if !s.updateMu.TryLock() {
		log.Printf("clean: scheduled run skipped, an update is running")
		return
	}
	defer s.updateMu.Unlock()
	s.refresh(ctx) // what is unused now, not two minutes ago
	for _, h := range s.cfg.Swarms {
		sn := s.snapshot(h.Name)
		if sn == nil {
			log.Printf("clean: %s unreachable, skipped", h.Name)
			continue
		}
		images, containers := pickClean(sn.Unused, time.Now(), s.cfg.Clean.Keep, s.cfg.Clean.KeepContainers)
		if len(images)+len(containers) == 0 {
			log.Printf("clean: %s has nothing older than %s (images) and %s (containers) to remove", h.Name, s.cfg.Clean.Keep, s.cfg.Clean.KeepContainers)
			continue
		}
		s.cleanMu.Lock()
		cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		res := swarm.Clean(cctx, h, images, containers)
		cancel()
		s.cleanMu.Unlock()
		log.Printf("clean: %s removed images=%d containers=%d skipped=%d errors=%d freed<=%d bytes",
			h.Name, res.Images, res.Containers, res.Skipped, len(res.Errors), res.Freed)
		note := cleanNote{Time: time.Now(), Bad: len(res.Errors) > 0,
			Text: fmt.Sprintf("%s: removed %d image(s) (up to %s freed) and %d container(s) on schedule", h.Name, res.Images, report.Size(res.Freed), res.Containers)}
		if len(res.Errors) > 0 {
			note.Text += "; errors: " + strings.Join(res.Errors, "; ")
		}
		s.mu.Lock()
		s.cleaned = note
		s.mu.Unlock()
	}
	s.refresh(ctx)
}
