package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
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
	res := swarm.Clean(ctx, *host, images, containers)
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
