package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/cron"
	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/sshx"
	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/update"
	"github.com/ardean/swarmwatch/pkg/api"
)

const (
	historyKeep = 100                 // update results remembered
	failureAge  = 14 * 24 * time.Hour // how long a failed update is flagged while the service is still outdated
)

// updateLog is the audit trail of updates: what was rolled to a newer image, when, and how it went. It
// is a small JSON file next to the scan results and survives restarts, like first-seen.json.
type updateLog struct {
	mu            sync.Mutex
	path          string
	LastScheduled time.Time       `json:"last_scheduled"`
	History       []update.Result `json:"history"` // oldest first
	warned        bool
}

func loadUpdateLog(dir string) *updateLog {
	l := &updateLog{path: filepath.Join(dir, "updates.json")}
	if b, err := os.ReadFile(l.path); err == nil {
		if err := json.Unmarshal(b, l); err != nil {
			log.Printf("updates: ignoring unreadable %s: %v", l.path, err)
			l.LastScheduled, l.History = time.Time{}, nil
		}
	}
	return l
}

func (l *updateLog) add(r update.Result) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.History = append(l.History, r)
	if len(l.History) > historyKeep {
		l.History = append([]update.Result(nil), l.History[len(l.History)-historyKeep:]...)
	}
	l.save()
}

func (l *updateLog) markScheduled(t time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.LastScheduled = t
	l.save()
}

func (l *updateLog) scheduled() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.LastScheduled
}

// recent returns the newest n results, newest first.
func (l *updateLog) recent(n int) []update.Result {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []update.Result
	for i := len(l.History) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, l.History[i])
	}
	return out
}

// failedBefore reports whether the latest image update of a service went to this very digest and failed.
// A scheduled run does not try that image again: it would roll a broken image out and back at every
// tick. A newer digest, or the button, tries again.
func (l *updateLog) failedBefore(swarmName, service, digest string) bool {
	if digest == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.History) - 1; i >= 0; i-- {
		r := l.History[i]
		if r.Restart || r.Swarm != swarmName || r.Service != service {
			continue
		}
		return !r.OK && r.Digest == digest
	}
	return false
}

// failed returns the services whose latest image update failed, by "swarm/service".
func (l *updateLog) failed(now time.Time) map[string]update.Result {
	l.mu.Lock()
	defer l.mu.Unlock()
	last := map[string]update.Result{}
	for _, r := range l.History {
		if !r.Restart {
			last[r.Swarm+"/"+r.Service] = r
		}
	}
	for k, r := range last {
		if r.OK || now.Sub(r.Time) > failureAge {
			delete(last, k)
		}
	}
	return last
}

// save writes the file atomically; a failure is logged once and the log then lives in memory only.
func (l *updateLog) save() {
	b, err := json.Marshal(l)
	if err == nil {
		if err = os.MkdirAll(filepath.Dir(l.path), 0o700); err == nil {
			tmp := l.path + ".tmp"
			if err = os.WriteFile(tmp, b, 0o600); err == nil {
				err = os.Rename(tmp, l.path)
			}
		}
	}
	if err != nil && !l.warned {
		l.warned = true
		log.Printf("updates: cannot persist to %s: %v (kept in memory only)", l.path, err)
	}
}

// updateStatus is what the page shows about a run in progress.
type updateStatus struct {
	Running bool
	Text    string
}

// updateEnabled reports whether any way of updating is switched on.
func (s *Server) updateEnabled() bool { return s.cfg.Update.Allow || s.cfg.Update.Schedule != "" }

// selfService is the swarm service swarmwatch runs as, so it never updates itself mid-run. It is looked
// up once, on the first local swarm; empty when not running inside a service.
func (s *Server) selfService() string {
	s.selfOnce.Do(func() {
		for _, h := range s.cfg.Swarms {
			if r := (sshx.Runner{Dest: h.SSH}); r.Local() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				s.self = update.Self(ctx, r)
				cancel()
				return
			}
		}
	})
	return s.self
}

func (s *Server) swarmConfig(name string) *config.Swarm {
	for i := range s.cfg.Swarms {
		if s.cfg.Swarms[i].Name == name {
			return &s.cfg.Swarms[i]
		}
	}
	return nil
}

// snapshot returns the current snapshot of a swarm, nil if unknown or unreadable.
func (s *Server) snapshot(name string) *swarm.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sn := range s.snaps {
		if sn.Name == name && sn.Err == "" {
			return sn
		}
	}
	return nil
}

// updateLoop fires the configured schedule. It looks at the clock every 20 s and runs once per
// matching minute; the last run is remembered so a restart within that minute does not repeat it. A
// run missed because swarmwatch was down is not caught up.
func (s *Server) updateLoop(ctx context.Context, sched *cron.Schedule) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			minute := time.Now().Truncate(time.Minute)
			if !sched.Match(minute) || !s.updates.scheduled().Before(minute) {
				continue
			}
			s.updates.markScheduled(minute)
			s.runScheduled(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) runScheduled(ctx context.Context) {
	if !s.updateMu.TryLock() {
		log.Printf("update: scheduled run skipped, another update is still running")
		return
	}
	defer s.updateMu.Unlock()
	log.Printf("update: scheduled run (%s)", s.cfg.Update.Schedule)
	s.refresh(ctx) // current registry state, not up to an hour old
	for _, h := range s.cfg.Swarms {
		sn := s.snapshot(h.Name)
		if sn == nil {
			log.Printf("update: %s unreachable, skipped", h.Name)
			continue
		}
		var targets []update.Target
		for _, t := range update.Plan(sn, s.selfService()) {
			if s.updates.failedBefore(t.Swarm, t.Service, t.Digest) {
				log.Printf("update: %s/%s skipped, the image %s failed before and has not changed", t.Swarm, t.Service, t.Digest)
				continue
			}
			targets = append(targets, t)
		}
		s.execUpdate(ctx, h, targets, false)
	}
}

// execUpdate rolls the targets of one swarm and records the results. The caller holds updateMu.
func (s *Server) execUpdate(ctx context.Context, h config.Swarm, targets []update.Target, manual bool) {
	if len(targets) == 0 {
		log.Printf("update: %s has nothing to update", h.Name)
		return
	}
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.Service
	}
	log.Printf("update: %s: %s", h.Name, strings.Join(names, ", "))
	s.mu.Lock()
	s.upd = updateStatus{Running: true, Text: fmt.Sprintf("updating %s: %s", h.Name, strings.Join(names, ", "))}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.upd = updateStatus{}
		s.mu.Unlock()
	}()

	ok, bad := 0, 0
	update.Run(ctx, sshx.Runner{Dest: h.SSH}, targets, update.Options{Pause: s.cfg.Update.Wait, Manual: manual}, func(r update.Result) {
		log.Printf("update: %s", r)
		s.updates.add(r)
		if r.OK {
			ok++
		} else {
			bad++
		}
	})
	s.refresh(ctx)
	if s.cfg.Update.Cleanup {
		s.cleanAfterUpdate(ctx, h)
	}
	log.Printf("update: %s done, %d step(s) ok, %d failed", h.Name, ok, bad)
}

// cleanAfterUpdate removes the images the update left behind, the same as the clean-up button would:
// only what is still unused at this moment.
func (s *Server) cleanAfterUpdate(ctx context.Context, h config.Swarm) {
	sn := s.snapshot(h.Name)
	if sn == nil || sn.Unused.Empty() {
		return
	}
	ids := make([]string, 0, len(sn.Unused.Images))
	for _, im := range sn.Unused.Images {
		ids = append(ids, im.ID)
	}
	if len(ids) == 0 {
		return
	}
	s.cleanMu.Lock()
	defer s.cleanMu.Unlock()
	res := swarm.Clean(ctx, h, ids, nil)
	log.Printf("update: cleanup %s removed images=%d skipped=%d errors=%d freed<=%d bytes", h.Name, res.Images, res.Skipped, len(res.Errors), res.Freed)
	s.refresh(ctx)
}

// handleUpdate starts the update of one service from its button. It is off unless update allow is set,
// only accepts same-origin POSTs, and only updates what is outdated in the current snapshot.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Update.Allow {
		http.Error(w, "updating from the page is disabled (deploy with --allow-update / SWARMWATCH_ALLOW_UPDATE=1)", http.StatusForbidden)
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
	h := s.swarmConfig(r.PostForm.Get("swarm"))
	if h == nil {
		http.Error(w, "unknown swarm", http.StatusBadRequest)
		return
	}
	sn := s.snapshot(h.Name)
	if sn == nil {
		http.Error(w, "swarm is unreachable", http.StatusConflict)
		return
	}
	var targets []update.Target
	for _, t := range update.Plan(sn, s.selfService()) {
		if t.Service == r.PostForm.Get("service") {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		http.Error(w, "that service has no newer image, or is excluded from updates", http.StatusBadRequest)
		return
	}
	if !s.updateMu.TryLock() {
		http.Error(w, "another update is still running", http.StatusConflict)
		return
	}
	log.Printf("update: %s/%s requested from %s", h.Name, targets[0].Service, r.RemoteAddr)
	// The roll can take minutes, longer than a request may: run it in the background, the page shows it.
	go func() {
		defer s.updateMu.Unlock()
		s.execUpdate(context.Background(), *h, targets, true)
	}()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// updateFindings flags services whose last image update failed and that are still outdated.
func (s *Server) updateFindings(snaps []*swarm.Snapshot) []swarm.Finding {
	failed := s.updates.failed(time.Now())
	if len(failed) == 0 {
		return nil
	}
	var out []swarm.Finding
	for _, sn := range snaps {
		for _, v := range sn.Services {
			res, ok := failed[sn.Name+"/"+v.Name]
			if !ok || v.Update == nil || v.Update.State != registry.StateOutdated {
				continue
			}
			f := swarm.Finding{Level: swarm.Warn, Kind: api.KindUpdateFailed, Swarm: sn.Name, Stack: v.Stack, Service: v.Name,
				Image: v.Image, Message: "last update failed: " + res.Message}
			if v.Exposure != nil {
				f.Exposure = v.Exposure.Level
			}
			out = append(out, f)
		}
	}
	return out
}

// updateView is the update part of the page.
type updateView struct {
	Enabled  bool
	CanClick bool
	Schedule string
	Status   updateStatus
	Recent   []resultView
}

type resultView struct {
	When, What, Message string
	OK                  bool
}

func (s *Server) updateView() updateView {
	v := updateView{Enabled: s.updateEnabled(), CanClick: s.cfg.Update.Allow, Schedule: s.cfg.Update.Schedule, Status: s.upd}
	for _, r := range s.updates.recent(10) {
		what := r.Swarm + "/" + r.Service
		if r.Restart {
			what += " (restart)"
		} else {
			what += " → " + r.Image
		}
		msg := r.Message
		if r.OK {
			msg = fmt.Sprintf("ok, %ds", r.Seconds)
		}
		if r.Manual {
			msg += " · by button"
		}
		v.Recent = append(v.Recent, resultView{When: ago(r.Time), What: what, Message: msg, OK: r.OK})
	}
	return v
}

func ago(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	if d < time.Minute {
		return d.String() + " ago"
	}
	return d.Round(time.Minute).String() + " ago"
}

// canUpdate reports whether the page offers the update button for a service.
func (s *Server) canUpdate(sn *swarm.Snapshot, service string) bool {
	for _, v := range sn.Services {
		if v.Name == service {
			return update.Skipped(v, s.selfService()) == ""
		}
	}
	return false
}
