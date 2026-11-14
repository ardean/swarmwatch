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
	LastScheduled time.Time            `json:"last_scheduled"`
	LastNight     time.Time            `json:"last_night,omitempty"`
	LastLanes     map[string]time.Time `json:"last_lanes,omitempty"`
	History       []update.Result      `json:"history"` // oldest first
	// Paused stops the automatic check and roll. A roll already running finishes, and the button can still roll once.
	Paused bool `json:"paused"`
	warned bool
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

func (l *updateLog) markLane(name string, t time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if name == "" {
		l.LastScheduled = t
	} else {
		if l.LastLanes == nil {
			l.LastLanes = map[string]time.Time{}
		}
		l.LastLanes[strings.ToLower(name)] = t
		if strings.EqualFold(name, "night") {
			l.LastNight = t
		}
	}
	l.save()
}

func (l *updateLog) laneAt(name string) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	if name == "" {
		return l.LastScheduled
	}
	if t, ok := l.LastLanes[strings.ToLower(name)]; ok {
		return t
	}
	if strings.EqualFold(name, "night") {
		return l.LastNight
	}
	return time.Time{}
}

// setPaused remembers whether the automatic check and roll should fire. It survives a restart.
func (l *updateLog) setPaused(v bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Paused = v
	l.save()
}

func (l *updateLog) paused() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Paused
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
func (s *Server) updateEnabled() bool {
	return s.cfg.Update.Allow || s.cfg.Update.Schedule != "" || len(s.cfg.Update.Lanes) > 0
}

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
func (s *Server) updateLoop(ctx context.Context, sched *cron.Schedule, lane string) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if s.updates.paused() {
				continue
			}
			minute := time.Now().Truncate(time.Minute)
			if !sched.Match(minute) || !s.updates.laneAt(lane).Before(minute) {
				continue
			}
			s.updates.markLane(lane, minute)
			s.runScheduled(ctx, lane)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) runScheduled(ctx context.Context, lane string) {
	if s.updates.paused() {
		log.Printf("update: scheduled run skipped, the check and roll interval is paused")
		return
	}
	if !s.updateMu.TryLock() {
		log.Printf("update: scheduled run skipped, another update is still running")
		return
	}
	defer s.updateMu.Unlock()
	spec := s.cfg.Update.Schedule
	which := "fast"
	if lane != "" {
		ln, ok := s.cfg.Update.FindLane(lane)
		if !ok {
			return
		}
		spec = ln.Cron
		which = ln.Name
	}
	log.Printf("update: scheduled run %s (%s)", which, spec)
	// The registry results are remembered for registry_ttl (an hour by default). Without this
	// reset a pushed image would only be seen after that.
	if s.checker != nil {
		s.checker.Reset()
	}
	s.refresh(ctx)
	s.rollOutdated(ctx, false, lane)
}

// rollAfterCheck is the deploy half of an API image check. It uses the snapshot the check just
// collected. Updates that are switched off stay check-only. A roll already in progress is left to finish.
func (s *Server) rollAfterCheck(ctx context.Context) {
	if !s.updateEnabled() {
		return
	}
	if !s.updateMu.TryLock() {
		log.Printf("update: image check finished, roll skipped, another update is still running")
		return
	}
	defer s.updateMu.Unlock()
	log.Printf("update: roll after image check")
	s.rollOutdated(ctx, true, "")
}

// rollOutdated rolls every service one schedule would roll. lane "" is the fast schedule.
// The caller holds updateMu.
// A digest that already failed stays put until a newer image is published, so a click does not
// roll a broken image out and back. manual marks the audit line as started from the button.
func (s *Server) rollOutdated(ctx context.Context, manual bool, lane string) {
	for _, h := range s.cfg.Swarms {
		sn := s.snapshot(h.Name)
		if sn == nil {
			log.Printf("update: %s unreachable, skipped", h.Name)
			continue
		}
		planned := update.PlanLane(sn, s.selfService(), lane)
		var targets []update.Target
		for _, t := range planned {
			if s.updates.failedBefore(t.Swarm, t.Service, t.Digest) {
				log.Printf("update: %s/%s skipped, the image %s failed before and has not changed", t.Swarm, t.Service, t.Digest)
				continue
			}
			targets = append(targets, t)
		}
		if s.rollFn != nil {
			s.rollFn(targets, manual)
			continue
		}
		s.execUpdate(ctx, h, targets, manual)
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

// handleUpdateAll starts the update of every service the row buttons would roll. It is off unless
// update allow is set, only accepts same-origin POSTs, and uses the current snapshot: a night service
// and a service labeled swarmwatch.update=false stay put. Unlike the schedule, an image that already
// failed is tried again, the same as pressing its row button. Services roll one at a time.
func (s *Server) handleUpdateAll(w http.ResponseWriter, r *http.Request) {
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
	type job struct {
		h       config.Swarm
		targets []update.Target
	}
	var jobs []job
	for _, h := range s.cfg.Swarms {
		sn := s.snapshot(h.Name)
		if sn == nil {
			continue
		}
		if targets := update.Plan(sn, s.selfService()); len(targets) > 0 {
			jobs = append(jobs, job{h: h, targets: targets})
		}
	}
	if len(jobs) == 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.updateMu.TryLock() {
		http.Error(w, "another update is still running", http.StatusConflict)
		return
	}
	log.Printf("update: all outdated services requested from %s", r.RemoteAddr)
	go func() {
		defer s.updateMu.Unlock()
		ctx := context.Background()
		for _, job := range jobs {
			if s.rollFn != nil {
				s.rollFn(job.targets, true)
				continue
			}
			s.execUpdate(ctx, job.h, job.targets, true)
		}
	}()
	http.Redirect(w, r, "/", http.StatusSeeOther)
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

// handleAPIUpdate is the row button for a caller that has the token. The pages stay off.
// It rolls one service the button would roll, and tries an image again after a failed roll.
func (s *Server) handleAPIUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	q := r.URL.Query()
	jobs, code, msg := s.manualJobs(q.Get("swarm"), q.Get("service"))
	if code != 0 {
		writeError(w, code, msg)
		return
	}
	s.acceptManualRoll(w, jobs)
}

// handleAPIUpdateAll is the update-all button for a caller that has the token.
// A night service and swarmwatch.update=false stay put. An image that already failed is tried again.
func (s *Server) handleAPIUpdateAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	jobs, code, msg := s.manualJobs("", "")
	if code != 0 {
		writeError(w, code, msg)
		return
	}
	s.acceptManualRoll(w, jobs)
}

type manualJob struct {
	h       config.Swarm
	targets []update.Target
}

// manualJobs lists what the row button would roll. onlySwarm and onlyService narrow it to one service.
// A non-zero code is an error response and jobs is empty.
func (s *Server) manualJobs(onlySwarm, onlyService string) ([]manualJob, int, string) {
	if onlyService != "" && onlySwarm == "" {
		return nil, http.StatusBadRequest, "swarm and service are required"
	}
	if onlySwarm != "" && s.swarmConfig(onlySwarm) == nil {
		return nil, http.StatusBadRequest, "unknown swarm"
	}
	var jobs []manualJob
	for _, h := range s.cfg.Swarms {
		if onlySwarm != "" && h.Name != onlySwarm {
			continue
		}
		sn := s.snapshot(h.Name)
		if sn == nil {
			if onlySwarm != "" {
				return nil, http.StatusConflict, "swarm is unreachable"
			}
			continue
		}
		var targets []update.Target
		for _, t := range update.Plan(sn, s.selfService()) {
			if onlyService != "" && t.Service != onlyService {
				continue
			}
			targets = append(targets, t)
		}
		if len(targets) > 0 {
			jobs = append(jobs, manualJob{h: h, targets: targets})
		}
	}
	if onlyService != "" && len(jobs) == 0 {
		return nil, http.StatusBadRequest, "that service has no newer image, or is excluded from updates"
	}
	return jobs, 0, ""
}

// acceptManualRoll starts the roll and answers 202. An empty list is still accepted: there was nothing to roll.
func (s *Server) acceptManualRoll(w http.ResponseWriter, jobs []manualJob) {
	if len(jobs) > 0 {
		if !s.updateMu.TryLock() {
			writeError(w, http.StatusConflict, "an update is already running")
			return
		}
		log.Printf("update: manual roll of %d swarm(s) requested", len(jobs))
		go func() {
			defer s.updateMu.Unlock()
			for _, job := range jobs {
				if s.rollFn != nil {
					s.rollFn(job.targets, true)
					continue
				}
				s.execUpdate(context.Background(), job.h, job.targets, true)
			}
		}()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(api.ImageCheckAccepted{Accepted: true})
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
	Enabled      bool
	CanClick     bool
	Pending      int // outdated services the update-all button would roll
	Schedule     string
	ScheduleText string // "every 5 minutes" when the cron can be said that way
	Night        string
	NightText    string
	Lanes        []laneView
	Paused       bool // the automatic check and roll does not fire
	Status       updateStatus
	Recent       []resultView
}

// laneView is one named schedule. Text and Next are for the note under the update line, not the row.
type laneView struct {
	Name, Text, Cron, Next string
}

type resultView struct {
	When, What, Message string
	OK                  bool
}

func (s *Server) updateView() updateView {
	v := updateView{Enabled: s.updateEnabled(), CanClick: s.cfg.Update.Allow, Schedule: s.cfg.Update.Schedule, Status: s.upd, Paused: s.updates.paused()}
	if text := cron.Describe(s.cfg.Update.Schedule); text != "" && text != s.cfg.Update.Schedule {
		v.ScheduleText = text
	}
	v.Night = s.cfg.Update.Night
	if text := cron.Describe(s.cfg.Update.Night); text != "" && text != s.cfg.Update.Night {
		v.NightText = text
	}
	now := time.Now()
	for _, ln := range s.cfg.Update.Lanes {
		text := cron.Describe(ln.Cron)
		if text == ln.Cron {
			text = ""
		}
		next := ""
		if parsed, err := cron.Parse(ln.Cron); err == nil {
			if t, ok := parsed.Next(now); ok {
				next = t.Format("15:04")
			}
		}
		v.Lanes = append(v.Lanes, laneView{Name: ln.Name, Text: text, Cron: ln.Cron, Next: next})
	}
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
			return update.Skipped(v, s.selfService()) == "" && update.Lane(v) == ""
		}
	}
	return false
}
