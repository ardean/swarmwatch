package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/update"
	"github.com/ardean/swarmwatch/pkg/api"
)

func imageServer() *Server {
	cfg := &config.Config{Swarms: []config.Swarm{{Name: "outdrive", SSH: "local"}}}
	cfg.Update.Schedule = "*/5 * * * *"
	s := New(cfg, nil)
	s.selfOnce.Do(func() {})
	s.snaps = []*swarm.Snapshot{{Name: "outdrive", Services: []*swarm.Service{
		{Name: "outdrive_api", Stack: "outdrive", Image: "ghcr.io/acme/api:prod", Running: 4, Desired: 4,
			Update:   &registry.Result{State: registry.StateCurrent},
			Exposure: &swarm.Exposure{Level: "internet"}},
		{Name: "outdrive_mongo", Stack: "outdrive", Image: "mongo:8", Running: 1, Desired: 1,
			Labels: map[string]string{"swarmwatch.update": "false"},
			Update: &registry.Result{State: registry.StateOutdated}},
	}}}
	s.updated = time.Now()
	return s
}

func TestImagesReport(t *testing.T) {
	s := imageServer()
	w := httptest.NewRecorder()
	s.handleImages(w, httptest.NewRequest(http.MethodGet, "/api/v1/images", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body api.Images
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Check.Running || !body.Check.Rolls || len(body.Services) != 2 {
		t.Fatalf("body = %+v", body)
	}
	if body.Services[0].Service != "outdrive_api" || body.Services[0].State != "current" || body.Services[0].Schedule != "auto" {
		t.Errorf("api row = %+v", body.Services[0])
	}
	if body.Services[1].Schedule != "no, excluded by label" || body.Services[1].State != "outdated" {
		t.Errorf("mongo row = %+v", body.Services[1])
	}
	if body.Schedules.Images.Text != "every 5 minutes" || body.Schedules.Images.Cron != "*/5 * * * *" {
		t.Errorf("image interval = %+v", body.Schedules.Images)
	}
	if body.Schedules.Images.Next.IsZero() || body.Schedules.Images.Next.Minute()%5 != 0 {
		t.Errorf("next image check = %v", body.Schedules.Images.Next)
	}
	if body.Schedules.Scan != "any time" || body.Schedules.Clean.Cron != "" {
		t.Errorf("other intervals = %+v", body.Schedules)
	}
}

func TestImagesReportIncludesTheScanWindowAndCleanup(t *testing.T) {
	s := imageServer()
	s.cfg.Scan.Window = "02:00-05:00"
	s.cfg.Clean.Schedule = "30 3 * * *"
	body := s.imageReport()
	if body.Schedules.Scan != "02:00-05:00" || body.Schedules.Clean.Text != "every day at 03:30" {
		t.Fatalf("intervals = %+v", body.Schedules)
	}
	if body.Schedules.Clean.Next.IsZero() || body.Schedules.Clean.Next.Hour() != 3 || body.Schedules.Clean.Next.Minute() != 30 {
		t.Fatalf("next cleanup = %v", body.Schedules.Clean.Next)
	}
}

func TestNightScheduleIsSeparateFromTheFastOne(t *testing.T) {
	s := imageServer()
	s.cfg.Update.Night = "15 1 * * *"
	s.cfg.Update.Lanes = []config.Lane{{Name: "night", Cron: "15 1 * * *"}}
	s.snaps[0].Services[1].Labels["swarmwatch.update"] = "night"
	body := s.imageReport()
	if body.Services[1].Schedule != "night" {
		t.Fatalf("mongo schedule = %q", body.Services[1].Schedule)
	}
	if len(body.Schedules.Lanes) != 1 || body.Schedules.Lanes[0].Name != "night" || body.Schedules.Lanes[0].Text != "every day at 01:15" {
		t.Fatalf("lanes = %+v", body.Schedules.Lanes)
	}
	view := s.updateView()
	if len(view.Lanes) != 1 || view.Lanes[0].Name != "night" || view.Lanes[0].Text != "every day at 01:15" || view.Lanes[0].Next == "" {
		t.Fatalf("page note = %+v", view.Lanes)
	}
	if body.Services[0].Schedule != "auto" {
		t.Fatalf("api schedule = %q", body.Services[0].Schedule)
	}
	if body.Schedules.Night.Text != "every day at 01:15" || body.Schedules.Night.Cron != "15 1 * * *" {
		t.Fatalf("night interval = %+v", body.Schedules.Night)
	}
	fast := update.Plan(s.snaps[0], "")
	night := update.PlanNight(s.snaps[0], "")
	if len(fast) != 0 || len(night) != 1 || night[0].Service != "outdrive_mongo" {
		t.Fatalf("fast %d night %+v", len(fast), night)
	}
}

func TestImageCheckRunsOnce(t *testing.T) {
	s := imageServer()
	started := make(chan struct{})
	release := make(chan struct{})
	s.imageCheckFn = func() {
		close(started)
		<-release
	}

	w := httptest.NewRecorder()
	s.handleImageCheck(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/check", nil))
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"accepted":true`) {
		t.Fatalf("first = %d %s", w.Code, w.Body.String())
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("check did not start")
	}
	w = httptest.NewRecorder()
	s.handleImageCheck(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/check", nil))
	if w.Code != http.StatusConflict {
		t.Errorf("second = %d, want 409", w.Code)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for s.imageReport().Check.Running && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.imageReport().Check.Running {
		t.Fatal("check did not finish")
	}
	if s.checker.Asked().IsZero() {
		t.Error("a finished check must record when the registries were asked")
	}
}

func TestAPIImageCheckRollsEligibleServicesAndSkipsAFailedDigest(t *testing.T) {
	s := imageServer()
	s.updates = loadUpdateLog(t.TempDir())
	s.updates.add(update.Result{Time: time.Now(), Swarm: "outdrive", Service: "outdrive_api", Digest: "sha256:bad", Message: "boom"})
	s.snaps[0].Services = []*swarm.Service{
		{Name: "outdrive_api", Stack: "outdrive", Image: "ghcr.io/acme/api:prod", Running: 4, Desired: 4,
			Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:bad"}},
		{Name: "outdrive_worker", Stack: "outdrive", Image: "ghcr.io/acme/worker:prod", Running: 1, Desired: 1,
			Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:new"}},
		{Name: "outdrive_mongo", Stack: "outdrive", Image: "mongo:8",
			Labels: map[string]string{"swarmwatch.update": "false"},
			Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:new"}},
	}
	checked := make(chan struct{})
	s.imageCheckFn = func() { close(checked) }
	rolled := make(chan update.Target, 1)
	s.rollFn = func(targets []update.Target, manual bool) {
		if !manual {
			t.Errorf("manual = false")
		}
		for _, target := range targets {
			rolled <- target
		}
		close(rolled)
	}

	w := httptest.NewRecorder()
	s.handleImageCheck(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/check", nil))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d", w.Code)
	}
	select {
	case <-checked:
	case <-time.After(2 * time.Second):
		t.Fatal("check did not start")
	}
	select {
	case target := <-rolled:
		if target.Service != "outdrive_worker" || target.Digest != "sha256:new" {
			t.Fatalf("rolled %+v", target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("roll did not start")
	}
	select {
	case extra, ok := <-rolled:
		if ok {
			t.Fatalf("also rolled %+v", extra)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("roll did not finish")
	}
}

func TestPageImageCheckDoesNotRoll(t *testing.T) {
	s := imageServer()
	s.rollFn = func(targets []update.Target, manual bool) {
		t.Errorf("page check rolled %+v manual=%v", targets, manual)
	}
	s.imageCheckFn = func() {}
	r := httptest.NewRequest(http.MethodPost, "/image-check", nil)
	w := httptest.NewRecorder()
	s.handleImageCheckPage(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", w.Code)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.imageReport().Check.Running && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.imageReport().Check.Running {
		t.Fatal("page check did not finish")
	}
}

func TestAPIImageCheckStaysACheckWhenUpdatesAreOff(t *testing.T) {
	s := imageServer()
	s.cfg.Update.Schedule = ""
	if s.imageReport().Check.Rolls {
		t.Fatal("rolls should be false when updates are off")
	}
	s.rollFn = func(targets []update.Target, manual bool) {
		t.Errorf("rolled %+v", targets)
	}
	started := make(chan struct{})
	s.imageCheckFn = func() { close(started) }
	w := httptest.NewRecorder()
	s.handleImageCheck(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/check", nil))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d", w.Code)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("check did not start")
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.imageReport().Check.Running && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.imageReport().Check.Running {
		t.Fatal("check did not finish")
	}
}

func TestAPIImageCheckRefusesWhileAnUpdateIsRunning(t *testing.T) {
	s := imageServer()
	s.mu.Lock()
	s.upd.Running = true
	s.mu.Unlock()
	s.imageCheckFn = func() { t.Error("check started during a roll") }
	s.rollFn = func(targets []update.Target, manual bool) { t.Error("roll started during a roll") }
	w := httptest.NewRecorder()
	s.handleImageCheck(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/check", nil))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "an update is already running") {
		t.Fatalf("status = %d %s", w.Code, w.Body.String())
	}
	if s.imageReport().Check.Running {
		t.Fatal("a refused check must not look running")
	}
}

func TestPauseSkipsTheScheduleAndTheButtonStillRolls(t *testing.T) {
	s := imageServer()
	dir := t.TempDir()
	s.updates = loadUpdateLog(dir)
	s.rollFn = func(targets []update.Target, manual bool) {
		t.Errorf("scheduled roll while paused: %+v manual=%v", targets, manual)
	}
	s.updates.setPaused(true)
	s.runScheduled(context.Background(), "")

	if report := s.imageReport(); report.Updates.Paused == nil || !*report.Updates.Paused || !report.Check.Rolls {
		t.Fatalf("paused report = %+v", report.Updates.Paused)
	}
	if !loadUpdateLog(dir).paused() {
		t.Fatal("pause must survive a restart")
	}

	rolled := make(chan struct{})
	s.imageCheckFn = func() {}
	s.rollFn = func(targets []update.Target, manual bool) {
		if !manual {
			t.Errorf("manual = false")
		}
		close(rolled)
	}
	w := httptest.NewRecorder()
	s.handleImageCheck(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/check", nil))
	if w.Code != http.StatusAccepted {
		t.Fatalf("check status = %d", w.Code)
	}
	select {
	case <-rolled:
	case <-time.After(2 * time.Second):
		t.Fatal("the button should still roll while the interval is paused")
	}

	w = httptest.NewRecorder()
	s.handleImageResume(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/resume", nil))
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"paused":false`) {
		t.Fatalf("resume = %d %s", w.Code, w.Body.String())
	}
	if s.imageReport().Updates.Paused == nil || *s.imageReport().Updates.Paused {
		t.Fatal("resume did not clear the pause")
	}
}

func TestPauseAndResumeEndpoints(t *testing.T) {
	s := imageServer()
	s.updates = loadUpdateLog(t.TempDir())
	w := httptest.NewRecorder()
	s.handleImagePause(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/pause", nil))
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"paused":true`) {
		t.Fatalf("pause = %d %s", w.Code, w.Body.String())
	}
	body := s.imageReport()
	raw, err := json.Marshal(body.Updates)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"paused":true`) {
		t.Fatalf("updates json = %s", raw)
	}
	page := httptest.NewRecorder()
	s.handleIndex(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(page.Body.String(), "interval paused") {
		t.Fatal("the page should say the interval is paused")
	}
}

func TestImageCheckPageRejectsAForeignOrigin(t *testing.T) {
	s := imageServer()
	r := httptest.NewRequest(http.MethodPost, "/image-check", nil)
	r.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	s.handleImageCheckPage(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin = %d", w.Code)
	}
}
