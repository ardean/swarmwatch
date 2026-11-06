package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/swarm"
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
	if body.Check.Running || len(body.Services) != 2 {
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
