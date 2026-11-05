package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/vuln"
)

func postScan(s *Server, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://sw.local:8590/scan", nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.handleScan(w, r)
	return w
}

func outsideWindow(t *testing.T) *config.Window {
	t.Helper()
	m := time.Now().Hour()*60 + time.Now().Minute()
	w := &config.Window{From: 18 * 60, To: 19 * 60}
	if m >= w.From && m < w.To {
		w = &config.Window{From: 6 * 60, To: 7 * 60}
	}
	if w.Contains(time.Now()) {
		t.Fatal("test window contains now")
	}
	return w
}

func TestScanNowIgnoresTheWindowAndRescansFreshImages(t *testing.T) {
	s := testServer(t, nil)
	s.cache = vuln.LoadCache(t.TempDir())
	s.scanWindow = outsideWindow(t)
	s.cfg.Scan.MaxAge = 24 * time.Hour
	if err := s.cache.Put(vuln.Key("db:8", ""), &vuln.Summary{ScannedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.cache.Put(vuln.Key("web:1", ""), &vuln.Summary{ScannedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	got := make(chan bool, 1)
	s.scanFn = func(_ context.Context, _ []*swarm.Snapshot, force bool) {
		s.mu.RLock()
		running, total := s.scan.Running, s.scan.Total
		s.mu.RUnlock()
		if !running || total != 2 {
			t.Errorf("scan status running=%v total=%d, want running with 2 images", running, total)
		}
		got <- force
	}
	w := postScan(s, map[string]string{"Origin": "http://sw.local:8590"})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("status %d location %q", w.Code, w.Header().Get("Location"))
	}
	select {
	case force := <-got:
		if !force {
			t.Fatal("a manual scan must rescan images that are still fresh")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start")
	}
}

func TestScanNowRejectsBadRequests(t *testing.T) {
	s := testServer(t, nil)
	s.cache = vuln.LoadCache(t.TempDir())
	called := false
	s.scanFn = func(context.Context, []*swarm.Snapshot, bool) { called = true }

	if w := postScan(s, map[string]string{"Origin": "http://evil.example"}); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin = %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/scan", nil)
	w := httptest.NewRecorder()
	s.handleScan(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d", w.Code)
	}
	if called {
		t.Fatal("a rejected request started a scan")
	}
}

func TestScanNowWhenOneIsAlreadyRunning(t *testing.T) {
	s := testServer(t, nil)
	s.cache = vuln.LoadCache(t.TempDir())
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	s.scan.Running = true
	called := false
	s.scanFn = func(context.Context, []*swarm.Snapshot, bool) { called = true }

	w := postScan(s, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want redirect back to the page", w.Code)
	}
	if called || !s.scan.Running {
		t.Fatalf("called=%v running=%v", called, s.scan.Running)
	}
}

func TestScanNowWithNothingToScan(t *testing.T) {
	s := testServer(t, nil)
	s.cache = vuln.LoadCache(t.TempDir())
	s.snaps = []*swarm.Snapshot{{Name: "prod", Err: "unreachable"}}
	called := false
	s.scanFn = func(context.Context, []*swarm.Snapshot, bool) { called = true }

	w := postScan(s, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", w.Code)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if called || s.scan.Running || s.scan.Note != "nothing to scan" {
		t.Fatalf("called=%v scan=%+v", called, s.scan)
	}
}

func TestScheduledScanStaysInsideTheWindow(t *testing.T) {
	s := testServer(t, nil)
	s.cache = vuln.LoadCache(t.TempDir())
	s.scanWindow = outsideWindow(t)
	s.cfg.Scan.MaxAge = time.Hour
	called := false
	s.scanFn = func(context.Context, []*swarm.Snapshot, bool) { called = true }

	s.scanIfStale(context.Background())
	if called {
		t.Fatal("automatic scan started outside the window")
	}

	s.scanWindow = nil
	var force bool
	s.scanFn = func(_ context.Context, _ []*swarm.Snapshot, f bool) { called, force = true, f }
	s.scanIfStale(context.Background())
	if !called || force {
		t.Fatalf("automatic scan called=%v force=%v, want a non-forced scan of stale images", called, force)
	}
}

func TestScheduledScanSkipsFreshImages(t *testing.T) {
	s := testServer(t, nil)
	s.cache = vuln.LoadCache(t.TempDir())
	s.cfg.Scan.MaxAge = 24 * time.Hour
	for _, image := range []string{"web:1", "db:8"} {
		if err := s.cache.Put(vuln.Key(image, ""), &vuln.Summary{ScannedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	called := false
	s.scanFn = func(context.Context, []*swarm.Snapshot, bool) { called = true }
	s.scanIfStale(context.Background())
	if called {
		t.Fatal("automatic scan ran though every image is fresh")
	}
}

func TestIndexPageOffersScanNow(t *testing.T) {
	s := testServer(t, nil)
	body := get(t, s.routes(), "/", "").Body.String()
	if !strings.Contains(body, `action="/scan"`) || !strings.Contains(body, `title="rescan every image now"`) {
		t.Fatal("the page has no scan button")
	}
	if !strings.Contains(body, "autoscan on (any time)") {
		t.Fatal("the page does not say automatic scans are on")
	}
	if strings.Contains(body, ">auto<") || strings.Contains(body, ">no,") {
		t.Fatal("without a schedule, services are not marked auto or no")
	}
	if strings.Contains(body, " disabled") {
		t.Fatal("the button is disabled when no scan is running")
	}
	s.mu.Lock()
	s.scan.Running = true
	s.scan.Done, s.scan.Total, s.scan.Current = 1, 4, "web:1"
	s.mu.Unlock()
	body = get(t, s.routes(), "/", "").Body.String()
	if !strings.Contains(body, "scanning 1/4 (web:1)") || !strings.Contains(body, " disabled") || !strings.Contains(body, "a scan is already running") {
		t.Fatal("a running scan should show progress and a button that cannot be pressed")
	}
}

func TestIndexMarksWhoTheScheduleUpdates(t *testing.T) {
	s := testServer(t, func(c *config.Config) { c.Update.Schedule = "0 4 1 * *" })
	s.selfOnce.Do(func() { s.self = "swarmwatch_swarmwatch" })
	s.snaps[0].Services = []*swarm.Service{
		{Name: "app_web", Stack: "app", Image: "web:latest"},
		{Name: "app_off", Stack: "app", Image: "web:latest", Labels: map[string]string{"swarmwatch.update": "false"}},
		{Name: "extra", Stack: swarm.Standalone, Image: "extra:1"},
		{Name: "swarmwatch_swarmwatch", Stack: "swarmwatch", Image: "swarmwatch:latest"},
	}
	body := get(t, s.routes(), "/", "").Body.String()
	for _, want := range []string{
		"autoscan on (any time)",
		">auto</span>",
		"no, excluded by label",
		"no, not a swarm service",
		"no, swarmwatch cannot update itself",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}
