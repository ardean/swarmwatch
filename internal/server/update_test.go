package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/update"
)

func TestUpdateDisabledByDefault(t *testing.T) {
	s := New(&config.Config{Swarms: []config.Swarm{{Name: "a", SSH: "local"}}}, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/update", strings.NewReader(url.Values{"swarm": {"a"}, "service": {"x_y"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleUpdate(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d; want 403 when update allow is off", w.Code)
	}
}

func TestUpdateRejectsBadRequests(t *testing.T) {
	cfg := &config.Config{Swarms: []config.Swarm{{Name: "a", SSH: "local"}}}
	cfg.Update.Allow = true
	s := New(cfg, nil)
	s.selfOnce.Do(func() {}) // no docker in tests
	s.snaps = []*swarm.Snapshot{{Name: "a", Services: []*swarm.Service{
		{Name: "x_cur", Stack: "x", Image: "nginx:1", Update: &registry.Result{State: registry.StateCurrent}},
	}}}
	post := func(vals url.Values, hdr map[string]string) int {
		r := httptest.NewRequest(http.MethodPost, "/update", strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.handleUpdate(w, r)
		return w.Code
	}
	if c := post(url.Values{"swarm": {"a"}, "service": {"x_cur"}}, map[string]string{"Origin": "http://evil.example"}); c != http.StatusForbidden {
		t.Errorf("cross-origin = %d", c)
	}
	if c := post(url.Values{"swarm": {"nope"}, "service": {"x_cur"}}, nil); c != http.StatusBadRequest {
		t.Errorf("unknown swarm = %d", c)
	}
	if c := post(url.Values{"swarm": {"a"}, "service": {"x_cur"}}, nil); c != http.StatusBadRequest {
		t.Errorf("up-to-date service = %d", c)
	}
	if c := post(url.Values{"swarm": {"a"}, "service": {"nope"}}, nil); c != http.StatusBadRequest {
		t.Errorf("unknown service = %d", c)
	}
	w := httptest.NewRecorder()
	s.handleUpdate(w, httptest.NewRequest(http.MethodGet, "/update", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d", w.Code)
	}
}

func TestUpdateLogPersistsAndFlagsFailures(t *testing.T) {
	dir := t.TempDir()
	l := loadUpdateLog(dir)
	now := time.Now()
	l.add(update.Result{Time: now.Add(-2 * time.Hour), Swarm: "m", Service: "a_web", OK: true})
	l.add(update.Result{Time: now.Add(-time.Hour), Swarm: "m", Service: "a_web", Message: "boom"})
	l.add(update.Result{Time: now.Add(-time.Hour), Swarm: "m", Service: "b_db", Message: "x"})
	l.add(update.Result{Time: now, Swarm: "m", Service: "b_db", OK: true})
	l.add(update.Result{Time: now, Swarm: "m", Service: "c_restart", Restart: true, Message: "ignored"})
	l.markScheduled(now.Truncate(time.Minute))

	l2 := loadUpdateLog(dir)
	if len(l2.History) != 5 || !l2.scheduled().Equal(now.Truncate(time.Minute)) {
		t.Fatalf("not persisted: %d entries, scheduled %v", len(l2.History), l2.scheduled())
	}
	f := l2.failed(now)
	if len(f) != 1 || f["m/a_web"].Message != "boom" {
		t.Errorf("failed = %+v; want only a_web (b_db was fixed, restarts are not updates)", f)
	}
	if f := l2.failed(now.Add(30 * 24 * time.Hour)); len(f) != 0 {
		t.Errorf("old failures should expire: %+v", f)
	}
	for i := 0; i < historyKeep+20; i++ {
		l2.add(update.Result{Time: now, Swarm: "m", Service: "s", OK: true})
	}
	if len(l2.History) != historyKeep {
		t.Errorf("history = %d; want capped at %d", len(l2.History), historyKeep)
	}
	if err := os.WriteFile(filepath.Join(dir, "updates.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l3 := loadUpdateLog(dir); len(l3.History) != 0 {
		t.Errorf("unreadable file should start empty")
	}
}

func TestUpdateFindings(t *testing.T) {
	s := New(&config.Config{Swarms: []config.Swarm{{Name: "m", SSH: "local"}}}, nil)
	s.updates = loadUpdateLog(t.TempDir())
	s.updates.add(update.Result{Time: time.Now(), Swarm: "m", Service: "a_web", Message: "boom"})
	s.updates.add(update.Result{Time: time.Now(), Swarm: "m", Service: "a_db", Message: "boom"})
	snaps := []*swarm.Snapshot{{Name: "m", Services: []*swarm.Service{
		{Name: "a_web", Stack: "a", Image: "nginx:1", Update: &registry.Result{State: registry.StateOutdated}},
		{Name: "a_db", Stack: "a", Image: "pg:1", Update: &registry.Result{State: registry.StateCurrent}},
	}}}
	got := s.updateFindings(snaps)
	if len(got) != 1 || got[0].Service != "a_web" || got[0].Level != swarm.Warn || !strings.Contains(got[0].Message, "boom") {
		t.Errorf("findings = %+v", got)
	}
}

func TestIndexShowsUpdateButton(t *testing.T) {
	cfg := &config.Config{Swarms: []config.Swarm{{Name: "m", SSH: "local"}}}
	cfg.Update.Allow = true
	s := New(cfg, nil)
	s.updates = loadUpdateLog(t.TempDir())
	s.selfOnce.Do(func() {})
	s.snaps = []*swarm.Snapshot{{Name: "m", Services: []*swarm.Service{
		{Name: "a_web", Stack: "a", Image: "nginx:1", Update: &registry.Result{State: registry.StateOutdated}},
		{Name: "a_off", Stack: "a", Image: "nginx:2", Update: &registry.Result{State: registry.StateOutdated},
			Labels: map[string]string{update.LabelUpdate: "false"}},
		{Name: "a_cur", Stack: "a", Image: "nginx:3", Update: &registry.Result{State: registry.StateCurrent}},
	}}}
	render := func() string {
		w := httptest.NewRecorder()
		s.handleIndex(w, httptest.NewRequest(http.MethodGet, "/", nil))
		return w.Body.String()
	}
	body := render()
	if n := strings.Count(body, `action="/update"`); n != 1 || !strings.Contains(body, `value="a_web"`) {
		t.Errorf("want one update button, for a_web; got %d", n)
	}
	if n := strings.Count(body, `action="/update-all"`); n != 1 || !strings.Contains(body, `>update all (1)</button>`) {
		t.Errorf("want one update-all button for the single outdated service")
	}
	s.upd.Running = true
	if !strings.Contains(render(), `disabled>update all (1)</button>`) {
		t.Errorf("update all stays visible but cannot be pressed while a roll is running")
	}
	s.upd.Running = false
	s.cfg.Update.Allow = false
	body = render()
	if strings.Contains(body, `action="/update"`) || strings.Contains(body, `action="/update-all"`) {
		t.Errorf("no button unless update allow is on")
	}
}

func TestUpdateAllRollsEveryRowButton(t *testing.T) {
	cfg := &config.Config{Swarms: []config.Swarm{{Name: "m", SSH: "local"}, {Name: "n", SSH: "local"}}}
	cfg.Update.Allow = true
	s := New(cfg, nil)
	s.updates = loadUpdateLog(t.TempDir())
	s.selfOnce.Do(func() {})
	s.snaps = []*swarm.Snapshot{
		{Name: "m", Services: []*swarm.Service{
			{Name: "a_web", Stack: "a", Image: "nginx:1", Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:bad"}},
			{Name: "a_off", Stack: "a", Image: "nginx:2", Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:off"},
				Labels: map[string]string{update.LabelUpdate: "false"}},
			{Name: "a_night", Stack: "a", Image: "nginx:4", Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:night"},
				Labels: map[string]string{update.LabelUpdate: "night"}},
			{Name: "a_cur", Stack: "a", Image: "nginx:3", Update: &registry.Result{State: registry.StateCurrent}},
		}},
		{Name: "n", Services: []*swarm.Service{
			{Name: "b_web", Stack: "b", Image: "nginx:5", Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:new"}},
		}},
	}
	s.updates.add(update.Result{Time: time.Now(), Swarm: "m", Service: "a_web", Digest: "sha256:bad", Message: "boom"})
	rolled := make(chan string, 4)
	s.rollFn = func(targets []update.Target, manual bool) {
		if !manual {
			t.Errorf("manual = false")
		}
		for _, target := range targets {
			rolled <- target.Swarm + "/" + target.Service
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/update-all", nil)
	w := httptest.NewRecorder()
	s.handleUpdateAll(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", w.Code)
	}
	var got []string
	deadline := time.Now().Add(2 * time.Second)
	for len(got) < 2 && time.Now().Before(deadline) {
		select {
		case name := <-rolled:
			got = append(got, name)
		case <-time.After(time.Until(deadline)):
		}
	}
	if strings.Join(got, ",") != "m/a_web,n/b_web" {
		t.Fatalf("rolled %v; want a_web (even though it failed before) and b_web, not the excluded or night service", got)
	}
}

func TestAPIUpdateRetriesAFailedImageAndLeavesNightAlone(t *testing.T) {
	cfg := &config.Config{Swarms: []config.Swarm{{Name: "m", SSH: "local"}}}
	cfg.Update.Schedule = "*/5 * * * *"
	s := New(cfg, nil)
	s.updates = loadUpdateLog(t.TempDir())
	s.selfOnce.Do(func() {})
	s.snaps = []*swarm.Snapshot{{Name: "m", Services: []*swarm.Service{
		{Name: "a_web", Stack: "a", Image: "nginx:1", Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:bad"}},
		{Name: "a_night", Stack: "a", Image: "nginx:4", Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:night"},
			Labels: map[string]string{update.LabelUpdate: "night"}},
	}}}
	s.updates.add(update.Result{Time: time.Now(), Swarm: "m", Service: "a_web", Digest: "sha256:bad", Message: "boom"})
	rolled := make(chan string, 2)
	s.rollFn = func(targets []update.Target, manual bool) {
		if !manual {
			t.Errorf("manual = false")
		}
		for _, target := range targets {
			rolled <- target.Service
		}
	}
	w := httptest.NewRecorder()
	s.handleAPIUpdate(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/update?swarm=m&service=a_web", nil))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d %s", w.Code, w.Body.String())
	}
	select {
	case name := <-rolled:
		if name != "a_web" {
			t.Fatalf("rolled %s", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("roll did not start")
	}
	w = httptest.NewRecorder()
	s.handleAPIUpdate(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/update?swarm=m&service=a_night", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("night status = %d", w.Code)
	}
}

func TestAPIUpdateAllRollsTheRowButtons(t *testing.T) {
	cfg := &config.Config{Swarms: []config.Swarm{{Name: "m", SSH: "local"}}}
	s := New(cfg, nil)
	s.selfOnce.Do(func() {})
	s.snaps = []*swarm.Snapshot{{Name: "m", Services: []*swarm.Service{
		{Name: "a_web", Stack: "a", Image: "nginx:1", Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:new"}},
		{Name: "a_off", Stack: "a", Image: "nginx:2", Labels: map[string]string{update.LabelUpdate: "false"},
			Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:off"}},
	}}}
	rolled := make(chan string, 4)
	s.rollFn = func(targets []update.Target, manual bool) {
		if !manual {
			rolled <- "not-manual"
			return
		}
		for _, target := range targets {
			rolled <- target.Service
		}
	}
	w := httptest.NewRecorder()
	s.handleAPIUpdateAll(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/update-all", nil))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d", w.Code)
	}
	select {
	case name := <-rolled:
		if name != "a_web" {
			t.Fatalf("rolled %s", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("roll did not start")
	}
	s.updateMu.Lock()
	w = httptest.NewRecorder()
	s.handleAPIUpdateAll(w, httptest.NewRequest(http.MethodPost, "/api/v1/images/update-all", nil))
	s.updateMu.Unlock()
	if w.Code != http.StatusConflict {
		t.Fatalf("busy = %d", w.Code)
	}
}

func TestUpdateAllRejects(t *testing.T) {
	cfg := &config.Config{Swarms: []config.Swarm{{Name: "m", SSH: "local"}}}
	s := New(cfg, nil)
	w := httptest.NewRecorder()
	s.handleUpdateAll(w, httptest.NewRequest(http.MethodPost, "/update-all", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("allow off = %d", w.Code)
	}
	s.cfg.Update.Allow = true
	s.selfOnce.Do(func() {})
	w = httptest.NewRecorder()
	s.handleUpdateAll(w, httptest.NewRequest(http.MethodGet, "/update-all", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodPost, "/update-all", nil)
	r.Header.Set("Origin", "http://evil.example")
	w = httptest.NewRecorder()
	s.handleUpdateAll(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin = %d", w.Code)
	}
	s.snaps = []*swarm.Snapshot{{Name: "m", Services: []*swarm.Service{
		{Name: "a_web", Stack: "a", Image: "nginx:1", Update: &registry.Result{State: registry.StateOutdated, Remote: "sha256:new"}},
	}}}
	s.updateMu.Lock()
	w = httptest.NewRecorder()
	s.handleUpdateAll(w, httptest.NewRequest(http.MethodPost, "/update-all", nil))
	s.updateMu.Unlock()
	if w.Code != http.StatusConflict {
		t.Errorf("busy = %d", w.Code)
	}
}

func TestScheduledRunDoesNotRetryTheSameFailedImage(t *testing.T) {
	l := loadUpdateLog(t.TempDir())
	now := time.Now()
	l.add(update.Result{Time: now, Swarm: "m", Service: "a_web", Digest: "sha256:bad", Message: "boom (rolled back)"})
	if !l.failedBefore("m", "a_web", "sha256:bad") {
		t.Error("the same digest that just failed must not be tried again")
	}
	if l.failedBefore("m", "a_web", "sha256:fixed") {
		t.Error("a newer image must be tried")
	}
	if l.failedBefore("m", "a_db", "sha256:bad") || l.failedBefore("other", "a_web", "sha256:bad") {
		t.Error("only that service in that swarm is held back")
	}
	if l.failedBefore("m", "a_web", "") {
		t.Error("without a digest nothing is held back")
	}
	l.add(update.Result{Time: now, Swarm: "m", Service: "a_web", Restart: true, OK: true})
	if !l.failedBefore("m", "a_web", "sha256:bad") {
		t.Error("a restart of the service is not an update and does not clear the failure")
	}
	l.add(update.Result{Time: now, Swarm: "m", Service: "a_web", Digest: "sha256:bad", OK: true, Manual: true})
	if l.failedBefore("m", "a_web", "sha256:bad") {
		t.Error("once the image went through (for example from the button) it is not held back")
	}
}
