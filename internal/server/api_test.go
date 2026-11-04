package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/vuln"
	"github.com/ardean/swarmwatch/pkg/api"
)

const testToken = "0123456789abcdef0123456789abcdef"

// testServer is a server holding a fixed snapshot: two stacks, three findings of different levels.
func testServer(t *testing.T, mutate func(*config.Config)) *Server {
	t.Helper()
	cfg := &config.Config{Swarms: []config.Swarm{{Name: "prod", SSH: "local"}}}
	cfg.Serve.Refresh = 2 * time.Minute
	if mutate != nil {
		mutate(cfg)
	}
	now := time.Now()
	findings := []swarm.Finding{
		{Level: swarm.Crit, Kind: api.KindReplicas, Swarm: "prod", Stack: "app", Service: "app_web", Image: "web:1", Message: "0/1 replicas running", Exposure: "internet"},
		{Level: swarm.Warn, Kind: api.KindOutdated, Swarm: "prod", Stack: "data", Service: "data_db", Image: "db:8", Message: "image outdated: db:8"},
		{Level: swarm.Info, Kind: api.KindUnused, Swarm: "prod", Message: "2 unused images can be cleaned up"},
	}
	svc := &swarm.Service{Name: "app_web", Stack: "app", Image: "web:1", Vuln: &vuln.Summary{
		Counts: map[string]int{"CRITICAL": 1}, Fixable: map[string]int{"CRITICAL": 1}, ScannedAt: now,
		Items: []vuln.Item{{ID: "CVE-2026-0001", Severity: "CRITICAL", Package: "openssl", Installed: "3.0", Fixed: "3.1", Title: "t"}}}}
	unscanned := &swarm.Service{Name: "data_db", Stack: "data", Image: "db:8"}
	s := &Server{cfg: cfg, firstSeen: loadFirstSeen(t.TempDir()), updated: now,
		snaps:    []*swarm.Snapshot{{Name: "prod", Services: []*swarm.Service{svc, unscanned}}},
		findings: findings, seen: map[string]time.Time{}}
	for _, f := range findings {
		s.seen[f.ID()] = now.Add(-time.Hour)
	}
	return s
}

func get(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return v
}

func TestFindingsHaveStructuredFields(t *testing.T) {
	h := testServer(t, nil).routes()
	got := decode[api.Findings](t, get(t, h, "/api/v1/findings", ""))
	if got.Status != "crit" || len(got.Findings) != 3 {
		t.Fatalf("status %q, %d findings", got.Status, len(got.Findings))
	}
	f := got.Findings[0]
	if f.ID != "replicas:prod:app_web" || f.Kind != api.KindReplicas || f.Level != "crit" || f.Stack != "app" ||
		f.Image != "web:1" || f.Exposure != "internet" || f.FirstSeen.IsZero() {
		t.Errorf("finding = %+v", f)
	}
}

func TestFindingsFilters(t *testing.T) {
	h := testServer(t, nil).routes()
	for path, want := range map[string]struct {
		status string
		n      int
	}{
		"/api/v1/findings?min_level=warn":            {"crit", 2},
		"/api/v1/findings?min_level=crit":            {"crit", 1},
		"/api/v1/findings?stack=data":                {"warn", 1},
		"/api/v1/findings?stack=data&min_level=crit": {"ok", 0},
		"/api/v1/findings?kind=unused":               {"info", 1},
		"/api/v1/findings?service=app_web":           {"crit", 1},
		"/api/v1/findings?swarm=other":               {"ok", 0},
	} {
		got := decode[api.Findings](t, get(t, h, path, ""))
		if got.Status != want.status || len(got.Findings) != want.n {
			t.Errorf("%s: status %q, %d findings; want %q, %d", path, got.Status, len(got.Findings), want.status, want.n)
		}
		if got.Findings == nil {
			t.Errorf("%s: findings must be [] and not null", path)
		}
	}
	if w := get(t, h, "/api/v1/findings?min_level=bogus", ""); w.Code != http.StatusBadRequest {
		t.Errorf("bad min_level = %d", w.Code)
	}
}

func TestLegacyPathsServeTheSameData(t *testing.T) {
	h := testServer(t, nil).routes()
	a, b := get(t, h, "/api/findings", ""), get(t, h, "/api/v1/findings", "")
	if a.Code != 200 || a.Body.String() != b.Body.String() {
		t.Errorf("legacy and v1 findings differ")
	}
	if w := get(t, h, "/api/vulns?swarm=prod&service=app_web", ""); w.Code != 200 {
		t.Errorf("legacy vulns = %d", w.Code)
	}
}

func TestSummary(t *testing.T) {
	s := testServer(t, nil)
	got := decode[api.Summary](t, get(t, s.routes(), "/api/v1/summary", ""))
	if got.Status != "crit" || got.Counts != (api.Counts{Crit: 1, Warn: 1, Info: 1}) || got.Stale {
		t.Errorf("summary = %+v", got)
	}
	if len(got.Swarms) != 1 || got.Swarms[0].Name != "prod" || got.Swarms[0].Status != "crit" {
		t.Errorf("swarms = %+v", got.Swarms)
	}
	if got.Version == "" {
		t.Error("version missing")
	}
	s.updated = time.Now().Add(-11 * time.Minute)
	got = decode[api.Summary](t, get(t, s.routes(), "/api/v1/summary", ""))
	if !got.Stale || got.AgeSeconds < 600 {
		t.Errorf("stale summary = %+v", got)
	}
}

func TestVulns(t *testing.T) {
	h := testServer(t, nil).routes()
	got := decode[api.Vulns](t, get(t, h, "/api/v1/vulns?swarm=prod&service=app_web", ""))
	if len(got.Items) != 1 || got.Items[0].ID != "CVE-2026-0001" || got.Items[0].URL == "" || got.Fixable["CRITICAL"] != 1 {
		t.Errorf("vulns = %+v", got)
	}
	for path, code := range map[string]int{
		"/api/v1/vulns?swarm=prod&service=nope":    http.StatusNotFound,
		"/api/v1/vulns?swarm=prod&service=data_db": http.StatusNotFound, // not scanned yet
		"/api/v1/vulns?swarm=prod":                 http.StatusBadRequest,
	} {
		w := get(t, h, path, "")
		if w.Code != code || decode[api.Error](t, w).Error == "" {
			t.Errorf("%s = %d %s", path, w.Code, w.Body.String())
		}
	}
}

func TestTokenIsRequiredOnEveryAPIPath(t *testing.T) {
	h := testServer(t, func(c *config.Config) { c.Serve.Token = testToken }).routes()
	paths := []string{"/api/v1/findings", "/api/v1/summary", "/api/v1/vulns?swarm=prod&service=app_web",
		"/api/findings", "/api/vulns?swarm=prod&service=app_web", "/api/overview", "/api/exposure", "/api/v1/nope", "/api/"}
	for _, p := range paths {
		for name, tok := range map[string]string{"none": "", "wrong": "wrong-token-0123456789", "prefix": testToken[:20], "longer": testToken + "x"} {
			w := get(t, h, p, tok)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s with %s token = %d, want 401", p, name, w.Code)
			}
			if w.Header().Get("WWW-Authenticate") == "" {
				t.Errorf("%s: no WWW-Authenticate", p)
			}
			if strings.Contains(w.Body.String(), testToken) {
				t.Errorf("%s: response echoes the token", p)
			}
		}
		if w := get(t, h, p, testToken); w.Code == http.StatusUnauthorized {
			t.Errorf("%s rejects the right token", p)
		}
	}
}

func TestOnlyBearerSchemeCounts(t *testing.T) {
	h := testServer(t, func(c *config.Config) { c.Serve.Token = testToken }).routes()
	for _, v := range []string{testToken, "Basic " + testToken, "bearer " + testToken, "Bearer"} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil)
		r.Header.Set("Authorization", v)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q = %d", v, w.Code)
		}
	}
}

func TestHealthzNeedsNoToken(t *testing.T) {
	h := testServer(t, func(c *config.Config) { c.Serve.Token = testToken }).routes()
	if w := get(t, h, "/healthz", ""); w.Code != 200 {
		t.Errorf("healthz = %d", w.Code)
	}
}

func TestNoTokenKeepsTheAPIOpen(t *testing.T) {
	if w := get(t, testServer(t, nil).routes(), "/api/v1/summary", ""); w.Code != 200 {
		t.Errorf("= %d", w.Code)
	}
}

func TestDisableUIServesOnlyTheAPI(t *testing.T) {
	h := testServer(t, func(c *config.Config) { c.Serve.DisableUI = true }).routes()
	for _, p := range []string{"/", "/vulns?swarm=prod&service=app_web", "/clean"} {
		if w := get(t, h, p, ""); w.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", p, w.Code)
		}
	}
	if w := get(t, h, "/api/v1/summary", ""); w.Code != 200 {
		t.Errorf("api = %d", w.Code)
	}
	if w := get(t, h, "/healthz", ""); w.Code != 200 {
		t.Errorf("healthz = %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := testServer(t, nil).routes()
	for _, p := range []string{"/", "/api/v1/summary", "/healthz"} {
		w := get(t, h, p, "")
		for _, k := range []string{"X-Content-Type-Options", "Content-Security-Policy", "X-Frame-Options", "Referrer-Policy"} {
			if w.Header().Get(k) == "" {
				t.Errorf("%s: missing %s", p, k)
			}
		}
	}
	if rp := get(t, h, "/", "").Header().Get("Referrer-Policy"); rp != "same-origin" {
		t.Errorf("Referrer-Policy = %q, want same-origin (no-referrer makes browsers post Origin: null)", rp)
	}
	if cc := get(t, h, "/api/v1/summary", "").Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestIndexPageHasNoInlineScript(t *testing.T) {
	s := testServer(t, func(c *config.Config) { c.Serve.AllowClean = true })
	s.snaps[0].Unused = &swarm.Unused{Images: []swarm.UnusedImage{{ID: "0123456789ab", Tags: []string{"old:1"}}}}
	w := get(t, s.routes(), "/", "")
	body := strings.ToLower(w.Body.String())
	if !strings.Contains(body, `action="/clean"`) {
		t.Fatal("the clean form is not on the page, the test would prove nothing")
	}
	if w.Code != 200 || strings.Contains(body, "<script") || strings.Contains(body, "onsubmit") || strings.Contains(body, "onclick") {
		t.Errorf("the page must work under a policy that forbids scripts (status %d)", w.Code)
	}
}
