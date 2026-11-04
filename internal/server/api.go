package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/version"
	"github.com/ardean/swarmwatch/pkg/api"
)

// routes builds the handler. The JSON API lives under /api/v1 (see pkg/api); the older /api/findings
// and /api/vulns paths serve the same data and stay for existing scripts. /api/overview and
// /api/exposure are not part of v1: overview is the raw snapshot, exposure is how instances talk.
// Every /api/ path needs the bearer token when one is configured; /healthz never does.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/v1/findings", s.handleFindings)
	apiMux.HandleFunc("/api/v1/summary", s.handleSummary)
	apiMux.HandleFunc("/api/v1/vulns", s.handleVulnsJSON)
	apiMux.HandleFunc("/api/findings", s.handleFindings)
	apiMux.HandleFunc("/api/vulns", s.handleVulnsJSON)
	apiMux.HandleFunc("/api/overview", s.handleOverview)
	apiMux.HandleFunc("/api/exposure", s.handleExposure)
	apiMux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "unknown API path")
	})
	mux.Handle("/api/", s.requireToken(apiMux))

	if !s.cfg.Serve.DisableUI {
		mux.HandleFunc("/", s.handleIndex)
		mux.HandleFunc("/vulns", s.handleVulns)
		mux.HandleFunc("/clean", s.handleClean)
		mux.HandleFunc("/update", s.handleUpdate)
	}
	return secureHeaders(mux)
}

// secureHeaders sets the headers every response gets. The pages load nothing from elsewhere, so the
// content security policy can forbid it; the inline style and the refresh meta tag are all they use.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		// same-origin, not no-referrer: with no-referrer browsers send "Origin: null" on the clean-up form POST,
		// which the same-origin check rightly refuses. Nothing is sent to other sites either way.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

// authLog limits "rejected request" log lines to one a minute, so a scanner cannot fill the log.
type authLog struct {
	mu       sync.Mutex
	last     time.Time
	rejected int
}

func (a *authLog) note(r *http.Request, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rejected++
	if now.Sub(a.last) < time.Minute {
		return
	}
	log.Printf("api: rejected %d request(s) without a valid token, latest from %s for %s", a.rejected, r.RemoteAddr, r.URL.Path)
	a.last, a.rejected = now, 0
}

// requireToken lets a request through when no token is configured or the bearer token matches. The
// comparison is on digests, in constant time, so neither the content nor the length leaks.
func (s *Server) requireToken(next http.Handler) http.Handler {
	token := s.cfg.Serve.Token
	if token == "" {
		return next
	}
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		have := sha256.Sum256([]byte(got))
		if !ok || subtle.ConstantTimeCompare(have[:], want[:]) != 1 {
			s.authLog.note(r, time.Now())
			w.Header().Set("WWW-Authenticate", `Bearer realm="swarmwatch"`)
			writeError(w, http.StatusUnauthorized, "a valid bearer token is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(api.Error{Error: msg})
}

func levelName(l swarm.Level) string { return l.String() }

// worst returns "ok" for no findings, otherwise the highest level.
func worst(levels []swarm.Level) string {
	if len(levels) == 0 {
		return api.LevelOK
	}
	w := swarm.Info
	for _, l := range levels {
		if l > w {
			w = l
		}
	}
	return levelName(w)
}

func (s *Server) stale() bool {
	return s.updated.IsZero() || time.Since(s.updated) > 5*s.cfg.Serve.Refresh
}

// parseLevel maps min_level to a level; "" means every level.
func parseLevel(v string) (swarm.Level, bool) {
	switch v {
	case "", api.LevelInfo:
		return swarm.Info, true
	case api.LevelWarn:
		return swarm.Warn, true
	case api.LevelCrit:
		return swarm.Crit, true
	}
	return 0, false
}

// handleFindings serves the findings, optionally narrowed with min_level, swarm, stack, service and
// kind. The status is the worst level of the findings returned, so a consumer that asks for one
// stack gets the status of that stack.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	minLevel, ok := parseLevel(q.Get("min_level"))
	if !ok {
		writeError(w, http.StatusBadRequest, "min_level must be info, warn or crit")
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]api.Finding, 0, len(s.findings))
	var levels []swarm.Level
	for _, f := range s.findings {
		if f.Level < minLevel ||
			(q.Get("swarm") != "" && f.Swarm != q.Get("swarm")) ||
			(q.Get("stack") != "" && f.Stack != q.Get("stack")) ||
			(q.Get("service") != "" && f.Service != q.Get("service")) ||
			(q.Get("kind") != "" && f.Kind != q.Get("kind")) {
			continue
		}
		out = append(out, s.apiFinding(f))
		levels = append(levels, f.Level)
	}
	writeJSON(w, api.Findings{Status: worst(levels), Updated: s.updated, Stale: s.stale(), Findings: out})
}

// apiFinding converts a finding; the caller holds s.mu.
func (s *Server) apiFinding(f swarm.Finding) api.Finding {
	return api.Finding{
		ID: f.ID(), Kind: f.Kind, Level: levelName(f.Level), Swarm: f.Swarm, Stack: f.Stack, Service: f.Service,
		Message: f.Message, Image: f.Image, Exposure: f.Exposure, Severity: f.VulnSev, Count: f.Count,
		FirstSeen: s.seen[f.ID()],
	}
}

// handleSummary serves the numbers a status badge needs, in a few hundred bytes.
func (s *Server) handleSummary(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sum := api.Summary{Version: version.Version, Updated: s.updated, Stale: s.stale(),
		Scan: api.Scan{Running: s.scan.Running, Current: s.scan.Current, Done: s.scan.Done, Total: s.scan.Total,
			LastEnd: s.scan.LastEnd, LastError: s.scan.LastError}}
	if !s.updated.IsZero() {
		sum.AgeSeconds = int64(time.Since(s.updated).Seconds())
	}
	var all []swarm.Level
	perSwarm := map[string][]swarm.Level{}
	for _, f := range s.findings {
		all = append(all, f.Level)
		perSwarm[f.Swarm] = append(perSwarm[f.Swarm], f.Level)
		switch f.Level {
		case swarm.Crit:
			sum.Counts.Crit++
		case swarm.Warn:
			sum.Counts.Warn++
		default:
			sum.Counts.Info++
		}
	}
	sum.Status = worst(all)
	sum.Swarms = make([]api.SwarmStatus, 0, len(s.snaps))
	for _, sn := range s.snaps {
		sum.Swarms = append(sum.Swarms, api.SwarmStatus{Name: sn.Name, Status: worst(perSwarm[sn.Name]), Error: sn.Err})
	}
	writeJSON(w, sum)
}

// handleVulnsJSON serves every vulnerability of the image of one service.
func (s *Server) handleVulnsJSON(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("swarm") == "" || q.Get("service") == "" {
		writeError(w, http.StatusBadRequest, "swarm and service are required")
		return
	}
	svc, sum := s.findService(q.Get("swarm"), q.Get("service"))
	switch {
	case svc == nil:
		writeError(w, http.StatusNotFound, "no such service")
		return
	case sum == nil:
		writeError(w, http.StatusNotFound, "the image of this service has not been scanned yet")
		return
	}
	items := make([]api.Vuln, 0, len(sum.Items))
	for _, it := range sum.Items {
		items = append(items, api.Vuln{ID: it.ID, Severity: it.Severity, Package: it.Package,
			Installed: it.Installed, Fixed: it.Fixed, Title: it.Title, URL: it.Link()})
	}
	writeJSON(w, api.Vulns{Swarm: q.Get("swarm"), Service: svc.Name, Image: svc.Image,
		ScannedAt: sum.ScannedAt, Counts: sum.Counts, Fixable: sum.Fixable, Items: items})
}
