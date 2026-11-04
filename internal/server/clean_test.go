package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ardean/swarmwatch/internal/config"
)

func TestSameOrigin(t *testing.T) {
	mk := func(h map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://sw.local:8590/clean", nil)
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}
	for name, c := range map[string]struct {
		h    map[string]string
		want bool
	}{
		"curl, no headers":  {nil, true},
		"same origin":       {map[string]string{"Origin": "http://sw.local:8590"}, true},
		"other origin":      {map[string]string{"Origin": "http://evil.example"}, false},
		"cross-site fetch":  {map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		"same-origin fetch": {map[string]string{"Sec-Fetch-Site": "same-origin"}, true},
	} {
		if got := sameOrigin(mk(c.h)); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestCleanDisabledByDefault(t *testing.T) {
	s := New(&config.Config{Swarms: []config.Swarm{{Name: "a", SSH: "local"}}}, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/clean", strings.NewReader(url.Values{"swarm": {"a"}, "image": {"0123456789ab"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleClean(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d; want 403 when allow_clean is off", w.Code)
	}
}

func TestCleanRejectsBadRequests(t *testing.T) {
	cfg := &config.Config{Swarms: []config.Swarm{{Name: "a", SSH: "local"}}}
	cfg.Serve.AllowClean = true
	s := New(cfg, nil)
	post := func(vals url.Values, hdr map[string]string) int {
		r := httptest.NewRequest(http.MethodPost, "/clean", strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.handleClean(w, r)
		return w.Code
	}
	if c := post(url.Values{"swarm": {"a"}, "image": {"0123456789ab"}}, map[string]string{"Origin": "http://evil.example"}); c != http.StatusForbidden {
		t.Errorf("cross-origin = %d", c)
	}
	if c := post(url.Values{"swarm": {"nope"}, "image": {"0123456789ab"}}, nil); c != http.StatusBadRequest {
		t.Errorf("unknown swarm = %d", c)
	}
	if c := post(url.Values{"swarm": {"a"}}, nil); c != http.StatusBadRequest {
		t.Errorf("nothing selected = %d", c)
	}
	r := httptest.NewRequest(http.MethodGet, "/clean", nil)
	w := httptest.NewRecorder()
	s.handleClean(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d", w.Code)
	}
}
