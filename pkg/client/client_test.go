package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ardean/swarmwatch/pkg/api"
)

func serve(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return New(ts.URL+"/", "secret-token-0123456789") // trailing slash on purpose
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func TestSummarySendsTheTokenAndDecodes(t *testing.T) {
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/summary" || r.Header.Get("Authorization") != "Bearer secret-token-0123456789" {
			t.Errorf("request %s, auth %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		reply(w, 200, api.Summary{Version: "0.3.0", Status: "warn", Counts: api.Counts{Warn: 2}})
	})
	got, err := c.Summary(context.Background())
	if err != nil || got.Status != "warn" || got.Counts.Warn != 2 || got.Version != "0.3.0" {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

func TestFindingsQueryOnlySendsSetFields(t *testing.T) {
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("stack") != "outdrive" || q.Get("min_level") != "warn" || len(q) != 2 {
			t.Errorf("query = %v", q)
		}
		reply(w, 200, api.Findings{Status: "ok", Findings: []api.Finding{}})
	})
	if _, err := c.Findings(context.Background(), FindingsQuery{Stack: "outdrive", MinLevel: "warn"}); err != nil {
		t.Fatal(err)
	}
}

func TestVulnsEscapesItsArguments(t *testing.T) {
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("service") != "a&b=c" {
			t.Errorf("service = %q", r.URL.Query().Get("service"))
		}
		reply(w, 200, api.Vulns{})
	})
	if _, err := c.Vulns(context.Background(), "prod", "a&b=c"); err != nil {
		t.Fatal(err)
	}
}

func TestErrorStatusCarriesTheServerMessage(t *testing.T) {
	c := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusNotFound, api.Error{Error: "the image of this service has not been scanned yet"})
	})
	_, err := c.Vulns(context.Background(), "prod", "x")
	if !IsNotFound(err) {
		t.Fatalf("err = %v", err)
	}
	var se *StatusError
	if !asStatus(err, &se) || se.Message == "" {
		t.Errorf("message lost: %v", err)
	}
}

func TestUnauthorizedIsAStatusError(t *testing.T) {
	c := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusUnauthorized, api.Error{Error: "a valid bearer token is required"})
	})
	_, err := c.Summary(context.Background())
	var se *StatusError
	if !asStatus(err, &se) || se.Code != 401 || IsNotFound(err) {
		t.Errorf("err = %v", err)
	}
}

func TestNonJSONErrorBodyStillGivesACode(t *testing.T) {
	c := serve(t, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusBadGateway) })
	_, err := c.Summary(context.Background())
	var se *StatusError
	if !asStatus(err, &se) || se.Code != 502 {
		t.Errorf("err = %v", err)
	}
}

func TestMalformedBodyIsAnError(t *testing.T) {
	c := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) })
	if _, err := c.Summary(context.Background()); err == nil {
		t.Error("a 200 that is not JSON must not look like an empty summary")
	}
}

func TestCancelledContext(t *testing.T) {
	c := serve(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, api.Summary{}) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Summary(ctx); err == nil {
		t.Error("want an error")
	}
}

func TestNoTokenSendsNoHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Error("Authorization sent without a token")
		}
		reply(w, 200, api.Summary{})
	}))
	defer ts.Close()
	if _, err := New(ts.URL, "").Summary(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func asStatus(err error, target **StatusError) bool {
	se, ok := err.(*StatusError)
	if ok {
		*target = se
	}
	return ok
}
