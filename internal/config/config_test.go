package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// containerEnv sets the minimum environment of a container run and clears everything else swarmwatch reads.
func containerEnv(t *testing.T, extra map[string]string) {
	t.Helper()
	for _, k := range []string{"SWARMWATCH_TOKEN", "SWARMWATCH_TOKEN_FILE", "SWARMWATCH_PEER_TOKEN",
		"SWARMWATCH_DISABLE_UI", "SWARMWATCH_ALLOW_CLEAN", "SWARMWATCH_SCAN_WINDOW", "SWARMWATCH_ALLOW_UPDATE",
		"SWARMWATCH_UPDATE_SCHEDULE", "SWARMWATCH_UPDATE_WAIT", "SWARMWATCH_UPDATE_CLEANUP"} {
		t.Setenv(k, "")
	}
	t.Setenv("SWARMWATCH_NAME", "prod")
	for k, v := range extra {
		t.Setenv(k, v)
	}
}

func TestTokenTooShortIsRefused(t *testing.T) {
	containerEnv(t, map[string]string{"SWARMWATCH_TOKEN": "short"})
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "shorter") {
		t.Fatalf("err = %v", err)
	}
}

func TestTokenFileIsTrimmed(t *testing.T) {
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte("0123456789abcdef0123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	containerEnv(t, map[string]string{"SWARMWATCH_TOKEN_FILE": f})
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Serve.Token != "0123456789abcdef0123" {
		t.Errorf("token = %q", c.Serve.Token)
	}
}

func TestInlineTokenWinsOverFile(t *testing.T) {
	containerEnv(t, map[string]string{"SWARMWATCH_TOKEN": "inline-token-0123456", "SWARMWATCH_TOKEN_FILE": "/does/not/exist"})
	c, err := Load("")
	if err != nil || c.Serve.Token != "inline-token-0123456" {
		t.Fatalf("token = %q, err = %v", c.Serve.Token, err)
	}
}

func TestMissingOrEmptyTokenFileIsAnError(t *testing.T) {
	containerEnv(t, map[string]string{"SWARMWATCH_TOKEN_FILE": "/does/not/exist"})
	if _, err := Load(""); err == nil {
		t.Error("a missing token file must stop the start, not silently run without a token")
	}
	f := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(f, []byte(" \n"), 0o600)
	containerEnv(t, map[string]string{"SWARMWATCH_TOKEN_FILE": f})
	if _, err := Load(""); err == nil {
		t.Error("an empty token file must stop the start")
	}
}

func TestNoTokenMeansOpenAPI(t *testing.T) {
	containerEnv(t, nil)
	c, err := Load("")
	if err != nil || c.Serve.Token != "" {
		t.Fatalf("token = %q, err = %v", c.Serve.Token, err)
	}
}

func TestDisableUIConflictsWithClean(t *testing.T) {
	containerEnv(t, map[string]string{"SWARMWATCH_DISABLE_UI": "1", "SWARMWATCH_ALLOW_CLEAN": "1"})
	if _, err := Load(""); err == nil {
		t.Error("allow_clean without the UI must be refused")
	}
}

func TestParseWindow(t *testing.T) {
	for _, bad := range []string{"02:00", "2-5", "02:00-02:00", "25:00-03:00", "02:00-03:60", "a-b"} {
		if _, err := ParseWindow(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	if w, err := ParseWindow(""); err != nil || w != nil {
		t.Errorf("empty = %v, %v", w, err)
	}
	at := func(h, m int) time.Time { return time.Date(2026, 11, 4, h, m, 0, 0, time.UTC) }
	day, _ := ParseWindow("02:00-05:00")
	for _, tc := range []struct {
		h, m int
		in   bool
	}{{1, 59, false}, {2, 0, true}, {4, 59, true}, {5, 0, false}, {14, 0, false}} {
		if got := day.Contains(at(tc.h, tc.m)); got != tc.in {
			t.Errorf("02:00-05:00 contains %02d:%02d = %v", tc.h, tc.m, got)
		}
	}
	night, _ := ParseWindow("22:00-04:00")
	for _, tc := range []struct {
		h, m int
		in   bool
	}{{21, 59, false}, {22, 0, true}, {23, 30, true}, {0, 0, true}, {3, 59, true}, {4, 0, false}, {12, 0, false}} {
		if got := night.Contains(at(tc.h, tc.m)); got != tc.in {
			t.Errorf("22:00-04:00 contains %02d:%02d = %v", tc.h, tc.m, got)
		}
	}
	var none *Window
	if !none.Contains(at(12, 0)) {
		t.Error("no window means always")
	}
}

func TestBadScanWindowStopsTheStart(t *testing.T) {
	containerEnv(t, map[string]string{"SWARMWATCH_SCAN_WINDOW": "never"})
	if _, err := Load(""); err == nil {
		t.Error("a bad window must be refused")
	}
}

func TestUpdateSettings(t *testing.T) {
	containerEnv(t, nil)
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Update.Allow || c.Update.Schedule != "" || c.Update.Cleanup || c.Update.Wait != time.Minute {
		t.Errorf("defaults: %+v", c.Update)
	}

	containerEnv(t, map[string]string{"SWARMWATCH_ALLOW_UPDATE": "1", "SWARMWATCH_UPDATE_SCHEDULE": " 0 4 1 * * ",
		"SWARMWATCH_UPDATE_WAIT": "90", "SWARMWATCH_UPDATE_CLEANUP": "true"})
	if c, err = Load(""); err != nil {
		t.Fatal(err)
	}
	if !c.Update.Allow || c.Update.Schedule != "0 4 1 * *" || c.Update.Wait != 90*time.Second || !c.Update.Cleanup {
		t.Errorf("env: %+v", c.Update)
	}

	containerEnv(t, map[string]string{"SWARMWATCH_UPDATE_WAIT": "2m"})
	if c, err = Load(""); err != nil || c.Update.Wait != 2*time.Minute {
		t.Errorf("duration wait: %v %+v", err, c)
	}
	for name, env := range map[string]map[string]string{
		"bad schedule": {"SWARMWATCH_UPDATE_SCHEDULE": "every day"},
		"bad wait":     {"SWARMWATCH_UPDATE_WAIT": "soon"},
		"no ui":        {"SWARMWATCH_ALLOW_UPDATE": "1", "SWARMWATCH_DISABLE_UI": "1"},
	} {
		containerEnv(t, env)
		if _, err := Load(""); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	containerEnv(t, map[string]string{"SWARMWATCH_UPDATE_SCHEDULE": "0 4 * * *", "SWARMWATCH_DISABLE_UI": "1"})
	if _, err := Load(""); err != nil {
		t.Errorf("a schedule works without the UI: %v", err)
	}
}
