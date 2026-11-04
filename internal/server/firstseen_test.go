package server

import (
	"os"
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/swarm"
)

func finding(kind, sw, svc string) swarm.Finding {
	return swarm.Finding{Kind: kind, Swarm: sw, Service: svc}
}

func TestFirstSeenKeepsTheOriginalTime(t *testing.T) {
	f := loadFirstSeen(t.TempDir())
	t0 := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	a := finding("outdated", "prod", "db")
	got := f.update([]swarm.Finding{a}, nil, t0)
	if !got[a.ID()].Equal(t0) {
		t.Fatalf("first = %v", got[a.ID()])
	}
	got = f.update([]swarm.Finding{a}, nil, t0.Add(time.Hour))
	if !got[a.ID()].Equal(t0) {
		t.Errorf("a finding that stays must keep its first-seen time, got %v", got[a.ID()])
	}
}

func TestFirstSeenForgetsAndRemembersAgain(t *testing.T) {
	f := loadFirstSeen(t.TempDir())
	t0 := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	a := finding("outdated", "prod", "db")
	f.update([]swarm.Finding{a}, nil, t0)
	f.update(nil, nil, t0.Add(time.Hour)) // fixed
	got := f.update([]swarm.Finding{a}, nil, t0.Add(2*time.Hour))
	if !got[a.ID()].Equal(t0.Add(2 * time.Hour)) {
		t.Errorf("a finding that came back is new again, got %v", got[a.ID()])
	}
}

func TestFirstSeenSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	a := finding("disk", "prod", "")
	a.Subject = "/data"
	loadFirstSeen(dir).update([]swarm.Finding{a}, nil, t0)
	got := loadFirstSeen(dir).update([]swarm.Finding{a}, nil, t0.Add(24*time.Hour))
	if !got[a.ID()].Equal(t0) {
		t.Errorf("after restart = %v", got[a.ID()])
	}
}

func TestFirstSeenKeepsEntriesOfAnUnreachableSwarm(t *testing.T) {
	f := loadFirstSeen(t.TempDir())
	t0 := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	a := finding("outdated", "prod", "db")
	f.update([]swarm.Finding{a}, nil, t0)
	// prod is unreachable: its findings are gone from the list, but they are not fixed
	f.update([]swarm.Finding{finding("unreachable", "prod", "")}, map[string]bool{"prod": true}, t0.Add(time.Hour))
	got := f.update([]swarm.Finding{a}, nil, t0.Add(2*time.Hour))
	if !got[a.ID()].Equal(t0) {
		t.Errorf("an outage must not make old findings look new, got %v", got[a.ID()])
	}
}

func TestFirstSeenIgnoresACorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(dir+"/first-seen.json", "{not json"); err != nil {
		t.Fatal(err)
	}
	f := loadFirstSeen(dir)
	if len(f.entries) != 0 {
		t.Errorf("entries = %v", f.entries)
	}
}

func TestFirstSeenSurvivesAnUnwritableDirectory(t *testing.T) {
	f := loadFirstSeen("/proc/does-not-exist/swarmwatch")
	got := f.update([]swarm.Finding{finding("outdated", "prod", "db")}, nil, time.Now())
	if len(got) != 1 {
		t.Errorf("a state file that cannot be written must not lose the findings: %v", got)
	}
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }
