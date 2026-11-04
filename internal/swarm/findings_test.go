package swarm

import (
	"strings"
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/vuln"
)

func TestFindings(t *testing.T) {
	snap := &Snapshot{
		Name:  "s",
		Nodes: []Node{{Hostname: "n1", Status: "Down", Availability: "Active"}},
		Host: HostInfo{MemTotal: 100, MemAvail: 5,
			Disks: []Disk{{Mount: "/data", Percent: 97}}},
		Services: []*Service{
			{Name: "a", Image: "a:1", Running: 0, Desired: 1},
			{Name: "b", Image: "b:1", Running: 1, Desired: 1, RecentFailures: 2},
			{Name: "c", Image: "c:1", Running: 1, Desired: 1, Update: &registry.Result{State: registry.StateOutdated}},
			{Name: "d", Image: "d:1", Running: 1, Desired: 1, Vuln: &vuln.Summary{
				Counts: map[string]int{"CRITICAL": 3}, Fixable: map[string]int{"CRITICAL": 1}, ScannedAt: time.Now()}},
			{Name: "ok", Image: "ok:1", Running: 1, Desired: 1, Update: &registry.Result{State: registry.StateCurrent}},
		},
	}
	got := snap.Findings(config.Thresholds{DiskPercent: 85, MemPercent: 90}, 24*time.Hour)
	want := map[string]Level{
		"node n1":          Crit,
		"memory":           Warn,
		"disk /data":       Crit,
		"0/1 replicas":     Crit,
		"failed task":      Warn,
		"image outdated":   Warn,
		"fixable CRITICAL": Crit,
	}
	for frag, lvl := range want {
		found := false
		for _, f := range got {
			if strings.Contains(f.Message, frag) {
				found = true
				if f.Level != lvl {
					t.Errorf("%q level = %v; want %v", frag, f.Level, lvl)
				}
			}
		}
		if !found {
			t.Errorf("missing finding %q in %+v", frag, got)
		}
	}
	for _, f := range got {
		if f.Service == "ok" {
			t.Errorf("healthy service flagged: %+v", f)
		}
	}
}

func TestFindingsUnreachable(t *testing.T) {
	got := (&Snapshot{Name: "s", Err: "ssh: timeout"}).Findings(config.Thresholds{}, 0)
	if len(got) != 1 || got[0].Level != Crit {
		t.Errorf("got %+v", got)
	}
}
