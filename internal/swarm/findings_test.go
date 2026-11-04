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

func TestFindingKindsAndIDs(t *testing.T) {
	snap := &Snapshot{
		Name:  "prod",
		Nodes: []Node{{Hostname: "n1", Status: "Down", Availability: "Active"}},
		Host:  HostInfo{MemTotal: 100, MemAvail: 100, Disks: []Disk{{Mount: "/data", Percent: 97}}},
		Services: []*Service{
			{Name: "app_web", Stack: "app", Image: "web:1", Running: 0, Desired: 2, Exposure: &Exposure{Level: "internet"}},
			{Name: "app_db", Stack: "app", Image: "db:1", Running: 1, Desired: 1, Update: &registry.Result{State: registry.StateOutdated}},
			{Name: "app_cache", Stack: "app", Image: "cache:1", Running: 1, Desired: 1, Vuln: &vuln.Summary{
				Counts: map[string]int{"CRITICAL": 4, "HIGH": 2}, Fixable: map[string]int{"CRITICAL": 3, "HIGH": 2}, ScannedAt: time.Now()}},
		},
	}
	byID := map[string]Finding{}
	for _, f := range snap.Findings(config.Thresholds{DiskPercent: 85, MemPercent: 90}, 24*time.Hour) {
		if _, dup := byID[f.ID()]; dup {
			t.Errorf("duplicate id %q", f.ID())
		}
		byID[f.ID()] = f
	}
	want := map[string]struct {
		kind, level string
	}{
		"node:prod:n1":                          {"node", "crit"},
		"disk:prod:/data":                       {"disk", "crit"},
		"replicas:prod:app_web":                 {"replicas", "crit"},
		"outdated:prod:app_db":                  {"outdated", "warn"},
		"vulnerability:prod:app_cache:critical": {"vulnerability", "crit"},
		"vulnerability:prod:app_cache:high":     {"vulnerability", "warn"},
	}
	for id, w := range want {
		f, ok := byID[id]
		if !ok {
			t.Errorf("missing finding %q, have %v", id, keys(byID))
			continue
		}
		if f.Kind != w.kind || f.Level.String() != w.level {
			t.Errorf("%s = %s/%s, want %s/%s", id, f.Kind, f.Level, w.kind, w.level)
		}
	}
	web := byID["replicas:prod:app_web"]
	if web.Stack != "app" || web.Image != "web:1" || web.Exposure != "internet" {
		t.Errorf("service fields: %+v", web)
	}
	if v := byID["vulnerability:prod:app_cache:critical"]; v.Count != 3 || v.VulnSev != "CRITICAL" {
		t.Errorf("vulnerability fields: %+v", v)
	}
}

func TestIDDoesNotDependOnTheMessage(t *testing.T) {
	a := Finding{Kind: "disk", Swarm: "s", Subject: "/data", Message: "disk /data 90% full"}
	b := Finding{Kind: "disk", Swarm: "s", Subject: "/data", Message: "disk /data 97% full"}
	if a.ID() != b.ID() {
		t.Errorf("%q != %q: a changing number must not make a new finding", a.ID(), b.ID())
	}
}

func keys(m map[string]Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
