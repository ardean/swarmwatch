package swarm

import (
	"fmt"
	"strings"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/pkg/api"
)

type Level int

const (
	Info Level = iota
	Warn
	Crit
)

func (l Level) String() string { return [...]string{"info", "warn", "crit"}[l] }

type Finding struct {
	Level    Level
	Kind     string // one of the api.Kind* constants
	Swarm    string
	Stack    string // Docker stack of the service, empty for swarm-level findings
	Service  string // empty for swarm-level findings
	Subject  string // what the finding is about when it is not a service: node name, disk mount
	Message  string
	Image    string // image of the service, for image findings
	VulnSev  string // set for vulnerability findings: the severity they are about
	Count    int    // set for vulnerability findings: how many fixable ones
	Exposure string // exposure level of the service (internet, lan, ...), if known
}

// ID names the problem on the object it is about, the same on every refresh and restart:
// kind, swarm, then the service or subject, then the severity for vulnerabilities.
func (f Finding) ID() string {
	parts := []string{f.Kind, f.Swarm}
	switch {
	case f.Service != "":
		parts = append(parts, f.Service)
	case f.Subject != "":
		parts = append(parts, f.Subject)
	}
	if f.VulnSev != "" {
		parts = append(parts, strings.ToLower(f.VulnSev))
	}
	return strings.Join(parts, ":")
}

// Findings lists what needs a reaction, worst first within a snapshot.
func (s *Snapshot) Findings(th config.Thresholds, maxScanAge time.Duration) []Finding {
	var out []Finding
	// add records a swarm-level finding; addSvc one about a service (stack, image and exposure come from it).
	add := func(l Level, kind, subject, format string, a ...any) {
		out = append(out, Finding{Level: l, Kind: kind, Swarm: s.Name, Subject: subject, Message: fmt.Sprintf(format, a...)})
	}
	addSvc := func(l Level, kind string, v *Service, format string, a ...any) *Finding {
		f := Finding{Level: l, Kind: kind, Swarm: s.Name, Stack: v.Stack, Service: v.Name, Image: v.Image, Message: fmt.Sprintf(format, a...)}
		if v.Exposure != nil {
			f.Exposure = v.Exposure.Level
		}
		out = append(out, f)
		return &out[len(out)-1]
	}
	if s.Err != "" {
		add(Crit, api.KindUnreachable, "", "unreachable: %s", s.Err)
		return out
	}
	for _, n := range s.Nodes {
		if n.Status != "Ready" || n.Availability != "Active" {
			add(Crit, api.KindNode, n.Hostname, "node %s is %s/%s", n.Hostname, n.Status, n.Availability)
		}
	}
	if p := s.Host.MemUsedPercent(); p > th.MemPercent {
		add(Warn, api.KindMemory, "", "memory %.0f%% used", p)
	}
	for _, d := range s.Host.Disks {
		if d.Percent > th.DiskPercent {
			add(Crit, api.KindDisk, d.Mount, "disk %s %.0f%% full", d.Mount, d.Percent)
		}
	}
	if !s.Unused.Empty() {
		add(Info, api.KindUnused, "", "%s can be cleaned up", s.Unused.Summary())
	}
	for _, v := range s.Services {
		if v.Running < v.Desired {
			addSvc(Crit, api.KindReplicas, v, "%d/%d replicas running", v.Running, v.Desired)
		}
		if v.RecentFailures > 0 {
			addSvc(Warn, api.KindFailedTasks, v, "%d failed task(s) in the last day", v.RecentFailures)
		}
		if v.Update != nil && v.Update.State == registry.StateOutdated {
			addSvc(Warn, api.KindOutdated, v, "image outdated: %s", v.Image)
		}
		if vs := v.Vuln; vs != nil {
			for _, sev := range []struct {
				name  string
				level Level
			}{{"CRITICAL", Crit}, {"HIGH", Warn}} {
				if n := vs.Fixable[sev.name]; n > 0 {
					f := addSvc(sev.level, api.KindVuln, v, "%d fixable %s vulnerabilities in %s", n, sev.name, v.Image)
					f.VulnSev, f.Count = sev.name, n
				}
			}
			if maxScanAge > 0 && time.Since(vs.ScannedAt) > 3*maxScanAge {
				addSvc(Info, api.KindStaleScan, v, "vulnerability data is %s old (run: swarmwatch scan)", time.Since(vs.ScannedAt).Round(time.Hour))
			}
		}
	}
	return out
}
