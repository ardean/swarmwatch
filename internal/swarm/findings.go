package swarm

import (
	"fmt"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/registry"
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
	Swarm    string
	Service  string // empty for swarm-level findings
	Message  string
	VulnSev  string // set for vulnerability findings: the severity they are about
	Exposure string // exposure level of the service (internet, lan, ...), if known
}

// Findings lists what needs a reaction, worst first within a snapshot.
func (s *Snapshot) Findings(th config.Thresholds, maxScanAge time.Duration) []Finding {
	var out []Finding
	exposureOf := map[string]string{}
	for _, v := range s.Services {
		if v.Exposure != nil {
			exposureOf[v.Name] = v.Exposure.Level
		}
	}
	add := func(l Level, svc, format string, a ...any) {
		out = append(out, Finding{Level: l, Swarm: s.Name, Service: svc, Message: fmt.Sprintf(format, a...), Exposure: exposureOf[svc]})
	}
	addVuln := func(l Level, svc, sev string, n int, image string) {
		out = append(out, Finding{Level: l, Swarm: s.Name, Service: svc, VulnSev: sev, Exposure: exposureOf[svc],
			Message: fmt.Sprintf("%d fixable %s vulnerabilities in %s", n, sev, image)})
	}
	if s.Err != "" {
		add(Crit, "", "unreachable: %s", s.Err)
		return out
	}
	for _, n := range s.Nodes {
		if n.Status != "Ready" || n.Availability != "Active" {
			add(Crit, "", "node %s is %s/%s", n.Hostname, n.Status, n.Availability)
		}
	}
	if p := s.Host.MemUsedPercent(); p > th.MemPercent {
		add(Warn, "", "memory %.0f%% used", p)
	}
	for _, d := range s.Host.Disks {
		if d.Percent > th.DiskPercent {
			add(Crit, "", "disk %s %.0f%% full", d.Mount, d.Percent)
		}
	}
	for _, v := range s.Services {
		if v.Running < v.Desired {
			add(Crit, v.Name, "%d/%d replicas running", v.Running, v.Desired)
		}
		if v.RecentFailures > 0 {
			add(Warn, v.Name, "%d failed task(s) in the last day", v.RecentFailures)
		}
		if v.Update != nil && v.Update.State == registry.StateOutdated {
			add(Warn, v.Name, "image outdated: %s", v.Image)
		}
		if vs := v.Vuln; vs != nil {
			if n := vs.Fixable["CRITICAL"]; n > 0 {
				addVuln(Crit, v.Name, "CRITICAL", n, v.Image)
			}
			if n := vs.Fixable["HIGH"]; n > 0 {
				addVuln(Warn, v.Name, "HIGH", n, v.Image)
			}
			if maxScanAge > 0 && time.Since(vs.ScannedAt) > 3*maxScanAge {
				add(Info, v.Name, "vulnerability data is %s old (run: swarmwatch scan)", time.Since(vs.ScannedAt).Round(time.Hour))
			}
		}
	}
	return out
}
