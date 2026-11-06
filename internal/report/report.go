// Package report renders snapshots as terminal text and provides the row data the web UI reuses.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ardean/swarmwatch/internal/exposure"
	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/swarm"
)

// Tones classify a cell for colouring (ANSI in the terminal, CSS classes on the web).
const (
	ToneNone = ""
	ToneCrit = "crit"
	ToneWarn = "warn"
	ToneOK   = "ok"
	ToneDim  = "dim"
	ToneBold = "bold"
)

var ansi = map[string]string{ToneCrit: "31", ToneWarn: "33", ToneOK: "32", ToneDim: "2", ToneBold: "1"}

type Cell struct{ Text, Tone string }

// Row is one service line of a swarm table.
type Row struct {
	Service                                                     string // full service name, e.g. "paperless_db"
	Stack, Name, Exposure, Repl, CPU, Mem, Image, Update, Vulns Cell
	Hosts                                                       []string // public/LAN hostnames behind the exposure badge
	Level                                                       string   // exposure level (internet, lan, ...), for filtering
}

var Header = []string{"STACK", "SERVICE", "EXPOSURE", "REPL", "CPU", "MEM", "IMAGE", "UPDATE", "VULNS (fixable)"}

func (r Row) Cells() []Cell {
	return []Cell{r.Stack, r.Name, r.Exposure, r.Repl, r.CPU, r.Mem, r.Image, r.Update, r.Vulns}
}

// Rows builds the service table; the stack name is only set on the first row of each stack.
func Rows(s *swarm.Snapshot) []Row {
	var rows []Row
	last := ""
	for _, v := range s.Services {
		stack := v.Stack
		if stack == last {
			stack = ""
		} else {
			last = v.Stack
		}
		repl := Cell{fmt.Sprintf("%d/%d", v.Running, v.Desired), ToneNone}
		if v.Running < v.Desired {
			repl.Tone = ToneCrit
		} else if v.RecentFailures > 0 {
			repl = Cell{repl.Text + fmt.Sprintf(" !%d", v.RecentFailures), ToneWarn}
		}
		mem := Size(v.MemUsed)
		if v.MemLimit > 0 && v.MemLimit < s.Host.MemTotal*9/10 {
			mem += " / " + Size(v.MemLimit)
		}
		rows = append(rows, Row{
			Service: v.Name, Stack: Cell{stack, ToneBold}, Name: Cell{strings.TrimPrefix(v.Name, v.Stack+"_"), ToneNone},
			Repl: repl, CPU: Cell{fmt.Sprintf("%.1f%%", v.CPUPercent), ToneNone}, Mem: Cell{mem, ToneNone},
			Image: Cell{v.Image, ToneNone}, Update: updateCell(v), Vulns: vulnCell(v),
			Exposure: exposureCell(v), Hosts: hostsOf(v), Level: levelOf(v),
		})
	}
	return rows
}

// ExposureLabel is the short badge text for an exposure level.
func ExposureLabel(e *swarm.Exposure) string {
	switch {
	case e == nil:
		return "-"
	case e.Gateway:
		return "gateway"
	case e.Level == exposure.InternetSSO:
		return "internet·SSO"
	}
	return e.Level
}

// ExposureTone colours a level: red for internet, yellow behind SSO, plain for LAN, green internal.
func ExposureTone(level string) string {
	switch level {
	case exposure.Internet:
		return ToneCrit
	case exposure.InternetSSO:
		return ToneWarn
	case exposure.Internal:
		return ToneOK
	}
	return ToneNone
}

func exposureCell(v *swarm.Service) Cell {
	if v.Exposure == nil {
		return Cell{"-", ToneDim}
	}
	return Cell{ExposureLabel(v.Exposure), ExposureTone(v.Exposure.Level)}
}

func levelOf(v *swarm.Service) string {
	if v.Exposure == nil {
		return ""
	}
	return v.Exposure.Level
}

func hostsOf(v *swarm.Service) []string {
	if v.Exposure == nil {
		return nil
	}
	return v.Exposure.Hosts
}

// ExposureCounts counts services per level, most exposed first.
func ExposureCounts(s *swarm.Snapshot) []LevelCount {
	n := map[string]int{}
	for _, v := range s.Services {
		if v.Exposure != nil {
			n[v.Exposure.Level]++
		}
	}
	var out []LevelCount
	for _, l := range []string{exposure.Internet, exposure.InternetSSO, exposure.LAN, exposure.Internal} {
		if n[l] > 0 {
			out = append(out, LevelCount{l, n[l]})
		}
	}
	return out
}

type LevelCount struct {
	Level string
	Count int
}

func updateCell(v *swarm.Service) Cell {
	if v.Update == nil {
		return Cell{"-", ToneDim}
	}
	switch v.Update.State {
	case registry.StateCurrent:
		return Cell{"current", ToneOK}
	case registry.StateOutdated:
		return Cell{"OUTDATED", ToneWarn}
	}
	return Cell{"unknown", ToneDim}
}

func vulnCell(v *swarm.Service) Cell {
	s := v.Vuln
	if s == nil {
		return Cell{"not scanned", ToneDim}
	}
	if s.Total() == 0 {
		return Cell{"none", ToneOK}
	}
	var parts []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if n := s.Counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s%d(%d)", sev[:1], n, s.Fixable[sev]))
		}
	}
	tone := ToneNone
	switch {
	case s.Fixable["CRITICAL"] > 0:
		tone = ToneCrit
	case s.Fixable["HIGH"] > 0:
		tone = ToneWarn
	}
	return Cell{strings.Join(parts, " "), tone}
}

// Summary returns the one-line host summaries shown under each swarm name.
func Summary(s *swarm.Snapshot) (line string, disks []string) {
	h := s.Host
	ready := 0
	for _, n := range s.Nodes {
		if n.Status == "Ready" {
			ready++
		}
	}
	line = fmt.Sprintf("manager up %s   load %.2f %.2f %.2f (%d cpu)   mem %s / %s (%.0f%%)   nodes %d/%d ready",
		Dur(h.Uptime), h.Load[0], h.Load[1], h.Load[2], h.CPUs,
		Size(h.MemTotal-h.MemAvail), Size(h.MemTotal), h.MemUsedPercent(), ready, len(s.Nodes))
	for _, d := range h.Disks {
		disks = append(disks, fmt.Sprintf("%s %.0f%% of %s", d.Mount, d.Percent, Size(d.Total)))
	}
	return line, disks
}

type Printer struct {
	W     io.Writer
	Color bool
}

func (p Printer) c(tone, s string) string {
	code := ansi[tone]
	if !p.Color || s == "" || code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p Printer) table(header []string, rows [][]Cell) {
	w := make([]int, len(header))
	for i, h := range header {
		w[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if n := utf8.RuneCountInString(c.Text); n > w[i] {
				w[i] = n
			}
		}
	}
	line := func(r []Cell) {
		var b strings.Builder
		b.WriteString("  ")
		for i, c := range r {
			pad := strings.Repeat(" ", w[i]-utf8.RuneCountInString(c.Text))
			if i < len(r)-1 {
				b.WriteString(p.c(c.Tone, c.Text) + pad + "  ")
			} else {
				b.WriteString(p.c(c.Tone, c.Text))
			}
		}
		fmt.Fprintln(p.W, b.String())
	}
	hc := make([]Cell, len(header))
	for i, h := range header {
		hc[i] = Cell{h, ToneDim}
	}
	line(hc)
	for _, r := range rows {
		line(r)
	}
}

// Overview prints findings first, then one block per swarm.
func (p Printer) Overview(snaps []*swarm.Snapshot, findings []swarm.Finding) {
	fmt.Fprintf(p.W, "%s  %s\n\n", p.c(ToneBold, "swarmwatch"), time.Now().Format("2006-01-02 15:04"))
	p.Findings(findings)
	for _, s := range snaps {
		p.swarm(s)
	}
}

func (p Printer) Findings(fs []swarm.Finding) {
	if len(fs) == 0 {
		fmt.Fprintln(p.W, p.c(ToneOK, "all clear — nothing needs a reaction"))
		fmt.Fprintln(p.W)
		return
	}
	SortFindings(fs)
	fmt.Fprintf(p.W, "%s (%d)\n", p.c(ToneBold, "NEEDS ATTENTION"), len(fs))
	for _, f := range fs {
		tone, tag := ToneDim, "info"
		switch f.Level {
		case swarm.Crit:
			tone, tag = ToneCrit, "CRIT"
		case swarm.Warn:
			tone, tag = ToneWarn, "warn"
		}
		who := f.Swarm
		if f.Service != "" {
			who += "/" + f.Service
		}
		if f.Exposure != "" {
			who += " [" + f.Exposure + "]"
		}
		fmt.Fprintf(p.W, "  %s  %-34s %s\n", p.c(tone, tag), who, f.Message)
	}
	fmt.Fprintln(p.W)
}

// Where a finding is shown on the page. Internet and internet·SSO are one group: both can be
// reached from outside the house. A finding with no exposure is about the host itself (a full
// disk, a node that is down). LAN and internal stay in the last group.
const (
	AttentionInternet = "on the internet"
	AttentionHost     = "on the host"
	AttentionHome     = "not on the internet"
)

// AttentionOf is the page group for an exposure level. An unknown or empty level is the host
// group, so a finding swarmwatch could not classify is not filed under "not on the internet".
func AttentionOf(level string) string {
	switch level {
	case exposure.Internet, exposure.InternetSSO:
		return AttentionInternet
	case exposure.LAN, exposure.Internal:
		return AttentionHome
	default:
		return AttentionHost
	}
}

// AttentionOrder is the page order: reachable from outside, then the host, then home-only.
func AttentionOrder() []string {
	return []string{AttentionInternet, AttentionHost, AttentionHome}
}

// SortFindings orders findings worst first, internet-exposed services first within a level.
func SortFindings(fs []swarm.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Level != fs[j].Level {
			return fs[i].Level > fs[j].Level
		}
		return exposure.Rank(fs[i].Exposure) > exposure.Rank(fs[j].Exposure)
	})
}

func (p Printer) swarm(s *swarm.Snapshot) {
	fmt.Fprintf(p.W, "%s\n", p.c(ToneBold, s.Name))
	if s.Err != "" {
		fmt.Fprintf(p.W, "  %s\n\n", p.c(ToneCrit, "unreachable: "+s.Err))
		return
	}
	line, disks := Summary(s)
	fmt.Fprintf(p.W, "  %s\n", line)
	if counts := ExposureCounts(s); len(counts) > 0 {
		var parts []string
		for _, c := range counts {
			parts = append(parts, fmt.Sprintf("%d %s", c.Count, c.Level))
		}
		fmt.Fprintf(p.W, "  exposure %s\n", strings.Join(parts, " · "))
	}
	if len(disks) > 0 {
		fmt.Fprintf(p.W, "  disk %s\n", strings.Join(disks, "   "))
	}
	if !s.Unused.Empty() {
		fmt.Fprintf(p.W, "  %s %s\n", p.c(ToneWarn, "cleanup"), s.Unused.Summary())
	}
	fmt.Fprintln(p.W)

	var rows [][]Cell
	for _, r := range Rows(s) {
		r.Image.Text = shorten(r.Image.Text, 48)
		if len(r.Hosts) > 0 {
			r.Exposure.Text += " " + r.Hosts[0]
			if len(r.Hosts) > 1 {
				r.Exposure.Text += fmt.Sprintf(" +%d", len(r.Hosts)-1)
			}
		}
		rows = append(rows, r.Cells())
	}
	p.table(Header, rows)
	fmt.Fprintln(p.W)
}

func shorten(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return "…" + string(r[len(r)-n+1:])
}

// Size formats bytes with binary units.
func Size(b uint64) string {
	const k = 1024.0
	f := float64(b)
	for _, u := range []string{"B", "K", "M", "G", "T"} {
		if f < k || u == "T" {
			if u == "B" || u == "K" {
				return fmt.Sprintf("%.0f%s", f, u)
			}
			return fmt.Sprintf("%.1f%s", f, u)
		}
		f /= k
	}
	return ""
}

// Dur formats an uptime as days or hours.
func Dur(d time.Duration) string {
	days := int(d.Hours()) / 24
	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
