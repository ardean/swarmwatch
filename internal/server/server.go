// Package server runs swarmwatch as a long-lived service: it refreshes snapshots,
// scans images on a schedule and serves a web overview plus a JSON API.
package server

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/cron"
	"github.com/ardean/swarmwatch/internal/report"
	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/update"
	"github.com/ardean/swarmwatch/internal/version"
	"github.com/ardean/swarmwatch/internal/vuln"
	"github.com/ardean/swarmwatch/internal/watch"
)

type scanStatus struct {
	Running   bool      `json:"running"`
	Current   string    `json:"current,omitempty"`
	Done      int       `json:"done"`
	Total     int       `json:"total"`
	LastEnd   time.Time `json:"last_end,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	Note      string    `json:"note,omitempty"` // a manual request that had nothing to scan
}

type Server struct {
	cfg     *config.Config
	cache   *vuln.Cache
	checker *watch.Checker

	mu       sync.RWMutex
	snaps    []*swarm.Snapshot
	findings []swarm.Finding
	seen     map[string]time.Time // first-seen time per finding ID, matching findings
	updated  time.Time
	peerMu   sync.Mutex
	peers    map[string][]swarm.Route // last good routes per peer URL
	scan     scanStatus

	refreshMu sync.Mutex // one refresh at a time (loop and clean both trigger one)
	cleanMu   sync.Mutex
	cleaned   cleanNote

	updateMu sync.Mutex   // one update run at a time
	upd      updateStatus // guarded by mu
	updates  *updateLog
	selfOnce sync.Once
	self     string

	firstSeen  *firstSeen
	scanWindow *config.Window
	scanMu     sync.Mutex // one vulnerability scan at a time, scheduled or from the button
	// imageChecking is true while a manual registry check is in progress, including the roll
	// the API check starts afterwards. The page button never rolls. Guarded by mu.
	imageChecking bool
	// imageCheckFn replaces the registry check in tests. Nil resets the cache and refreshes.
	imageCheckFn func()
	// rollFn replaces the docker roll in tests. Nil rolls with execUpdate.
	// manual is true when the API image check started it.
	rollFn func(targets []update.Target, manual bool)
	// scanFn replaces the Trivy run in tests. Nil scans with Trivy and then refreshes.
	scanFn  func(ctx context.Context, snaps []*swarm.Snapshot, force bool)
	authLog authLog
}

func New(cfg *config.Config, cache *vuln.Cache) *Server {
	window, _ := config.ParseWindow(cfg.Scan.Window) // validated by config.Load
	return &Server{cfg: cfg, cache: cache, checker: watch.NewChecker(cfg.Serve.RegistryTTL),
		firstSeen: loadFirstSeen(config.CacheDir()), updates: loadUpdateLog(config.CacheDir()), scanWindow: window}
}

// Run blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if s.updateEnabled() {
		s.selfService() // look it up now, not in the middle of rendering a page
	}
	s.refresh(ctx)
	go s.loop(ctx, s.cfg.Serve.Refresh, s.cfg.Serve.Refresh, s.refresh)
	// first scan check shortly after start, then every 10 minutes
	go s.loop(ctx, 20*time.Second, 10*time.Minute, s.scanIfStale)
	if sched := s.cfg.Update.Schedule; sched != "" {
		c, _ := cron.Parse(sched) // validated by config.Load
		go s.updateLoop(ctx, c, "")
		log.Printf("automatic updates on schedule %q (%s), %s between services", sched, time.Local, s.cfg.Update.Wait)
	}
	for _, ln := range s.cfg.Update.Lanes {
		c, _ := cron.Parse(ln.Cron) // validated by config.Load
		go s.updateLoop(ctx, c, ln.Name)
		log.Printf("updates labeled swarmwatch.update=%s on schedule %q (%s)", ln.Name, ln.Cron, time.Local)
	}

	if sched := s.cfg.Clean.Schedule; sched != "" {
		c, _ := cron.Parse(sched) // validated by config.Load
		go s.cleanLoop(ctx, c)
		log.Printf("clean-up on schedule %q (%s): unused images older than %s, stopped containers older than %s",
			sched, time.Local, s.cfg.Clean.Keep, s.cfg.Clean.KeepContainers)
	}

	srv := &http.Server{Addr: s.cfg.Serve.Listen, Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	log.Printf("swarmwatch %s listening on %s (api token: %s, web pages: %s)", version.Version, s.cfg.Serve.Listen,
		onOff(s.cfg.Serve.Token != "", "required", "none, the API is open"), onOff(!s.cfg.Serve.DisableUI, "on", "off"))
	switch {
	case s.cfg.Serve.Token == "":
		log.Printf("the API has no token: keep the port on a trusted network or set SWARMWATCH_TOKEN_FILE (see SECURITY.md)")
	case !s.cfg.Serve.DisableUI:
		log.Printf("the token covers /api/ only, the web pages stay open: set SWARMWATCH_DISABLE_UI=1 if the API is all you need")
	}
	if s.scanWindow != nil {
		log.Printf("vulnerability scans start only between %02d:%02d and %02d:%02d (%s)",
			s.scanWindow.From/60, s.scanWindow.From%60, s.scanWindow.To/60, s.scanWindow.To%60, time.Local)
	}
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) loop(ctx context.Context, first, every time.Duration, fn func(context.Context)) {
	select {
	case <-time.After(first):
		fn(ctx)
	case <-ctx.Done():
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			fn(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) refresh(ctx context.Context) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	snaps := watch.Gather(ctx, s.cfg, s.cache, s.checker, s.fetchPeers(ctx))
	findings := watch.Findings(s.cfg, snaps)
	findings = append(findings, s.updateFindings(snaps)...)
	report.SortFindings(findings)
	unreadable := map[string]bool{}
	for _, sn := range snaps {
		if sn.Err != "" {
			unreadable[sn.Name] = true
		}
	}
	now := time.Now()
	seen := s.firstSeen.update(findings, unreadable, now)
	s.mu.Lock()
	s.snaps, s.findings, s.seen, s.updated = snaps, findings, seen, now
	s.mu.Unlock()
}

func (s *Server) scanIfStale(ctx context.Context) {
	if !s.scanWindow.Contains(time.Now()) {
		return
	}
	if !s.scanMu.TryLock() {
		return // a scan, possibly a manual one, is already running
	}
	defer s.scanMu.Unlock()
	s.mu.RLock()
	snaps := append([]*swarm.Snapshot(nil), s.snaps...)
	s.mu.RUnlock()
	n := s.armScan(snaps, false)
	if n == 0 {
		return
	}
	log.Printf("scanning %d stale image(s)", n)
	s.executeScan(ctx, snaps, false)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	stale := s.stale()
	s.mu.RUnlock()
	if stale {
		http.Error(w, "stale", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, map[string]any{"updated": s.updated, "scan": s.scan, "swarms": s.snaps})
}

type swarmView struct {
	Name, Summary, Err string
	Disks              []string
	Rows               []rowView
	Exposure           []exposureChip
	Unused             *swarm.Unused
	UnusedSummary      string
}

// exposureChip is one "N internet" style count that filters the table when clicked.
type exposureChip struct {
	Label, Tone, Link string
	Count             int
	On                bool
}

// rowView is a table row plus the link to its vulnerability list.
type rowView struct {
	report.Row
	VulnLink  string
	CanUpdate bool   // the update button is shown
	Auto      string // "auto", or "no, <reason>", when a schedule is set; otherwise empty
	AutoTone  string
}

type indexView struct {
	Filter        string // exposure level the table is filtered to ("" = all)
	Updated       time.Time
	Status        string // ok | warn | crit
	Findings      []findingView
	Groups        []attentionGroup // Findings split by who can reach them; empty groups are left out
	Swarms        []swarmView
	Scan          scanStatus
	ScanWhen      string // when automatic scans may start: "any time" or "02:00–05:00"
	Header        []string
	CanClean      bool
	Cleaned       cleanNote
	Updates       updateView
	ImageChecking bool // the check-images button cannot be pressed
}

// attentionGroup is one block of "Needs attention": on the internet, on the host, or not on the internet.
type attentionGroup struct {
	Label, Tone string
	Items       []findingView
}

type findingView struct{ Tone, Tag, Who, Message, Link, Exposure, ExpTone string }

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.mu.RLock()
	v := indexView{Updated: s.updated, Status: "ok", Scan: s.scan, ScanWhen: s.scanWhen(), Header: report.Header, Filter: r.URL.Query().Get("exposure"),
		CanClean: s.cfg.Serve.AllowClean, Cleaned: s.cleaned, Updates: s.updateView(),
		ImageChecking: s.imageChecking}
	byPlace := map[string][]findingView{}
	for _, f := range s.findings {
		fv := findingView{Tone: "dim", Tag: "info", Who: f.Swarm, Message: f.Message}
		if f.Service != "" {
			fv.Who += "/" + f.Service
		}
		if f.VulnSev != "" {
			fv.Link = vulnLink(f.Swarm, f.Service, f.VulnSev, true)
		}
		if f.Exposure != "" {
			fv.Exposure, fv.ExpTone = f.Exposure, report.ExposureTone(f.Exposure)
		}
		switch f.Level {
		case swarm.Crit:
			fv.Tone, fv.Tag, v.Status = "crit", "CRIT", "crit"
		case swarm.Warn:
			fv.Tone, fv.Tag = "warn", "warn"
			if v.Status != "crit" {
				v.Status = "warn"
			}
		}
		v.Findings = append(v.Findings, fv)
		place := report.AttentionOf(f.Exposure)
		byPlace[place] = append(byPlace[place], fv)
	}
	for _, place := range report.AttentionOrder() {
		items := byPlace[place]
		if len(items) == 0 {
			continue
		}
		v.Groups = append(v.Groups, attentionGroup{Label: place, Tone: attentionTone(place, items), Items: items})
	}
	for _, sn := range s.snaps {
		sv := swarmView{Name: sn.Name, Err: sn.Err}
		if sn.Err == "" {
			sv.Summary, sv.Disks = report.Summary(sn)
			if !sn.Unused.Empty() {
				sv.Unused, sv.UnusedSummary = sn.Unused, sn.Unused.Summary()
			}
			for _, c := range report.ExposureCounts(sn) {
				link := "/?exposure=" + c.Level
				if v.Filter == c.Level {
					link = "/" // clicking the active filter clears it
				}
				sv.Exposure = append(sv.Exposure, exposureChip{Label: report.ExposureLabel(&swarm.Exposure{Level: c.Level}), Tone: report.ExposureTone(c.Level), Link: link, Count: c.Count, On: v.Filter == c.Level})
			}
			for _, r := range report.Rows(sn) {
				if v.Filter != "" && r.Level != v.Filter {
					continue
				}
				rv := rowView{Row: r}
				if v.Updates.Schedule != "" || len(v.Updates.Lanes) > 0 {
					rv.Auto, rv.AutoTone = "auto", "ok"
					if svc := serviceByName(sn, r.Service); svc != nil {
						rv.Auto, rv.AutoTone = s.schedulePhrase(svc, s.selfService())
					}
				}
				if v.Updates.CanClick {
					rv.CanUpdate = s.canUpdate(sn, r.Service)
				}
				if r.Vulns.Text != "" && r.Vulns.Text != "not scanned" && r.Vulns.Text != "none" {
					rv.VulnLink = vulnLink(sn.Name, r.Service, "", false)
				}
				sv.Rows = append(sv.Rows, rv)
			}
		}
		v.Swarms = append(v.Swarms, sv)
	}
	if v.Updates.CanClick {
		for _, sn := range s.snaps {
			if sn == nil || sn.Err != "" {
				continue
			}
			v.Updates.Pending += len(update.Plan(sn, s.selfService()))
		}
	}
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, v); err != nil {
		log.Printf("render: %v", err)
	}
}

var page = template.Must(template.New("index").Funcs(template.FuncMap{
	"size": report.Size,
	"age": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return report.Dur(time.Since(t))
	},
	"short": func(id string) string {
		id = strings.TrimPrefix(id, "sha256:")
		if len(id) > 12 {
			id = id[:12]
		}
		return id
	},
	"ago": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		d := time.Since(t).Round(time.Second)
		if d < time.Minute {
			return d.String() + " ago"
		}
		return d.Round(time.Minute).String() + " ago"
	},
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>swarmwatch · {{.Status}}</title>
<style>
:root{--bg:#0f1115;--fg:#d7dae0;--dim:#7d8590;--line:#232830;--ok:#3fb950;--warn:#d29922;--crit:#f85149}
*{box-sizing:border-box}
body{margin:0;padding:6px 10px 4px;background:var(--bg);color:var(--fg);font:12px/1.25 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
h1{font-size:14px;line-height:1.2;margin:0 0 1px;display:flex;align-items:center;gap:8px}
.dot{width:10px;height:10px;border-radius:50%;background:var(--ok);flex:none}
.dot.warn{background:var(--warn)}.dot.crit{background:var(--crit)}
h2{font-size:13px;line-height:1.2;margin:3px 0 1px}
.meta,.dim{color:var(--dim)}
.crit{color:var(--crit)}.warn{color:var(--warn)}.ok{color:var(--ok)}.bold{font-weight:700}
ul{list-style:none;padding:0;margin:2px 0 4px}
li{padding:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}li b{display:inline-block;min-width:3.2em}
.tag{border:1px solid currentColor;border-radius:4px;padding:0 4px;font-size:11px}
.chips{margin:1px 0;color:var(--dim)}
.group{margin:8px 0 0}
.chip{border:1px solid var(--line);border-radius:6px;padding:0 6px;margin-right:4px;text-decoration:none}
.chip.on{border-color:var(--fg)}
a.host{color:var(--dim)}
details{margin:0}summary{cursor:pointer}
details.clean summary,details.attn summary{color:var(--warn)}
button{background:none;color:var(--crit);border:1px solid var(--crit);border-radius:6px;padding:1px 8px;font:inherit;cursor:pointer;margin:4px 0}
button:hover{background:var(--crit);color:var(--bg)}
button.upd{color:var(--warn);border-color:var(--warn);margin:0 0 0 6px;padding:0 6px;font-size:11px;line-height:1.1}button.upd:hover{background:var(--warn)}
button.upd:disabled{color:var(--dim);border-color:var(--line);cursor:not-allowed}button.upd:disabled:hover{background:none;color:var(--dim)}
button.scan{color:var(--fg);border-color:var(--dim);margin:0 0 0 6px;padding:0 6px;font-size:11px;line-height:1.1}button.scan:hover{background:var(--fg);color:var(--bg)}
button.scan:disabled{color:var(--dim);border-color:var(--line);cursor:not-allowed}button.scan:disabled:hover{background:none;color:var(--dim)}
form.inline{display:inline}
.wrap{overflow:hidden}
.wrap table{border-collapse:collapse;margin-top:2px;width:100%;table-layout:fixed}
.wrap th{color:var(--dim);font-weight:400;text-align:left;border-bottom:1px solid var(--line)}
.wrap td,.wrap th{padding:0 8px 0 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:0}
.wrap tr:hover td{background:#161a21}
table{border-collapse:collapse}
td,th{padding:1px 8px 1px 0;white-space:nowrap}
a{color:inherit;text-decoration:underline dotted;text-underline-offset:2px}a:hover{text-decoration:underline}
</style></head><body>
<h1><span class="dot {{.Status}}"></span>swarmwatch</h1>
{{if .Cleaned.Text}}<div class="{{if .Cleaned.Bad}}warn{{else}}ok{{end}}">{{.Cleaned.Text}} ({{ago .Cleaned.Time}})</div>{{end}}
<div class="meta">updated {{ago .Updated}}{{if .Scan.Running}} · scanning {{.Scan.Done}}/{{.Scan.Total}}{{if .Scan.Current}} ({{.Scan.Current}}){{end}}{{else}}{{if not .Scan.LastEnd.IsZero}} · last scan {{ago .Scan.LastEnd}}{{end}}{{end}} · autoscan on ({{.ScanWhen}}) <form class="inline" method="post" action="/scan"><button class="scan" type="submit" title="{{if .Scan.Running}}a scan is already running{{else}}rescan every image now{{end}}"{{if .Scan.Running}} disabled{{end}}>scan now</button></form> <form class="inline" method="post" action="/image-check"><button class="scan" type="submit" title="{{if .ImageChecking}}an image check is already running{{else}}ask the registries whether tags have a new image{{end}}"{{if .ImageChecking}} disabled{{end}}>check images</button></form>{{if .Scan.Note}} · {{.Scan.Note}}{{end}}{{if .Scan.LastError}} · <span class="warn">scan error: {{.Scan.LastError}}</span>{{end}}</div>

{{if .Updates.Status.Running}}<div class="warn">{{.Updates.Status.Text}} …</div>{{end}}
{{if .Updates.Enabled}}<div class="meta">updates: {{if .Updates.Schedule}}{{if .Updates.ScheduleText}}automatic {{.Updates.ScheduleText}} (<code>{{.Updates.Schedule}}</code>){{else}}automatic on <code>{{.Updates.Schedule}}</code>{{end}}{{end}}{{if and .Updates.Schedule .Updates.CanClick}}, {{end}}{{if .Updates.CanClick}}button enabled{{if .Updates.Pending}} <form class="inline" method="post" action="/update-all"><button class="upd" type="submit" title="roll every outdated service the row buttons would roll, one at a time. A named schedule and swarmwatch.update=false stay put."{{if .Updates.Status.Running}} disabled{{end}}>update all ({{.Updates.Pending}})</button></form>{{end}}{{end}}{{if or .Updates.Schedule .Updates.Lanes}} · <span class="ok">auto</span> on a service means the fast schedule updates it, <span class="dim">no</span> means it is left out · check images asks the registries now and does not roll{{end}}{{if .Updates.Paused}} · <span class="warn">interval paused</span>{{end}}</div>
{{range .Updates.Lanes}}<div class="meta">Services marked <span class="ok">{{.Name}}</span> roll {{if .Text}}{{.Text}}{{else}}on <code>{{.Cron}}</code>{{end}}{{if .Next}}, next at {{.Next}}{{end}}. Update all leaves those until that run.</div>{{end}}
{{if .Updates.Recent}}<details class="clean"><summary>recent updates ({{len .Updates.Recent}})</summary><table>
{{range .Updates.Recent}}<tr><td class="dim">{{.When}}</td><td>{{.What}}</td><td class="{{if .OK}}ok{{else}}crit{{end}}">{{.Message}}</td></tr>{{end}}
</table></details>{{end}}{{end}}

{{if .Findings}}
<details class="attn"><summary>Needs attention ({{len .Findings}}){{range .Groups}} · <span class="{{.Tone}}">{{len .Items}} {{.Label}}</span>{{end}}</summary>
{{range .Groups}}<div class="group {{.Tone}}">{{.Label}}</div>
<ul>{{range .Items}}<li><b class="{{.Tone}}">{{.Tag}}</b> {{.Who}}{{if .Exposure}} <span class="tag {{.ExpTone}}">{{.Exposure}}</span>{{end}} — {{if .Link}}<a href="{{.Link}}">{{.Message}}</a>{{else}}{{.Message}}{{end}}</li>{{end}}</ul>
{{end}}</details>
{{else}}<p class="ok">All clear — nothing needs a reaction.</p>{{end}}

{{$h := .Header}}
{{range .Swarms}}
<h2>{{.Name}}</h2>{{$sw := .Name}}
{{if .Err}}<div class="crit">unreachable: {{.Err}}</div>{{else}}
<div class="meta">{{.Summary}}</div>
<div class="chips">exposure {{range .Exposure}}<a class="chip {{.Tone}}{{if .On}} on{{end}}" href="{{.Link}}">{{.Count}} {{.Label}}</a>{{end}}</div>
<div class="meta">disk {{range .Disks}}{{.}} &nbsp; {{end}}</div>
{{if .Unused}}<details class="clean"><summary>cleanup: {{.UnusedSummary}}</summary>
<table>
{{range .Unused.Images}}<tr><td class="dim">image</td><td>{{range .Tags}}{{.}} {{else}}&lt;dangling&gt;{{end}}</td><td>{{size .Size}}</td><td class="dim">{{short .ID}}{{if age .Created}} · {{age .Created}} old{{end}}</td></tr>{{end}}
{{range .Unused.Containers}}<tr><td class="dim">container</td><td>{{.Name}}</td><td>{{.Image}}</td><td class="dim">{{.Status}}</td></tr>{{end}}
</table>
{{if $.CanClean}}<form method="post" action="/clean">
<input type="hidden" name="swarm" value="{{.Name}}">
{{range .Unused.Images}}<input type="hidden" name="image" value="{{.ID}}">{{end}}{{range .Unused.Containers}}<input type="hidden" name="container" value="{{.ID}}">{{end}}
<label class="dim"><input type="checkbox" name="confirm" value="1" required> remove everything listed on {{.Name}} (items in use by then are skipped)</label><br>
<button type="submit">Remove all listed</button>
</form>{{else}}<div class="dim">read-only: redeploy with <code>--allow-clean</code> to enable the remove button</div>{{end}}
</details>{{end}}
<div class="wrap"><table>
<colgroup><col style="width:8%"><col style="width:12%"><col style="width:14%"><col style="width:6%"><col style="width:5%"><col style="width:5%"><col style="width:8%"><col style="width:15%"><col style="width:13%"><col style="width:14%"></colgroup>
<tr>{{range $h}}<th>{{.}}</th>{{end}}</tr>
{{range .Rows}}<tr>
<td class="{{.Stack.Tone}}" title="{{.Stack.Text}}">{{.Stack.Text}}</td><td title="{{.Name.Text}}">{{.Name.Text}}</td>
<td class="{{.Exposure.Tone}}" title="{{.Exposure.Text}}{{range .Hosts}} {{.}}{{end}}">{{.Exposure.Text}}{{range .Hosts}} <a class="host" href="https://{{.}}" target="_blank" rel="noopener noreferrer">{{.}}</a>{{end}}</td>
<td class="dim" title="published on the host{{range .Ports}} {{.}}{{end}}">{{range .Ports}}{{.}} {{end}}</td>
<td class="{{.Repl.Tone}}">{{.Repl.Text}}</td><td>{{.CPU.Text}}</td><td>{{.Mem.Text}}</td>
<td class="dim" title="{{.Image.Text}}">{{.Image.Text}}</td>
<td class="{{.Update.Tone}}" title="{{.Update.Text}}{{if .Auto}} {{.Auto}}{{end}}">{{.Update.Text}}{{if .Auto}} <span class="{{.AutoTone}}" title="{{if eq .Auto "auto"}}the schedule updates this service when its image changes{{else}}{{.Auto}}{{end}}">{{.Auto}}</span>{{end}}{{if .CanUpdate}} <form class="inline" method="post" action="/update"><input type="hidden" name="swarm" value="{{$sw}}"><input type="hidden" name="service" value="{{.Service}}"><button class="upd" type="submit" title="roll {{.Service}} to the newest {{.Image.Text}}">update</button></form>{{end}}</td><td class="{{.Vulns.Tone}}" title="{{.Vulns.Text}}">{{if .VulnLink}}<a href="{{.VulnLink}}">{{.Vulns.Text}}</a>{{else}}{{.Vulns.Text}}{{end}}</td>
</tr>{{end}}
</table></div>
{{end}}
{{end}}
</body></html>`))

// attentionTone colours the group count. Home-only findings stay dim even when one of them is
// critical, so a full disk or a public service is what reads as red.
func attentionTone(place string, items []findingView) string {
	if place == report.AttentionHome {
		return "dim"
	}
	tone := "dim"
	for _, it := range items {
		switch it.Tone {
		case "crit":
			return "crit"
		case "warn":
			tone = "warn"
		}
	}
	return tone
}

func serviceByName(sn *swarm.Snapshot, name string) *swarm.Service {
	for _, v := range sn.Services {
		if v.Name == name {
			return v
		}
	}
	return nil
}

// scanWhen is the span in which automatic scans may start.
func (s *Server) scanWhen() string {
	w := s.scanWindow
	if w == nil {
		return "any time"
	}
	return fmt.Sprintf("%02d:%02d–%02d:%02d", w.From/60, w.From%60, w.To/60, w.To%60)
}

func onOff(on bool, yes, no string) string {
	if on {
		return yes
	}
	return no
}
