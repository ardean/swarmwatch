// Package server runs swarmwatch as a long-lived service: it refreshes snapshots,
// scans images on a schedule and serves a web overview plus a JSON API.
package server

import (
	"context"
	"errors"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/report"
	"github.com/ardean/swarmwatch/internal/swarm"
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

	firstSeen  *firstSeen
	scanWindow *config.Window
	authLog    authLog
}

func New(cfg *config.Config, cache *vuln.Cache) *Server {
	window, _ := config.ParseWindow(cfg.Scan.Window) // validated by config.Load
	return &Server{cfg: cfg, cache: cache, checker: watch.NewChecker(cfg.Serve.RegistryTTL),
		firstSeen: loadFirstSeen(config.CacheDir()), scanWindow: window}
}

// Run blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.refresh(ctx)
	go s.loop(ctx, s.cfg.Serve.Refresh, s.cfg.Serve.Refresh, s.refresh)
	// first scan check shortly after start, then every 10 minutes
	go s.loop(ctx, 20*time.Second, 10*time.Minute, s.scanIfStale)

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
	s.mu.RLock()
	snaps, running := s.snaps, s.scan.Running
	s.mu.RUnlock()
	if running || !s.scanWindow.Contains(time.Now()) {
		return
	}
	stale := 0
	for _, sn := range snaps {
		if sn.Err == "" {
			stale += watch.StaleImages(sn, s.cache, s.cfg.Scan.MaxAge)
		}
	}
	if stale == 0 {
		return
	}
	log.Printf("scanning %d stale image(s)", stale)
	s.mu.Lock()
	s.scan = scanStatus{Running: true, Total: stale, LastEnd: s.scan.LastEnd}
	s.mu.Unlock()

	var lastErr string
	watch.ScanStale(ctx, s.cfg, snaps, s.cache, false, func(e watch.Event) {
		s.mu.Lock()
		s.scan.Done++
		s.scan.Current = e.Image
		if e.Err != nil {
			lastErr = e.Image + ": " + e.Err.Error()
			log.Printf("scan %s: %v", e.Image, e.Err)
		}
		s.mu.Unlock()
	})
	s.mu.Lock()
	s.scan = scanStatus{LastEnd: time.Now(), LastError: lastErr}
	s.mu.Unlock()
	s.refresh(ctx) // pick up fresh results immediately
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
	VulnLink string
}

type indexView struct {
	Filter   string // exposure level the table is filtered to ("" = all)
	Updated  time.Time
	Status   string // ok | warn | crit
	Findings []findingView
	Swarms   []swarmView
	Scan     scanStatus
	Header   []string
	CanClean bool
	Cleaned  cleanNote
}

type findingView struct{ Tone, Tag, Who, Message, Link, Exposure, ExpTone string }

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.mu.RLock()
	v := indexView{Updated: s.updated, Status: "ok", Scan: s.scan, Header: report.Header, Filter: r.URL.Query().Get("exposure"),
		CanClean: s.cfg.Serve.AllowClean, Cleaned: s.cleaned}
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
				if r.Vulns.Text != "" && r.Vulns.Text != "not scanned" && r.Vulns.Text != "none" {
					rv.VulnLink = vulnLink(sn.Name, r.Service, "", false)
				}
				sv.Rows = append(sv.Rows, rv)
			}
		}
		v.Swarms = append(v.Swarms, sv)
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
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
h1{font-size:18px;margin:0 0 4px;display:flex;align-items:center;gap:10px}
.dot{width:12px;height:12px;border-radius:50%;background:var(--ok)}
.dot.warn{background:var(--warn)}.dot.crit{background:var(--crit)}
h2{font-size:15px;margin:28px 0 4px}
.meta,.dim{color:var(--dim)}
.crit{color:var(--crit)}.warn{color:var(--warn)}.ok{color:var(--ok)}.bold{font-weight:700}
ul{list-style:none;padding:0;margin:8px 0}
li{padding:2px 0}li b{display:inline-block;min-width:3.5em}
.tag{border:1px solid currentColor;border-radius:4px;padding:0 6px;font-size:12px}
.chips{margin:6px 0 2px;color:var(--dim)}
.chip{border:1px solid var(--line);border-radius:6px;padding:1px 9px;margin-right:6px;text-decoration:none}
.chip.on{border-color:var(--fg)}
a.host{color:var(--dim)}
details.clean{margin:8px 0}summary{cursor:pointer;color:var(--warn)}
button{background:none;color:var(--crit);border:1px solid var(--crit);border-radius:6px;padding:3px 12px;font:inherit;cursor:pointer;margin:8px 0}
button:hover{background:var(--crit);color:var(--bg)}
.wrap{overflow-x:auto}
table{border-collapse:collapse;margin-top:10px;min-width:100%}
th{color:var(--dim);font-weight:400;text-align:left;border-bottom:1px solid var(--line)}
td,th{padding:3px 14px 3px 0;white-space:nowrap}
tr:hover td{background:#161a21}
a{color:inherit;text-decoration:underline dotted;text-underline-offset:3px}a:hover{text-decoration:underline}
</style></head><body>
<h1><span class="dot {{.Status}}"></span>swarmwatch</h1>
{{if .Cleaned.Text}}<div class="{{if .Cleaned.Bad}}warn{{else}}ok{{end}}">{{.Cleaned.Text}} ({{ago .Cleaned.Time}})</div>{{end}}
<div class="meta">updated {{ago .Updated}}{{if .Scan.Running}} · scanning {{.Scan.Done}}/{{.Scan.Total}} ({{.Scan.Current}}){{else if not .Scan.LastEnd.IsZero}} · last scan {{ago .Scan.LastEnd}}{{end}}{{if .Scan.LastError}} · <span class="warn">scan error: {{.Scan.LastError}}</span>{{end}}</div>

{{if .Findings}}
<h2>Needs attention ({{len .Findings}})</h2>
<ul>{{range .Findings}}<li><b class="{{.Tone}}">{{.Tag}}</b> {{.Who}}{{if .Exposure}} <span class="tag {{.ExpTone}}">{{.Exposure}}</span>{{end}} — {{if .Link}}<a href="{{.Link}}">{{.Message}}</a>{{else}}{{.Message}}{{end}}</li>{{end}}</ul>
{{else}}<p class="ok">All clear — nothing needs a reaction.</p>{{end}}

{{$h := .Header}}
{{range .Swarms}}
<h2>{{.Name}}</h2>
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
<tr>{{range $h}}<th>{{.}}</th>{{end}}</tr>
{{range .Rows}}<tr>
<td class="{{.Stack.Tone}}">{{.Stack.Text}}</td><td>{{.Name.Text}}</td>
<td class="{{.Exposure.Tone}}">{{.Exposure.Text}}{{range .Hosts}} <a class="host" href="https://{{.}}" target="_blank" rel="noopener noreferrer">{{.}}</a>{{end}}</td>
<td class="{{.Repl.Tone}}">{{.Repl.Text}}</td><td>{{.CPU.Text}}</td><td>{{.Mem.Text}}</td>
<td class="dim">{{.Image.Text}}</td>
<td class="{{.Update.Tone}}">{{.Update.Text}}</td><td class="{{.Vulns.Tone}}">{{if .VulnLink}}<a href="{{.VulnLink}}">{{.Vulns.Text}}</a>{{else}}{{.Vulns.Text}}{{end}}</td>
</tr>{{end}}
</table></div>
{{end}}
{{end}}
</body></html>`))

func onOff(on bool, yes, no string) string {
	if on {
		return yes
	}
	return no
}
