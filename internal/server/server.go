// Package server runs swarmwatch as a long-lived service: it refreshes snapshots,
// scans images on a schedule and serves a web overview plus a JSON API.
package server

import (
	"context"
	"encoding/json"
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
	updated  time.Time
	peerMu   sync.Mutex
	peers    map[string][]swarm.Route // last good routes per peer URL
	scan     scanStatus

	refreshMu sync.Mutex // one refresh at a time (loop and clean both trigger one)
	cleanMu   sync.Mutex
	cleaned   cleanNote
}

func New(cfg *config.Config, cache *vuln.Cache) *Server {
	return &Server{cfg: cfg, cache: cache, checker: watch.NewChecker(cfg.Serve.RegistryTTL)}
}

// Run blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.refresh(ctx)
	go s.loop(ctx, s.cfg.Serve.Refresh, s.cfg.Serve.Refresh, s.refresh)
	// first scan check shortly after start, then every 10 minutes
	go s.loop(ctx, 20*time.Second, 10*time.Minute, s.scanIfStale)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/overview", s.handleOverview)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/exposure", s.handleExposure)
	mux.HandleFunc("/clean", s.handleClean)
	mux.HandleFunc("/vulns", s.handleVulns)
	mux.HandleFunc("/api/vulns", s.handleVulnsJSON)
	mux.HandleFunc("/healthz", s.handleHealth)
	srv := &http.Server{Addr: s.cfg.Serve.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	log.Printf("listening on %s", s.cfg.Serve.Listen)
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
	s.mu.Lock()
	s.snaps, s.findings, s.updated = snaps, findings, time.Now()
	s.mu.Unlock()
}

func (s *Server) scanIfStale(ctx context.Context) {
	s.mu.RLock()
	snaps, running := s.snaps, s.scan.Running
	s.mu.RUnlock()
	if running {
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
	ok := !s.updated.IsZero() && time.Since(s.updated) < 5*s.cfg.Serve.Refresh
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "stale", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, map[string]any{"updated": s.updated, "scan": s.scan, "swarms": s.snaps})
}

type findingJSON struct {
	Level   string `json:"level"`
	Swarm   string `json:"swarm"`
	Service string `json:"service,omitempty"`
	Message string `json:"message"`
}

func (s *Server) handleFindings(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]findingJSON, 0, len(s.findings))
	worst := swarm.Info
	for _, f := range s.findings {
		out = append(out, findingJSON{f.Level.String(), f.Swarm, f.Service, f.Message})
		if f.Level > worst {
			worst = f.Level
		}
	}
	status := "ok"
	if len(out) > 0 {
		status = worst.String()
	}
	writeJSON(w, map[string]any{"status": status, "updated": s.updated, "findings": out})
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
{{if $.CanClean}}<form method="post" action="/clean" onsubmit="return confirm('Remove everything listed on {{.Name}}? Items that are in use by then are skipped.')">
<input type="hidden" name="swarm" value="{{.Name}}">
{{range .Unused.Images}}<input type="hidden" name="image" value="{{.ID}}">{{end}}{{range .Unused.Containers}}<input type="hidden" name="container" value="{{.ID}}">{{end}}
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
