package server

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/vuln"
)

// vulnLink builds the URL of the vulnerability list for one service.
func vulnLink(swarmName, service, sev string, fixableOnly bool) string {
	q := url.Values{"swarm": {swarmName}, "service": {service}}
	if sev != "" {
		q.Set("sev", sev)
	}
	if fixableOnly {
		q.Set("fixable", "1")
	}
	return "/vulns?" + q.Encode()
}

// findService returns the service and its image's scan result from the latest snapshot.
func (s *Server) findService(swarmName, service string) (*swarm.Service, *vuln.Summary) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sn := range s.snaps {
		if sn.Name != swarmName {
			continue
		}
		for _, v := range sn.Services {
			if v.Name == service {
				return v, v.Vuln
			}
		}
	}
	return nil, nil
}

type vulnRow struct {
	vuln.Item
	Link       string
	SevTone    string
	HasFix     bool
	FixedShort string
}

type vulnView struct {
	Swarm, Service, Image string
	ScannedAt             time.Time
	Counts                []sevCount
	Rows                  []vulnRow
	Shown, Total          int
	Sev                   string
	FixableOnly           bool
	AllLink, FixLink      string
}

type sevCount struct {
	Sev          string
	Tone         string
	Count, Fixed int
	Link         string
}

func sevTone(sev string) string {
	switch sev {
	case "CRITICAL":
		return "crit"
	case "HIGH":
		return "warn"
	}
	return "dim"
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	svc, sum := s.findService(q.Get("swarm"), q.Get("service"))
	if svc == nil {
		http.NotFound(w, r)
		return
	}
	v := vulnView{
		Swarm: q.Get("swarm"), Service: svc.Name, Image: svc.Image,
		Sev: strings.ToUpper(q.Get("sev")), FixableOnly: q.Get("fixable") == "1",
	}
	v.AllLink = vulnLink(v.Swarm, v.Service, "", false)
	v.FixLink = vulnLink(v.Swarm, v.Service, v.Sev, true)
	if sum != nil {
		v.ScannedAt, v.Total = sum.ScannedAt, sum.Total()
		for _, sev := range vuln.Severities {
			if sum.Counts[sev] > 0 {
				v.Counts = append(v.Counts, sevCount{sev, sevTone(sev), sum.Counts[sev], sum.Fixable[sev],
					vulnLink(v.Swarm, v.Service, sev, v.FixableOnly)})
			}
		}
		for _, it := range sum.Items {
			if v.Sev != "" && it.Severity != v.Sev {
				continue
			}
			if v.FixableOnly && it.Fixed == "" {
				continue
			}
			v.Rows = append(v.Rows, vulnRow{Item: it, Link: it.Link(), SevTone: sevTone(it.Severity), HasFix: it.Fixed != ""})
		}
		v.Shown = len(v.Rows)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := vulnPage.Execute(w, v); err != nil {
		log.Printf("render vulns: %v", err)
	}
}

var vulnPage = template.Must(template.New("vulns").Funcs(template.FuncMap{
	"ago": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return time.Since(t).Round(time.Minute).String() + " ago"
	},
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Service}} · vulnerabilities</title>
<style>
:root{--bg:#0f1115;--fg:#d7dae0;--dim:#7d8590;--line:#232830;--ok:#3fb950;--warn:#d29922;--crit:#f85149}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
h1{font-size:18px;margin:8px 0 4px}
.meta,.dim{color:var(--dim)}.crit{color:var(--crit)}.warn{color:var(--warn)}.ok{color:var(--ok)}
a{color:inherit;text-decoration:underline dotted;text-underline-offset:3px}a:hover{text-decoration:underline}
.pills{margin:14px 0;display:flex;gap:10px;flex-wrap:wrap}
.pill{border:1px solid var(--line);border-radius:6px;padding:3px 10px}
.pill.on{border-color:var(--fg)}
.wrap{overflow-x:auto}
table{border-collapse:collapse;min-width:100%}
th{color:var(--dim);font-weight:400;text-align:left;border-bottom:1px solid var(--line)}
td,th{padding:3px 14px 3px 0;vertical-align:top}
td.title{white-space:normal;min-width:24em;max-width:60em}
td.nw{white-space:nowrap}
tr:hover td{background:#161a21}
</style></head><body>
<a href="/">← overview</a>
<h1>{{.Swarm}} / {{.Service}}</h1>
<div class="meta">{{.Image}}{{if not .ScannedAt.IsZero}} · scanned {{ago .ScannedAt}}{{end}}</div>
{{if not .Total}}<p class="dim">{{if .ScannedAt.IsZero}}Not scanned yet.{{else}}<span class="ok">No known vulnerabilities.</span>{{end}}</p>{{else}}
<div class="pills">
 <a class="pill{{if not .Sev}} on{{end}}" href="{{.AllLink}}">all ({{.Total}})</a>
 {{range .Counts}}<a class="pill {{.Tone}}{{if eq .Sev $.Sev}} on{{end}}" href="{{.Link}}">{{.Sev}} {{.Count}} ({{.Fixed}} fixable)</a>{{end}}
 {{if .FixableOnly}}<a class="pill on" href="{{.AllLink}}">fixable only ✕</a>{{else}}<a class="pill" href="{{.FixLink}}">fixable only</a>{{end}}
</div>
<div class="meta">showing {{.Shown}} of {{.Total}} — a fix means the image maintainer must rebuild with a newer package; updating the image tag/digest is the usual remedy.</div>
<div class="wrap"><table>
<tr><th>SEVERITY</th><th>ID</th><th>PACKAGE</th><th>INSTALLED</th><th>FIXED IN</th><th>WHAT</th></tr>
{{range .Rows}}<tr>
<td class="nw {{.SevTone}}">{{.Severity}}</td>
<td class="nw">{{if .Link}}<a href="{{.Link}}" target="_blank" rel="noopener noreferrer">{{.ID}}</a>{{else}}{{.ID}}{{end}}</td>
<td class="nw">{{.Package}}</td><td class="nw dim">{{.Installed}}</td>
<td class="nw {{if .HasFix}}ok{{else}}dim{{end}}">{{if .HasFix}}{{.Fixed}}{{else}}no fix yet{{end}}</td>
<td class="title">{{.Title}}</td>
</tr>{{end}}
</table></div>{{end}}
</body></html>`))
