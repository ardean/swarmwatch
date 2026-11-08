package exposure

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ardean/swarmwatch/internal/swarm"
)

func TestAllPrivate(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want bool
	}{
		{[]string{"192.168.1.0/24", "192.168.2.0/24"}, true},
		{[]string{"10.0.0.0/8", "127.0.0.1"}, true},
		{[]string{"192.168.1.0/24", "8.8.8.0/24"}, false},
		{[]string{"0.0.0.0/0"}, false},
		{nil, false},
		{[]string{"nonsense"}, false},
	} {
		if got := allPrivate(c.in); got != c.want {
			t.Errorf("allPrivate(%v) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestHostsFromRule(t *testing.T) {
	got := hostsFromRule("Host(`a.example`, `b.example`) && PathPrefix(`/x`) || HostRegexp(`{x:.+}`)")
	if !reflect.DeepEqual(got, []string{"a.example", "b.example"}) {
		t.Errorf("hosts = %v", got)
	}
}

const sampleFile = `
http:
  middlewares:
    https-redirect:
      redirectScheme: {scheme: https}
    old-host:
      redirectRegex: {regex: "^https?://old.example(.*)", replacement: "https://jelly.example${1}"}
    lan-only:
      ipAllowList:
        sourceRange: ["192.168.1.0/24"]
    sso:
      forwardAuth: {address: "http://auth"}
  routers:
    jelly-http:
      rule: Host(` + "`jelly.example`" + `)
      middlewares: ["https-redirect@file"]
      service: jelly
    jelly-old:
      rule: Host(` + "`old.example`" + `)
      middlewares: ["old-host@file"]
      service: jelly
    jelly-https:
      rule: Host(` + "`jelly.example`" + `)
      service: jelly
    vault:
      rule: Host(` + "`vault.example`" + `)
      middlewares: ["lan-only@file"]
      service: vault
  services:
    jelly: {loadBalancer: {servers: [{url: "http://10.0.0.10:8081"}]}}
    vault: {loadBalancer: {servers: [{url: "http://10.0.0.11"}]}}
`

func TestFileConfigRoutes(t *testing.T) {
	var fc fileConfig
	if err := yaml.Unmarshal([]byte(sampleFile), &fc); err != nil {
		t.Fatal(err)
	}
	routes := fc.routes("m", fc.middlewares())
	by := map[string]swarm.Route{}
	for _, r := range routes {
		by[r.Name] = r
	}
	if _, ok := by["jelly-http"]; ok {
		t.Error("redirect-only router must be skipped")
	}
	if _, ok := by["jelly-old"]; ok {
		t.Error("redirectRegex router must be skipped")
	}
	if r := by["jelly-https"]; r.LANOnly || r.BackendHost != "10.0.0.10" || r.BackendPort != 8081 {
		t.Errorf("jelly-https = %+v", r)
	}
	if r := by["vault"]; !r.LANOnly || r.BackendPort != 80 {
		t.Errorf("vault = %+v", r)
	}
}

func snap(addrs ...string) *swarm.Snapshot {
	return &swarm.Snapshot{Name: "s", Host: swarm.HostInfo{Addrs: addrs}}
}

func TestClassify(t *testing.T) {
	defs := map[string]mw{"lan-only": {lanOnly: true}, "sso": {auth: true}, "redir": {redirect: true}}
	s := snap("10.0.0.11")
	label := func(rule, mws string) map[string]string {
		l := map[string]string{"traefik.enable": "true", "traefik.http.routers.r.rule": rule}
		if mws != "" {
			l["traefik.http.routers.r.middlewares"] = mws
		}
		return l
	}
	routes := []swarm.Route{
		{Swarm: "other", Name: "bw", Hosts: []string{"bw.example"}, BackendHost: "10.0.0.11", BackendPort: 8080},
		{Swarm: "other", Name: "adm", Hosts: []string{"adm.example"}, LANOnly: true, BackendHost: "10.0.0.11", BackendPort: 9000},
	}
	for _, c := range []struct {
		name  string
		svc   *swarm.Service
		level string
		hosts []string
	}{
		{"public label route", &swarm.Service{Name: "a_a", Stack: "a", Image: "x", Labels: label("Host(`a.example`)", "")}, Internet, []string{"a.example"}},
		{"sso gate", &swarm.Service{Name: "a_b", Stack: "a", Image: "x", Labels: label("Host(`b.example`)", "sso@file")}, InternetSSO, []string{"b.example"}},
		{"lan-only route", &swarm.Service{Name: "a_c", Stack: "a", Image: "x", Labels: label("Host(`c.example`)", "lan-only@file")}, LAN, []string{"c.example"}},
		{"redirect only is ignored", &swarm.Service{Name: "a_d", Stack: "a", Image: "x", Labels: label("Host(`d.example`)", "redir@file")}, Internal, nil},
		{"no traefik.enable", &swarm.Service{Name: "a_e", Stack: "a", Image: "x", Labels: map[string]string{"traefik.http.routers.r.rule": "Host(`e.example`)"}}, Internal, nil},
		{"proxied by a peer route", &swarm.Service{Name: "vw", Stack: "-", Image: "x", Ports: []swarm.Port{{Published: 8080}}}, Internet, []string{"bw.example"}},
		{"peer route that is lan-only", &swarm.Service{Name: "adm", Stack: "-", Image: "x", Ports: []swarm.Port{{Published: 9000}}}, LAN, []string{"adm.example"}},
		{"published port, no route", &swarm.Service{Name: "p", Stack: "-", Image: "x", Ports: []swarm.Port{{Published: 5555}}}, LAN, nil},
		{"no port, no route", &swarm.Service{Name: "q", Stack: "-", Image: "x"}, Internal, nil},
		{"traefik gateway", &swarm.Service{Name: "traefik_traefik", Stack: "traefik", Image: "traefik:v3", Ports: []swarm.Port{{Published: 443}}}, Internet, nil},
	} {
		e := classify(s, c.svc, defs, routes)
		if e.Level != c.level || !reflect.DeepEqual(e.Hosts, c.hosts) {
			t.Errorf("%s: got %s %v; want %s %v", c.name, e.Level, e.Hosts, c.level, c.hosts)
		}
	}
	// a route to another host's IP must not match a service here
	if e := classify(snap("10.9.9.9"), &swarm.Service{Name: "vw", Stack: "-", Image: "x", Ports: []swarm.Port{{Published: 8080}}}, defs, routes); e.Level != LAN {
		t.Errorf("foreign backend matched: %+v", e)
	}
}

func TestLabelMiddlewares(t *testing.T) {
	s := &swarm.Snapshot{Services: []*swarm.Service{{Labels: map[string]string{
		"traefik.http.middlewares.home.ipallowlist.sourcerange": "192.168.0.0/16, 10.0.0.0/8",
		"traefik.http.middlewares.gate.forwardauth.address":     "http://auth",
	}}}}
	got := labelMiddlewares(s)
	if !got["home"].lanOnly || !got["gate"].auth {
		t.Errorf("middlewares = %+v", got)
	}
}
