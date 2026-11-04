package exposure

import (
	"context"
	"net"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ardean/swarmwatch/internal/sshx"
	"github.com/ardean/swarmwatch/internal/swarm"
)

// mw is what a Traefik middleware means for exposure.
type mw struct{ lanOnly, auth, redirect bool }

func (m *mw) or(o mw) {
	m.lanOnly = m.lanOnly || o.lanOnly
	m.auth = m.auth || o.auth
	m.redirect = m.redirect || o.redirect
}

// kindOf interprets one middleware definition (kind lower-cased, e.g. "ipallowlist").
func kindOf(kind string, sourceRange []string) mw {
	switch kind {
	case "ipallowlist", "ipwhitelist":
		return mw{lanOnly: allPrivate(sourceRange)}
	case "forwardauth", "basicauth", "digestauth":
		return mw{auth: true}
	case "redirectscheme":
		return mw{redirect: true}
	}
	return mw{}
}

// allPrivate reports whether every range is inside private (RFC 1918 / loopback) space.
func allPrivate(ranges []string) bool {
	if len(ranges) == 0 {
		return false
	}
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		ip := net.ParseIP(r)
		if ip == nil {
			var err error
			if ip, _, err = net.ParseCIDR(r); err != nil {
				return false
			}
			_, n, _ := net.ParseCIDR(r)
			ip = n.IP // the network address, so 0.0.0.0/0 or 8.0.0.0/5 do not count
		}
		if !ip.IsPrivate() && !ip.IsLoopback() {
			return false
		}
	}
	return true
}

var (
	hostRe = regexp.MustCompile(`Host\(([^)]*)\)`)
	tickRe = regexp.MustCompile("`([^`]+)`")
)

// hostsFromRule extracts the hostnames of a Traefik rule such as Host(`a.example`).
func hostsFromRule(rule string) []string {
	var out []string
	for _, m := range hostRe.FindAllStringSubmatch(rule, -1) {
		for _, t := range tickRe.FindAllStringSubmatch(m[1], -1) {
			out = append(out, t[1])
		}
	}
	return out
}

type router struct {
	rule string
	mws  []string
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// labelRouters reads traefik.http.routers.<name>.{rule,middlewares} labels.
func labelRouters(labels map[string]string) []router {
	byName := map[string]*router{}
	for k, v := range labels {
		rest, ok := strings.CutPrefix(k, "traefik.http.routers.")
		if !ok {
			continue
		}
		name, field, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		r := byName[name]
		if r == nil {
			r = &router{}
			byName[name] = r
		}
		switch field {
		case "rule":
			r.rule = v
		case "middlewares":
			r.mws = splitList(v)
		}
	}
	var out []router
	for _, r := range byName {
		if r.rule != "" {
			out = append(out, *r)
		}
	}
	return out
}

// labelMiddlewares reads traefik.http.middlewares.<name>.<kind>.<option> labels of all services.
func labelMiddlewares(s *swarm.Snapshot) map[string]mw {
	type def struct {
		kind  string
		sr    []string
		other bool
	}
	defs := map[string]map[string]*def{}
	for _, svc := range s.Services {
		for k, v := range svc.Labels {
			rest, ok := strings.CutPrefix(k, "traefik.http.middlewares.")
			if !ok {
				continue
			}
			parts := strings.SplitN(rest, ".", 3)
			if len(parts) < 2 {
				continue
			}
			name, kind := parts[0], strings.ToLower(parts[1])
			if defs[name] == nil {
				defs[name] = map[string]*def{}
			}
			d := defs[name][kind]
			if d == nil {
				d = &def{kind: kind}
				defs[name][kind] = d
			}
			if len(parts) == 3 && strings.ToLower(parts[2]) == "sourcerange" {
				d.sr = splitList(v)
			}
		}
	}
	out := map[string]mw{}
	for name, kinds := range defs {
		var m mw
		for _, d := range kinds {
			m.or(kindOf(d.kind, d.sr))
		}
		out[name] = m
	}
	return out
}

// resolve combines the named middlewares ("name@provider" is looked up as "name").
func resolve(names []string, defs map[string]mw) mw {
	var m mw
	for _, n := range names {
		n, _, _ = strings.Cut(n, "@")
		m.or(defs[n])
	}
	return m
}

// fileConfig is the part of a Traefik file-provider document we need.
type fileConfig struct {
	HTTP struct {
		Routers map[string]struct {
			Rule        string   `yaml:"rule"`
			Middlewares []string `yaml:"middlewares"`
			Service     string   `yaml:"service"`
		} `yaml:"routers"`
		Services map[string]struct {
			LoadBalancer struct {
				Servers []struct {
					URL string `yaml:"url"`
				} `yaml:"servers"`
			} `yaml:"loadBalancer"`
		} `yaml:"services"`
		Middlewares map[string]map[string]any `yaml:"middlewares"`
	} `yaml:"http"`
}

// fileMiddlewares converts file-provider middleware definitions.
func (f fileConfig) middlewares() map[string]mw {
	out := map[string]mw{}
	for name, def := range f.HTTP.Middlewares {
		var m mw
		for kind, opts := range def {
			var sr []string
			if om, ok := opts.(map[string]any); ok {
				for k, v := range om {
					if strings.EqualFold(k, "sourceRange") {
						if list, ok := v.([]any); ok {
							for _, e := range list {
								if s, ok := e.(string); ok {
									sr = append(sr, s)
								}
							}
						}
					}
				}
			}
			m.or(kindOf(strings.ToLower(kind), sr))
		}
		out[name] = m
	}
	return out
}

// routes turns file-provider routers into routes with a resolved backend address.
func (f fileConfig) routes(swarmName string, defs map[string]mw) []swarm.Route {
	var out []swarm.Route
	for name, r := range f.HTTP.Routers {
		m := resolve(r.Middlewares, defs)
		if m.redirect {
			continue
		}
		rt := swarm.Route{Swarm: swarmName, Name: name, Hosts: hostsFromRule(r.Rule), LANOnly: m.lanOnly, Auth: m.auth}
		if svc, ok := f.HTTP.Services[strings.SplitN(r.Service, "@", 2)[0]]; ok && len(svc.LoadBalancer.Servers) > 0 {
			rt.BackendHost, rt.BackendPort = splitBackend(svc.LoadBalancer.Servers[0].URL)
		}
		out = append(out, rt)
	}
	return out
}

func splitBackend(raw string) (string, int) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", 0
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 80
		if u.Scheme == "https" {
			port = 443
		}
	}
	return u.Hostname(), port
}

// isTraefik reports whether the image is Traefik.
func isTraefik(image string) bool {
	repo, _, _ := strings.Cut(image, ":")
	return path.Base(repo) == "traefik"
}

// readTraefikFiles reads the file-provider documents of the swarm's Traefik, locating them via the
// Traefik service's bind mounts and its static config. root is where the host's / is mounted.
func readTraefikFiles(ctx context.Context, r sshx.Runner, root string, svc *swarm.Service) []fileConfig {
	hostPath := func(containerPath string) string {
		best := ""
		src := ""
		for _, m := range svc.Mounts {
			if (containerPath == m.Target || strings.HasPrefix(containerPath, m.Target+"/")) && len(m.Target) > len(best) {
				best, src = m.Target, m.Source+strings.TrimPrefix(containerPath, m.Target)
			}
		}
		return src
	}
	staticSrc := hostPath("/etc/traefik/traefik.yml")
	if staticSrc == "" {
		staticSrc = hostPath("/etc/traefik/traefik.yaml")
	}
	if staticSrc == "" {
		return nil
	}
	out, err := r.Run(ctx, "cat "+sshx.Quote(root+staticSrc))
	if err != nil {
		return nil
	}
	var static struct {
		Providers struct {
			File struct {
				Directory string `yaml:"directory"`
				Filename  string `yaml:"filename"`
			} `yaml:"file"`
		} `yaml:"providers"`
	}
	if yaml.Unmarshal(out, &static) != nil {
		return nil
	}
	var script string
	if d := static.Providers.File.Directory; d != "" {
		if src := hostPath(d); src != "" {
			q := sshx.Quote(root + src)
			script = `for f in ` + q + `/*.yml ` + q + `/*.yaml; do [ -f "$f" ] && { echo "##FILE $f"; cat "$f"; }; done; true`
		}
	} else if fn := static.Providers.File.Filename; fn != "" {
		if src := hostPath(fn); src != "" {
			script = `echo "##FILE"; cat ` + sshx.Quote(root+src)
		}
	}
	if script == "" {
		return nil
	}
	raw, err := r.Run(ctx, script)
	if err != nil {
		return nil
	}
	var files []fileConfig
	for _, doc := range strings.Split(string(raw), "##FILE")[1:] {
		_, body, _ := strings.Cut(doc, "\n")
		var fc fileConfig
		if yaml.Unmarshal([]byte(body), &fc) == nil {
			files = append(files, fc)
		}
	}
	return files
}
