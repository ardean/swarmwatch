// Package swarm collects a read-only snapshot of one Docker Swarm over ssh.
package swarm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/sshx"
	"github.com/ardean/swarmwatch/internal/vuln"
)

const Standalone = "(standalone)"

type Snapshot struct {
	Name     string     `json:"name"`
	Time     time.Time  `json:"time"`
	Err      string     `json:"error,omitempty"`
	Host     HostInfo   `json:"host"`
	Nodes    []Node     `json:"nodes"`
	Services []*Service `json:"services"`
	// Routes are the Traefik file-provider routes found on this swarm (shared with peers for matching).
	Routes []Route `json:"routes,omitempty"`
	// Unused lists what can be cleaned up on the manager; nil when nothing.
	Unused *Unused `json:"unused,omitempty"`

	// DockerConfig is the host's ~/.docker/config.json; used in memory for registry auth only.
	DockerConfig []byte `json:"-"`
}

type HostInfo struct {
	Uptime    time.Duration `json:"uptime"`
	Load      [3]float64    `json:"load"`
	CPUs      int           `json:"cpus"`
	MemTotal  uint64        `json:"mem_total"`
	MemAvail  uint64        `json:"mem_available"`
	SwapTotal uint64        `json:"swap_total"`
	SwapFree  uint64        `json:"swap_free"`
	Disks     []Disk        `json:"disks"`
	Addrs     []string      `json:"addrs"` // IPv4 addresses of the host (for matching proxy backends)
}

func (h HostInfo) MemUsedPercent() float64 {
	if h.MemTotal == 0 {
		return 0
	}
	return float64(h.MemTotal-h.MemAvail) / float64(h.MemTotal) * 100
}

type Disk struct {
	Mount   string  `json:"mount"`
	Total   uint64  `json:"total"`
	Used    uint64  `json:"used"`
	Percent float64 `json:"percent"`
}

type Node struct {
	Hostname     string `json:"hostname"`
	Status       string `json:"status"`
	Availability string `json:"availability"`
	Role         string `json:"role"`
	Engine       string `json:"engine"`
}

// Port is a published port of a service or standalone container.
type Port struct {
	Published int    `json:"published"`
	Target    int    `json:"target"`
	Proto     string `json:"proto,omitempty"` // tcp or udp
	Mode      string `json:"mode,omitempty"`  // ingress | host
}

type Mount struct{ Source, Target string }

// Route is a Traefik route to a backend, already reduced to what exposure analysis needs.
type Route struct {
	Swarm       string   `json:"swarm"` // swarm whose Traefik serves it
	Name        string   `json:"name"`
	Hosts       []string `json:"hosts"`
	LANOnly     bool     `json:"lan_only"` // restricted to private source ranges
	Auth        bool     `json:"auth"`     // behind a forward-auth / basic-auth gate
	BackendHost string   `json:"backend_host,omitempty"`
	BackendPort int      `json:"backend_port,omitempty"`
}

// Exposure says how reachable a service is. Level: internet | internet-sso | lan | internal.
type Exposure struct {
	Level   string   `json:"level"`
	Hosts   []string `json:"hosts,omitempty"` // public (or LAN) hostnames from Traefik routes
	Ports   []int    `json:"ports,omitempty"` // ports published on the host
	Gateway bool     `json:"gateway,omitempty"`
}

type Service struct {
	Name           string            `json:"name"`
	Stack          string            `json:"stack"`
	Image          string            `json:"image"`  // name:tag without digest
	Digest         string            `json:"digest"` // running digest, if pinned by swarm
	Running        int               `json:"running"`
	Desired        int               `json:"desired"`
	RecentFailures int               `json:"recent_failures"` // failed/rejected tasks in the last day
	CPUPercent     float64           `json:"cpu_percent"`
	MemUsed        uint64            `json:"mem_used"`
	MemLimit       uint64            `json:"mem_limit"`
	Update         *registry.Result  `json:"update,omitempty"`
	Vuln           *vuln.Summary     `json:"vulns,omitempty"`
	Ports          []Port            `json:"ports,omitempty"`
	Exposure       *Exposure         `json:"exposure,omitempty"`
	HostNetwork    bool              `json:"host_network,omitempty"`
	Labels         map[string]string `json:"-"` // service and container labels (Traefik config)
	Mounts         []Mount           `json:"-"`
}

func (s *Service) Standalone() bool { return s.Stack == Standalone }

// Collect gathers everything for one swarm. Errors are recorded in Snapshot.Err.
func Collect(ctx context.Context, h config.Swarm) *Snapshot {
	snap := &Snapshot{Name: h.Name, Time: time.Now()}
	r := sshx.Runner{Dest: h.SSH}

	type result struct {
		out []byte
		err error
	}
	cmds := map[string]string{
		"nodes":     `docker node ls --format '{{json .}}'`,
		"svcls":     `docker service ls --format '{{json .}}'`,
		"svcinsp":   `docker service ls -q | xargs -r docker service inspect`,
		"tasks":     `docker service ls -q | xargs -r docker service ps --no-trunc --format '{{json .}}'`,
		"stats":     `docker stats --no-stream --no-trunc --format '{{json .}}'`,
		"ps":        `docker ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Label "com.docker.swarm.service.name"}}\t{{.Image}}\t{{.Ports}}\t{{.Networks}}'`,
		"hostinfo":  hostScript(h.HostRoot, h.Disks),
		"dockercfg": `cat "$HOME/.docker/config.json" 2>/dev/null`,
		// container -> image id, and image id -> registry digest, for standalone containers
		"ctrimg":  `docker ps -q --no-trunc | xargs -r docker inspect -f '{{.Id}}	{{.Image}}'`,
		"imgdig":  `docker image ls --digests --no-trunc --format '{{.ID}}	{{.Digest}}'`,
		"imgls":   cmdImages,
		"dangdig": cmdDangling,
		"psall":   cmdAllPS,
		"usedid":  cmdUsedIDs,
	}
	res := map[string]result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for k, c := range cmds {
		wg.Add(1)
		go func(k, c string) {
			defer wg.Done()
			out, err := r.Run(ctx, c)
			mu.Lock()
			res[k] = result{out, err}
			mu.Unlock()
		}(k, c)
	}
	wg.Wait()

	// The swarm commands are what matter; if they fail the host is unusable.
	for _, k := range []string{"nodes", "svcls", "svcinsp"} {
		if res[k].err != nil {
			snap.Err = res[k].err.Error()
			return snap
		}
	}
	if res["hostinfo"].err == nil {
		snap.Host = parseHost(res["hostinfo"].out, h.HostRoot)
	}
	snap.DockerConfig = res["dockercfg"].out
	snap.Nodes = parseNodes(res["nodes"].out)
	byName := map[string]*Service{}
	for _, s := range parseServices(res["svcls"].out, res["svcinsp"].out) {
		snap.Services = append(snap.Services, s)
		byName[s.Name] = s
	}
	if res["tasks"].err == nil {
		applyTasks(byName, res["tasks"].out)
	}
	if res["stats"].err == nil && res["ps"].err == nil {
		snap.Services = append(snap.Services, applyStats(byName, res["stats"].out, res["ps"].out, containerDigests(res["ctrimg"].out, res["imgdig"].out))...)
	}
	if res["imgls"].err == nil && res["psall"].err == nil && res["usedid"].err == nil {
		var refs []string
		for _, s := range snap.Services {
			refs = append(refs, s.Image)
		}
		if u := findUnused(res["imgls"].out, res["psall"].out, res["usedid"].out, refs); !u.Empty() {
			if res["dangdig"].err == nil {
				attachDanglingNames(u, res["dangdig"].out)
			}
			snap.Unused = u
		}
	}
	sort.Slice(snap.Services, func(i, j int) bool {
		a, b := snap.Services[i], snap.Services[j]
		if a.Stack != b.Stack {
			return a.Stack < b.Stack
		}
		return a.Name < b.Name
	})
	return snap
}

// hostScript gathers host load, memory and disk usage. root is where the host filesystem is
// mounted when running in a container ("" otherwise); df is run against paths below it.
func hostScript(root string, disks []string) string {
	var b strings.Builder
	b.WriteString("echo '##load'; cat /proc/loadavg; ")
	b.WriteString("echo '##uptime'; cut -d' ' -f1 /proc/uptime; ")
	b.WriteString("echo '##mem'; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo; ")
	b.WriteString("echo '##addrs'; awk '/32 host LOCAL/ {print prev} {prev=$2}' " + sshx.Quote(root+procNet(root)) + " 2>/dev/null | sort -u; ")
	b.WriteString("echo '##cpus'; nproc; echo '##df'; ")
	fmt.Fprintf(&b, "df -PB1 %s 2>/dev/null | tail -n +2; ", sshx.Quote(root+"/"))
	fmt.Fprintf(&b, `df -PB1 "%s$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)" 2>/dev/null | tail -n +2; `, root)
	for _, d := range disks {
		fmt.Fprintf(&b, "df -PB1 %s 2>/dev/null | tail -n +2; ", sshx.Quote(root+d))
	}
	return b.String()
}

// procNet is where the host's own network namespace table lives: in a container the host's
// pid 1 is visible below the mounted root, otherwise /proc/net is already the host's.
func procNet(root string) string {
	if root == "" {
		return "/proc/net/fib_trie"
	}
	return "/proc/1/net/fib_trie"
}

func parseHost(out []byte, root string) HostInfo {
	var h HostInfo
	sections := map[string][]string{}
	cur := ""
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "##") {
			cur = line[2:]
			continue
		}
		if line != "" {
			sections[cur] = append(sections[cur], line)
		}
	}
	if l := sections["load"]; len(l) > 0 {
		f := strings.Fields(l[0])
		for i := 0; i < 3 && i < len(f); i++ {
			h.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	if l := sections["uptime"]; len(l) > 0 {
		sec, _ := strconv.ParseFloat(l[0], 64)
		h.Uptime = time.Duration(sec * float64(time.Second))
	}
	if l := sections["cpus"]; len(l) > 0 {
		h.CPUs, _ = strconv.Atoi(l[0])
	}
	for _, l := range sections["mem"] {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			h.MemTotal = kb * 1024
		case "MemAvailable:":
			h.MemAvail = kb * 1024
		case "SwapTotal:":
			h.SwapTotal = kb * 1024
		case "SwapFree:":
			h.SwapFree = kb * 1024
		}
	}
	for _, a := range sections["addrs"] {
		if a != "127.0.0.1" {
			h.Addrs = append(h.Addrs, a)
		}
	}
	seen := map[string]bool{}
	for _, l := range sections["df"] {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		mount := f[len(f)-1]
		if mount = strings.TrimPrefix(mount, root); mount == "" {
			mount = "/"
		}
		if seen[mount] {
			continue
		}
		seen[mount] = true
		total, _ := strconv.ParseUint(f[1], 10, 64)
		used, _ := strconv.ParseUint(f[2], 10, 64)
		avail, _ := strconv.ParseUint(f[3], 10, 64)
		d := Disk{Mount: mount, Total: total, Used: used}
		if used+avail > 0 {
			d.Percent = float64(used) / float64(used+avail) * 100
		}
		h.Disks = append(h.Disks, d)
	}
	return h
}

func jsonLines(out []byte, fn func(map[string]any)) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			fn(m)
		}
	}
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func parseNodes(out []byte) []Node {
	var nodes []Node
	jsonLines(out, func(m map[string]any) {
		nodes = append(nodes, Node{
			Hostname: str(m, "Hostname"), Status: str(m, "Status"), Availability: str(m, "Availability"),
			Role: strings.ToLower(orDefault(str(m, "ManagerStatus"), "worker")), Engine: str(m, "EngineVersion"),
		})
	})
	return nodes
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func parseServices(ls, inspect []byte) []*Service {
	type spec struct {
		Spec struct {
			Name         string            `json:"Name"`
			Labels       map[string]string `json:"Labels"`
			TaskTemplate struct {
				ContainerSpec struct {
					Image  string            `json:"Image"`
					Labels map[string]string `json:"Labels"`
					Mounts []struct {
						Source string `json:"Source"`
						Target string `json:"Target"`
					} `json:"Mounts"`
				} `json:"ContainerSpec"`
			} `json:"TaskTemplate"`
		} `json:"Spec"`
		Endpoint struct {
			Ports []struct {
				Protocol      string `json:"Protocol"`
				TargetPort    int    `json:"TargetPort"`
				PublishedPort int    `json:"PublishedPort"`
				PublishMode   string `json:"PublishMode"`
			} `json:"Ports"`
		} `json:"Endpoint"`
	}
	var specs []spec
	_ = json.Unmarshal(inspect, &specs)
	byName := map[string]*Service{}
	var out []*Service
	for _, sp := range specs {
		cs := sp.Spec.TaskTemplate.ContainerSpec
		img, digest, _ := strings.Cut(cs.Image, "@")
		stack := sp.Spec.Labels["com.docker.stack.namespace"]
		if stack == "" {
			stack = "-"
		}
		s := &Service{Name: sp.Spec.Name, Stack: stack, Image: img, Digest: digest, Labels: map[string]string{}}
		for k, v := range sp.Spec.Labels { // deploy.labels and container labels both feed Traefik's swarm provider
			s.Labels[k] = v
		}
		for k, v := range cs.Labels {
			s.Labels[k] = v
		}
		for _, m := range cs.Mounts {
			s.Mounts = append(s.Mounts, Mount{m.Source, m.Target})
		}
		for _, p := range sp.Endpoint.Ports {
			if p.PublishedPort > 0 {
				s.Ports = append(s.Ports, Port{Published: p.PublishedPort, Target: p.TargetPort, Proto: p.Protocol, Mode: p.PublishMode})
			}
		}
		byName[s.Name] = s
		out = append(out, s)
	}
	jsonLines(ls, func(m map[string]any) {
		s := byName[str(m, "Name")]
		if s == nil {
			return
		}
		fmt.Sscanf(str(m, "Replicas"), "%d/%d", &s.Running, &s.Desired)
	})
	return out
}

// parseContainerPorts reads `docker ps` port text such as
// "0.0.0.0:8096->8096/tcp, [::]:8096->8096/tcp, 8920/tcp". Loopback bindings are not exposure.
func parseContainerPorts(s string) []Port {
	var out []Port
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		host, target, ok := strings.Cut(strings.TrimSpace(part), "->")
		if !ok {
			continue
		}
		i := strings.LastIndex(host, ":")
		if i < 0 {
			continue
		}
		if ip := strings.Trim(host[:i], "[]"); ip == "127.0.0.1" || ip == "::1" {
			continue
		}
		pub, _ := strconv.Atoi(host[i+1:])
		tgtPart, proto, hasProto := strings.Cut(target, "/")
		tgt, _ := strconv.Atoi(tgtPart)
		if !hasProto || proto == "" {
			proto = "tcp"
		}
		key := strconv.Itoa(pub) + "/" + proto
		if pub > 0 && !seen[key] {
			seen[key] = true
			out = append(out, Port{Published: pub, Target: tgt, Proto: proto, Mode: "host"})
		}
	}
	return out
}

var recent = regexp.MustCompile(`(second|minute|hour)`)

// applyTasks counts tasks that failed or were rejected within the last day.
func applyTasks(byName map[string]*Service, out []byte) {
	jsonLines(out, func(m map[string]any) {
		state := str(m, "CurrentState")
		if !(strings.HasPrefix(state, "Failed") || strings.HasPrefix(state, "Rejected")) || !recent.MatchString(state) {
			return
		}
		name := str(m, "Name") // service.slot (replicated) or service.nodeid (global)
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[:i]
		}
		if s := byName[name]; s != nil {
			s.RecentFailures++
		}
	})
}

// applyStats sums CPU/memory per service and returns standalone (non-swarm) containers.
func applyStats(byName map[string]*Service, stats, ps []byte, digests map[string]string) []*Service {
	type cont struct{ name, service, image, ports, network string }
	conts := map[string]cont{}
	sc := bufio.NewScanner(bytes.NewReader(ps))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) >= 6 {
			conts[f[0]] = cont{name: f[1], service: f[2], image: f[3], ports: f[4], network: f[5]}
		}
	}
	standalone := map[string]*Service{}
	jsonLines(stats, func(m map[string]any) {
		c, ok := conts[str(m, "Container")]
		if !ok {
			return
		}
		var s *Service
		if c.service != "" {
			s = byName[c.service]
			// the stack was deployed without a pinned digest (registry unreachable at deploy time,
			// --resolve-image never): fall back to what the running container's image was pulled as
			if s != nil && s.Digest == "" {
				s.Digest = digests[str(m, "Container")]
			}
		} else {
			if standalone[c.name] == nil {
				img, _, _ := strings.Cut(c.image, "@")
				standalone[c.name] = &Service{Name: c.name, Stack: Standalone, Image: img, Digest: digests[str(m, "Container")], Running: 1, Desired: 1,
					Ports: parseContainerPorts(c.ports), HostNetwork: c.network == "host", Labels: map[string]string{}}
			}
			s = standalone[c.name]
		}
		if s == nil {
			return
		}
		cpu, _ := strconv.ParseFloat(strings.TrimSuffix(str(m, "CPUPerc"), "%"), 64)
		s.CPUPercent += cpu
		used, limit, _ := strings.Cut(str(m, "MemUsage"), " / ")
		s.MemUsed += parseSize(used)
		if l := parseSize(limit); l > s.MemLimit {
			s.MemLimit = l
		}
	})
	var out []*Service
	for _, s := range standalone {
		out = append(out, s)
	}
	return out
}

// containerDigests maps full container id -> registry digest of the image it runs.
func containerDigests(ctrImg, imgDig []byte) map[string]string {
	byImage := map[string]string{}
	for _, l := range strings.Split(string(imgDig), "\n") {
		f := strings.Split(l, "\t")
		if len(f) == 2 && strings.HasPrefix(f[1], "sha256:") {
			byImage[f[0]] = f[1]
		}
	}
	out := map[string]string{}
	for _, l := range strings.Split(string(ctrImg), "\n") {
		f := strings.Split(l, "\t")
		if len(f) == 2 {
			if d := byImage[f[1]]; d != "" {
				out[f[0]] = d
			}
		}
	}
	return out
}

var sizeRe = regexp.MustCompile(`^([\d.]+)\s*([A-Za-z]*)$`)

func parseSize(s string) uint64 {
	m := sizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	mult := map[string]float64{"": 1, "B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
		"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}[m[2]]
	return uint64(v * mult)
}
