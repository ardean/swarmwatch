// Package config loads the swarmwatch swarm list and thresholds.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ardean/swarmwatch/internal/cron"
	"gopkg.in/yaml.v3"
)

// Swarm is one independent Docker Swarm, reached over SSH through one of its managers
// (or locally when swarmwatch itself runs on that manager, e.g. as a service in the swarm).
// Container stats (CPU/memory) are only visible for containers on that manager.
type Swarm struct {
	Name     string   `yaml:"name"`
	SSH      string   `yaml:"ssh"`       // ssh destination or alias; "local" runs on this machine
	Disks    []string `yaml:"disks"`     // extra mount points to report besides / and the Docker root
	HostRoot string   `yaml:"host_root"` // where the host's / is bind-mounted when running in a container
}

type Thresholds struct {
	DiskPercent float64 `yaml:"disk_percent"` // flag when a disk is fuller than this
	MemPercent  float64 `yaml:"mem_percent"`  // flag when used memory exceeds this
}

type Scan struct {
	MaxAge     time.Duration `yaml:"max_age"`     // rescan images whose result is older than this
	TrivyImage string        `yaml:"trivy_image"` // used over ssh; the container image bundles trivy
	// Window limits when the server starts automatic scans, "HH:MM-HH:MM" in the server's time zone (TZ),
	// for example "02:00-05:00". Empty means any time. A scan that has started always finishes. The scan
	// now button and the CLI ignore the window, and images that were never scanned wait for it like the rest.
	Window string `yaml:"window"`
}

type Serve struct {
	Listen      string        `yaml:"listen"`
	Peers       []string      `yaml:"peers"`        // base URLs of other swarmwatch instances whose Traefik routes to this swarm
	AllowClean  bool          `yaml:"allow_clean"`  // show the "remove unused images/containers" button (UI is unauthenticated!)
	Refresh     time.Duration `yaml:"refresh"`      // how often the snapshot is re-collected
	RegistryTTL time.Duration `yaml:"registry_ttl"` // how long registry digests are reused

	// Token, when set, is required as "Authorization: Bearer <token>" on every /api/ request.
	// /healthz stays open for health checks. The web pages are not covered, see DisableUI.
	Token string `yaml:"token"`
	// TokenFile is a file holding the token, for example a Docker secret at /run/secrets/…;
	// it is read once at start and used when Token is empty.
	TokenFile string `yaml:"token_file"`
	// PeerToken is sent as a bearer token to the peers, for peers that have a token set.
	PeerToken string `yaml:"peer_token"`
	// DisableUI serves only /api/ and /healthz: no web pages and no clean-up endpoint. Use it with a token
	// when swarmwatch is only a data source for another tool.
	DisableUI bool `yaml:"disable_ui"`
}

// Update controls rolling services to newer images. Everything is off unless switched on here: the
// page is unauthenticated, so an update button is as sensitive as the clean-up one.
type Update struct {
	// Allow shows an "update" button on services that have a newer image behind their tag.
	Allow bool `yaml:"allow"`
	// Schedule is a cron expression (minute hour day-of-month month day-of-week, in the server's TZ),
	// for example "0 4 1 * *" for 04:00 on the first of each month. Empty means no automatic updates.
	// Services labeled swarmwatch.update=night are not part of this schedule.
	Schedule string `yaml:"schedule"`
	// Night is a second cron for services labeled swarmwatch.update=night, for example "15 1 * * *"
	// for 01:15 every day. Empty means those services are never rolled. The fast schedule and the
	// button do not roll them either.
	Night string `yaml:"night"`
	// Wait is the pause after each updated service, so one that others depend on can settle. Default 60s.
	Wait time.Duration `yaml:"wait"`
	// Cleanup removes the images no service uses any more after an update run.
	Cleanup bool `yaml:"cleanup"`
}

// Clean removes unused images and stopped containers on a schedule. Off unless a schedule is set. It needs
// no web page and no button: nothing can trigger it from the network.
type Clean struct {
	// Schedule is a cron expression in the server's TZ, for example "30 3 * * *" for 03:30 every day.
	Schedule string `yaml:"schedule"`
	// Keep is how long an unused image stays, counted from when it was built, so a quick rollback does not
	// need a pull. Default 7 days ("7d" or "168h").
	Keep time.Duration `yaml:"keep"`
	// KeepContainers is the same for stopped containers that are not swarm tasks. Default 24h.
	KeepContainers time.Duration `yaml:"keep_containers"`
}

type Config struct {
	Swarms     []Swarm    `yaml:"swarms"`
	Thresholds Thresholds `yaml:"thresholds"`
	Scan       Scan       `yaml:"scan"`
	Serve      Serve      `yaml:"serve"`
	Update     Update     `yaml:"update"`
	Clean      Clean      `yaml:"clean"`
}

func DefaultPath() string {
	if p := os.Getenv("SWARMWATCH_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "swarmwatch", "config.yaml")
}

func CacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".cache")
	}
	return filepath.Join(dir, "swarmwatch")
}

// Load reads the config file. If SWARMWATCH_NAME is set, a single local swarm is
// configured from SWARMWATCH_* environment variables instead (container use).
func Load(path string) (*Config, error) {
	var c Config
	if name := os.Getenv("SWARMWATCH_NAME"); name != "" {
		c.Swarms = []Swarm{{
			Name:     name,
			SSH:      "local",
			HostRoot: os.Getenv("SWARMWATCH_HOST_ROOT"),
			Disks:    splitList(os.Getenv("SWARMWATCH_DISKS")),
		}}
		c.Thresholds.DiskPercent = envFloat("SWARMWATCH_DISK_PERCENT")
		c.Thresholds.MemPercent = envFloat("SWARMWATCH_MEM_PERCENT")
		c.Serve.Listen = os.Getenv("SWARMWATCH_LISTEN")
		c.Serve.Peers = splitList(os.Getenv("SWARMWATCH_PEERS"))
		c.Serve.AllowClean = envBool("SWARMWATCH_ALLOW_CLEAN")
		c.Serve.Token = os.Getenv("SWARMWATCH_TOKEN")
		c.Serve.TokenFile = os.Getenv("SWARMWATCH_TOKEN_FILE")
		c.Serve.PeerToken = os.Getenv("SWARMWATCH_PEER_TOKEN")
		c.Serve.DisableUI = envBool("SWARMWATCH_DISABLE_UI")
		c.Scan.Window = os.Getenv("SWARMWATCH_SCAN_WINDOW")
		c.Update.Allow = envBool("SWARMWATCH_ALLOW_UPDATE")
		c.Update.Schedule = os.Getenv("SWARMWATCH_UPDATE_SCHEDULE")
		c.Update.Night = os.Getenv("SWARMWATCH_UPDATE_NIGHT")
		c.Update.Cleanup = envBool("SWARMWATCH_UPDATE_CLEANUP")
		c.Clean.Schedule = os.Getenv("SWARMWATCH_CLEAN_SCHEDULE")
		if v := os.Getenv("SWARMWATCH_CLEAN_KEEP"); v != "" {
			d, err := parseAge(v)
			if err != nil {
				return nil, fmt.Errorf("SWARMWATCH_CLEAN_KEEP: %w", err)
			}
			c.Clean.Keep = d
		}
		if v := os.Getenv("SWARMWATCH_CLEAN_KEEP_CONTAINERS"); v != "" {
			d, err := parseAge(v)
			if err != nil {
				return nil, fmt.Errorf("SWARMWATCH_CLEAN_KEEP_CONTAINERS: %w", err)
			}
			c.Clean.KeepContainers = d
		}
		if v := os.Getenv("SWARMWATCH_UPDATE_WAIT"); v != "" {
			d, err := parseWait(v)
			if err != nil {
				return nil, fmt.Errorf("SWARMWATCH_UPDATE_WAIT: %w", err)
			}
			c.Update.Wait = d
		}
	} else {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w (see swarmwatch.example.yaml)", path, err)
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	if len(c.Swarms) == 0 {
		return nil, fmt.Errorf("config %s: no swarms", path)
	}
	for i := range c.Swarms {
		s := &c.Swarms[i]
		if s.SSH == "" {
			s.SSH = s.Name
		}
		if s.Name == "" {
			s.Name = s.SSH
		}
	}
	setDefaults(&c)
	if err := c.resolveToken(); err != nil {
		return nil, err
	}
	if _, err := ParseWindow(c.Scan.Window); err != nil {
		return nil, fmt.Errorf("scan window: %w", err)
	}
	if c.Serve.DisableUI && c.Serve.AllowClean {
		return nil, fmt.Errorf("serve: allow_clean needs the web UI, remove disable_ui or allow_clean")
	}
	c.Update.Schedule = strings.TrimSpace(c.Update.Schedule)
	if c.Update.Schedule != "" {
		if _, err := cron.Parse(c.Update.Schedule); err != nil {
			return nil, fmt.Errorf("update schedule: %w", err)
		}
	}
	c.Update.Night = strings.TrimSpace(c.Update.Night)
	if c.Update.Night != "" {
		if _, err := cron.Parse(c.Update.Night); err != nil {
			return nil, fmt.Errorf("update night schedule: %w", err)
		}
	}
	if c.Update.Wait < 0 {
		return nil, fmt.Errorf("update wait must not be negative")
	}
	c.Clean.Schedule = strings.TrimSpace(c.Clean.Schedule)
	if c.Clean.Schedule != "" {
		if _, err := cron.Parse(c.Clean.Schedule); err != nil {
			return nil, fmt.Errorf("clean schedule: %w", err)
		}
	}
	if c.Clean.Keep < 0 || c.Clean.KeepContainers < 0 {
		return nil, fmt.Errorf("clean keep must not be negative")
	}
	if c.Serve.DisableUI && c.Update.Allow {
		return nil, fmt.Errorf("update: allow needs the web UI, remove disable_ui or update allow (a schedule works without it)")
	}
	return &c, nil
}

// MinTokenLength is the shortest accepted API token. Generate one with: openssl rand -hex 32
const MinTokenLength = 16

// resolveToken reads TokenFile when no token is set inline and rejects a token that is too short to
// be a secret. Surrounding whitespace, such as the newline at the end of a file, is not part of it.
func (c *Config) resolveToken() error {
	c.Serve.Token = strings.TrimSpace(c.Serve.Token)
	if c.Serve.Token == "" && c.Serve.TokenFile != "" {
		b, err := os.ReadFile(c.Serve.TokenFile)
		if err != nil {
			return fmt.Errorf("read token file: %w", err)
		}
		c.Serve.Token = strings.TrimSpace(string(b))
		if c.Serve.Token == "" {
			return fmt.Errorf("token file %s is empty", c.Serve.TokenFile)
		}
	}
	if t := c.Serve.Token; t != "" && len(t) < MinTokenLength {
		return fmt.Errorf("API token is shorter than %d characters (generate one with: openssl rand -hex 32)", MinTokenLength)
	}
	c.Serve.PeerToken = strings.TrimSpace(c.Serve.PeerToken)
	return nil
}

// Window is a daily time span, in minutes since midnight. It may wrap past midnight (22:00-04:00).
type Window struct{ From, To int }

// ParseWindow parses "HH:MM-HH:MM". The empty string is "always" and returns a nil window.
func ParseWindow(s string) (*Window, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	from, to, ok := strings.Cut(s, "-")
	if !ok {
		return nil, fmt.Errorf("%q: want HH:MM-HH:MM", s)
	}
	f, err1 := parseClock(from)
	t, err2 := parseClock(to)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("%q: want HH:MM-HH:MM", s)
	}
	if f == t {
		return nil, fmt.Errorf("%q: the window is empty", s)
	}
	return &Window{From: f, To: t}, nil
}

func parseClock(s string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	return t.Hour()*60 + t.Minute(), nil
}

// Contains reports whether the clock time of t is inside the window. A nil window contains every time.
func (w *Window) Contains(t time.Time) bool {
	if w == nil {
		return true
	}
	m := t.Hour()*60 + t.Minute()
	if w.From < w.To {
		return m >= w.From && m < w.To
	}
	return m >= w.From || m < w.To
}

func setDefaults(c *Config) {
	if c.Thresholds.DiskPercent == 0 {
		c.Thresholds.DiskPercent = 85
	}
	if c.Thresholds.MemPercent == 0 {
		c.Thresholds.MemPercent = 90
	}
	if c.Scan.MaxAge == 0 {
		c.Scan.MaxAge = 24 * time.Hour
	}
	if c.Scan.TrivyImage == "" {
		c.Scan.TrivyImage = "aquasec/trivy:latest"
	}
	if c.Serve.Listen == "" {
		c.Serve.Listen = ":8590"
	}
	if c.Serve.Refresh == 0 {
		c.Serve.Refresh = 2 * time.Minute
	}
	if c.Serve.RegistryTTL == 0 {
		c.Serve.RegistryTTL = time.Hour
	}
	if c.Update.Wait == 0 {
		c.Update.Wait = time.Minute
	}
	if c.Clean.Keep == 0 {
		c.Clean.Keep = 7 * 24 * time.Hour
	}
	if c.Clean.KeepContainers == 0 {
		c.Clean.KeepContainers = 24 * time.Hour
	}
}

// parseAge reads "7d", "36h" or any time.ParseDuration value. A number of days is the unit people think in
// for how long an image stays, and time.ParseDuration has none.
func parseAge(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%q is not a number of days", v)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%q is neither days (7d) nor a duration (168h)", v)
	}
	return d, nil
}

// parseWait reads "90s" style durations, or a plain number of seconds.
func parseWait(v string) (time.Duration, error) {
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(v)
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

func envFloat(k string) float64 {
	f, _ := strconv.ParseFloat(os.Getenv(k), 64)
	return f
}

func envBool(k string) bool {
	switch strings.ToLower(os.Getenv(k)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
