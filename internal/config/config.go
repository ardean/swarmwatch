// Package config loads the swarmwatch swarm list and thresholds.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
}

type Serve struct {
	Listen      string        `yaml:"listen"`
	Peers       []string      `yaml:"peers"`        // base URLs of other swarmwatch instances whose Traefik routes to this swarm
	AllowClean  bool          `yaml:"allow_clean"`  // show the "remove unused images/containers" button (UI is unauthenticated!)
	Refresh     time.Duration `yaml:"refresh"`      // how often the snapshot is re-collected
	RegistryTTL time.Duration `yaml:"registry_ttl"` // how long registry digests are reused
}

type Config struct {
	Swarms     []Swarm    `yaml:"swarms"`
	Thresholds Thresholds `yaml:"thresholds"`
	Scan       Scan       `yaml:"scan"`
	Serve      Serve      `yaml:"serve"`
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
	return &c, nil
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
