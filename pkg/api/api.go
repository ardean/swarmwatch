// Package api holds the wire types of the swarmwatch HTTP API, version 1.
//
// The server marshals exactly these types, so the structs are the contract. Within v1 fields are only
// ever added, never renamed, removed or given another meaning; a breaking change would be served under
// /api/v2. Clients should ignore fields they do not know.
package api

import "time"

// Levels of a finding, and of the overall status. Status is "ok" when there are no findings at all,
// otherwise the worst level present.
const (
	LevelOK   = "ok"
	LevelInfo = "info"
	LevelWarn = "warn"
	LevelCrit = "crit"
)

// Kinds of finding. The set may grow; treat an unknown kind as "something else needs attention".
const (
	KindUnreachable = "unreachable"   // the manager could not be reached
	KindNode        = "node"          // a node is not Ready/Active
	KindMemory      = "memory"        // host memory above the threshold
	KindDisk        = "disk"          // a disk fuller than the threshold
	KindReplicas    = "replicas"      // fewer replicas running than desired
	KindFailedTasks = "failed_tasks"  // failed or rejected tasks in the last 24 h
	KindOutdated    = "outdated"      // the registry has another image behind the running tag
	KindVuln        = "vulnerability" // fixable vulnerabilities of a severity in an image
	KindStaleScan   = "stale_scan"    // the vulnerability data of an image is old
	KindUnused      = "unused"        // unused images or stopped containers can be removed
)

// Finding is one thing that needs a reaction.
type Finding struct {
	// ID is stable for the same problem on the same object across refreshes and restarts, for
	// example "outdated:prod:outdrive_redis". Use it to de-duplicate alerts.
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Level is "crit", "warn" or "info".
	Level string `json:"level"`
	Swarm string `json:"swarm"`
	// Stack is the Docker stack of the service, empty for swarm-level findings.
	Stack   string `json:"stack,omitempty"`
	Service string `json:"service,omitempty"`
	// Message is a human readable sentence. Do not parse it; use the other fields.
	Message string `json:"message"`
	Image   string `json:"image,omitempty"`
	// Exposure is "internet", "internet-sso", "lan" or "internal" when known.
	Exposure string `json:"exposure,omitempty"`
	// Severity and Count are set for vulnerability findings: how many fixable ones of that severity.
	Severity string `json:"severity,omitempty"`
	Count    int    `json:"count,omitempty"`
	// FirstSeen is when this finding first appeared and has not gone away since.
	FirstSeen time.Time `json:"first_seen"`
}

// Findings is the response of GET /api/v1/findings.
type Findings struct {
	Status   string    `json:"status"`
	Updated  time.Time `json:"updated"`
	Stale    bool      `json:"stale,omitempty"` // the data is older than five refresh intervals
	Findings []Finding `json:"findings"`
}

// Counts of findings per level.
type Counts struct {
	Crit int `json:"crit"`
	Warn int `json:"warn"`
	Info int `json:"info"`
}

// Scan is the state of the vulnerability scanner.
type Scan struct {
	Running   bool      `json:"running"`
	Current   string    `json:"current,omitempty"`
	Done      int       `json:"done"`
	Total     int       `json:"total"`
	LastEnd   time.Time `json:"last_end"`
	LastError string    `json:"last_error,omitempty"`
}

// SwarmStatus is the worst level of one swarm.
type SwarmStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Summary is the response of GET /api/v1/summary: small enough to poll every minute.
type Summary struct {
	Version    string        `json:"version"`
	Status     string        `json:"status"`
	Updated    time.Time     `json:"updated"`
	AgeSeconds int64         `json:"age_seconds"`
	Stale      bool          `json:"stale,omitempty"`
	Counts     Counts        `json:"counts"`
	Scan       Scan          `json:"scan"`
	Swarms     []SwarmStatus `json:"swarms"`
}

// Vuln is one vulnerability of an image.
type Vuln struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Package   string `json:"package"`
	Installed string `json:"installed,omitempty"`
	Fixed     string `json:"fixed,omitempty"`
	Title     string `json:"title,omitempty"`
	URL       string `json:"url,omitempty"`
}

// Vulns is the response of GET /api/v1/vulns?swarm=…&service=….
type Vulns struct {
	Swarm     string         `json:"swarm"`
	Service   string         `json:"service"`
	Image     string         `json:"image"`
	ScannedAt time.Time      `json:"scanned_at"`
	Counts    map[string]int `json:"counts"`
	Fixable   map[string]int `json:"fixable"`
	Items     []Vuln         `json:"items"`
}

// Error is the body of every non-2xx response of /api/v1.
type Error struct {
	Error string `json:"error"`
}
