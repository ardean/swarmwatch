package server

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ardean/swarmwatch/internal/swarm"
)

// seenEntry remembers when a finding first appeared.
type seenEntry struct {
	Swarm string    `json:"swarm"`
	First time.Time `json:"first"`
}

// firstSeen tracks since when each finding exists, so a consumer can alert on new findings only. The
// state is a small JSON file next to the scan results and survives restarts. A finding that goes away
// is forgotten; if it comes back it is new again.
type firstSeen struct {
	mu      sync.Mutex
	path    string
	entries map[string]seenEntry
	warned  bool
}

func loadFirstSeen(dir string) *firstSeen {
	f := &firstSeen{path: filepath.Join(dir, "first-seen.json"), entries: map[string]seenEntry{}}
	if b, err := os.ReadFile(f.path); err == nil {
		if err := json.Unmarshal(b, &f.entries); err != nil {
			log.Printf("first-seen: ignoring unreadable %s: %v", f.path, err)
			f.entries = map[string]seenEntry{}
		}
	}
	return f
}

// update records the current findings and returns the first-seen time of each by ID. Findings of a
// swarm that could not be read (unreachable) are not judged: their entries are kept, so an outage
// of the manager does not make every old finding look new when it is back.
func (f *firstSeen) update(findings []swarm.Finding, unreadable map[string]bool, now time.Time) map[string]time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	current := make(map[string]time.Time, len(findings))
	changed := false
	next := make(map[string]seenEntry, len(findings))
	for _, fi := range findings {
		id := fi.ID()
		e, ok := f.entries[id]
		if !ok {
			e = seenEntry{Swarm: fi.Swarm, First: now}
			changed = true
		}
		next[id] = e
		current[id] = e.First
	}
	for id, e := range f.entries {
		if _, ok := next[id]; !ok && unreadable[e.Swarm] {
			next[id] = e
		} else if !ok {
			changed = true
		}
	}
	f.entries = next
	if changed {
		f.save()
	}
	return current
}

// save writes the state atomically. A failure is logged once and never stops the server: the
// first-seen times then only live in memory.
func (f *firstSeen) save() {
	b, err := json.Marshal(f.entries)
	if err == nil {
		if err = os.MkdirAll(filepath.Dir(f.path), 0o700); err == nil {
			tmp := f.path + ".tmp"
			if err = os.WriteFile(tmp, b, 0o600); err == nil {
				err = os.Rename(tmp, f.path)
			}
		}
	}
	if err != nil && !f.warned {
		f.warned = true
		log.Printf("first-seen: cannot persist to %s: %v (kept in memory only)", f.path, err)
	}
}
