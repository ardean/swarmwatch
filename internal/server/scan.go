package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/ardean/swarmwatch/pkg/api"

	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/watch"
)

// handleScan starts a vulnerability scan of every image. The scan window only limits the automatic
// scans; this ignores it. The pages have no login, so it only accepts same-origin POSTs. A scan does
// not change the swarm. One runs at a time: a second request while one is running comes back to the
// page, which already shows the progress.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	if !s.scanMu.TryLock() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.mu.RLock()
	snaps := append([]*swarm.Snapshot(nil), s.snaps...)
	s.mu.RUnlock()
	n := s.armScan(snaps, true)
	if n == 0 {
		s.scanMu.Unlock()
		s.mu.Lock()
		s.scan.Note = "nothing to scan"
		s.mu.Unlock()
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	log.Printf("scan: %d image(s) requested from %s", n, r.RemoteAddr)
	go func() {
		defer s.scanMu.Unlock()
		s.executeScan(context.Background(), snaps, true)
	}()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleAPIScan is scan now for a caller that has the token. The scan window does not apply.
// One scan runs at a time. Accepted is false when there was nothing to scan.
func (s *Server) handleAPIScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if !s.scanMu.TryLock() {
		writeError(w, http.StatusConflict, "a scan is already running")
		return
	}
	s.mu.RLock()
	snaps := append([]*swarm.Snapshot(nil), s.snaps...)
	s.mu.RUnlock()
	n := s.armScan(snaps, true)
	accepted := n > 0
	if !accepted {
		s.scanMu.Unlock()
	} else {
		log.Printf("scan: %d image(s) requested from %s", n, r.RemoteAddr)
		go func() {
			defer s.scanMu.Unlock()
			s.executeScan(context.Background(), snaps, true)
		}()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(api.ImageCheckAccepted{Accepted: accepted})
}

// armScan marks a scan running and returns how many images it will cover. Zero means there is
// nothing to do and the status is left unchanged, apart from the caller setting a note.
func (s *Server) armScan(snaps []*swarm.Snapshot, force bool) int {
	n := 0
	for _, sn := range snaps {
		if sn.Err == "" {
			n += watch.StaleImages(sn, s.cache, s.cfg.Scan.MaxAge, force)
		}
	}
	if n == 0 {
		return 0
	}
	s.mu.Lock()
	s.scan = scanStatus{Running: true, Total: n, LastEnd: s.scan.LastEnd}
	s.mu.Unlock()
	return n
}

// executeScan runs the scan and refreshes the snapshot so the new results show up at once.
// s.scanFn replaces that in tests, which have no Docker.
func (s *Server) executeScan(ctx context.Context, snaps []*swarm.Snapshot, force bool) {
	if s.scanFn != nil {
		s.scanFn(ctx, snaps, force)
		s.mu.Lock()
		s.scan = scanStatus{LastEnd: time.Now()}
		s.mu.Unlock()
		return
	}
	var lastErr string
	watch.ScanStale(ctx, s.cfg, snaps, s.cache, force, func(e watch.Event) {
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
	s.refresh(ctx)
}
