package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ardean/swarmwatch/internal/cron"
	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/update"
	"github.com/ardean/swarmwatch/pkg/api"
)

// handleImages serves each service and whether its tag has a new image, plus whether a manual
// check may be started. The pages stay off when the UI is disabled; this is the API for that.
func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	writeJSON(w, s.imageReport())
}

// handleImageCheck starts a registry check. It forgets the remembered digests and collects again,
// so a tag that moved is visible without waiting for the schedule. When updates are switched on,
// the same request then rolls every service the schedule would roll. The page button does not:
// that page has no login. A second request while a check or a roll is running is refused.
func (s *Server) handleImageCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if s.updateBusy() {
		writeError(w, http.StatusConflict, "an update is already running")
		return
	}
	if !s.beginImageCheck() {
		writeError(w, http.StatusConflict, "an image check is already running")
		return
	}
	log.Printf("images: check requested from %s", r.RemoteAddr)
	go s.finishAPIImageCheck()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(api.ImageCheckAccepted{Accepted: true})
}

// handleImageCheckPage is the button on the web page. It sits next to scan now: always there, and
// it cannot be pressed again until the check has finished. Only same-origin POSTs, because the
// pages have no login.
func (s *Server) handleImageCheckPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	if !s.beginImageCheck() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	log.Printf("images: check requested from %s", r.RemoteAddr)
	go s.finishImageCheck()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// updateBusy reports whether a roll is in progress. An API check is refused while one is running.
func (s *Server) updateBusy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.upd.Running
}

// finishAPIImageCheck asks the registries and then, when updates are on, rolls what the schedule would.
// imageChecking stays set until the roll has finished, so the button cannot start another one.
func (s *Server) finishAPIImageCheck() {
	defer func() {
		s.mu.Lock()
		s.imageChecking = false
		s.mu.Unlock()
	}()
	s.runImageCheck()
	s.rollAfterCheck(context.Background())
}

func (s *Server) beginImageCheck() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.imageChecking {
		return false
	}
	s.imageChecking = true
	return true
}

// finishImageCheck is the page button. It only asks the registries. The page has no login, so it must
// not roll a service.
func (s *Server) finishImageCheck() {
	defer func() {
		s.mu.Lock()
		s.imageChecking = false
		s.mu.Unlock()
	}()
	s.runImageCheck()
}

func (s *Server) runImageCheck() {
	if s.imageCheckFn != nil {
		s.imageCheckFn()
	} else {
		if s.checker != nil {
			s.checker.Reset()
		}
		s.refresh(context.Background())
	}
	if s.checker != nil {
		s.checker.NoteAsked(time.Now())
	}
}

func (s *Server) imageReport() api.Images {
	s.mu.RLock()
	snaps := append([]*swarm.Snapshot(nil), s.snaps...)
	updated, stale, checking := s.updated, s.stale(), s.imageChecking
	upd := s.upd
	s.mu.RUnlock()

	var self string
	if s.cfg.Update.Schedule != "" {
		self = s.selfService()
	}
	out := api.Images{
		Updated: updated,
		Stale:   stale,
		Check: api.ImageCheck{
			Running: checking,
			Last:    s.checker.Asked(),
			Rolls:   s.updateEnabled(),
		},
		Schedules: s.schedules(time.Now()),
		Updates: api.ImageUpdates{
			Schedule: s.cfg.Update.Schedule,
			Running:  upd.Running,
			Text:     upd.Text,
			Recent:   []api.ImageUpdate{},
		},
		Services: []api.ImageService{},
	}
	for _, r := range s.updates.recent(20) {
		out.Updates.Recent = append(out.Updates.Recent, api.ImageUpdate{
			Time: r.Time, Swarm: r.Swarm, Service: r.Service, Image: r.Image,
			OK: r.OK, Message: r.Message, Restart: r.Restart, Manual: r.Manual,
		})
	}
	for _, sn := range snaps {
		if sn == nil {
			continue
		}
		for _, v := range sn.Services {
			svc := api.ImageService{
				Swarm: sn.Name, Stack: v.Stack, Service: v.Name, Image: v.Image,
				Running: v.Running, Desired: v.Desired,
			}
			if v.Update != nil {
				svc.State = v.Update.State
			}
			if v.Exposure != nil {
				svc.Exposure = v.Exposure.Level
			}
			if s.cfg.Update.Schedule != "" {
				svc.Schedule = "auto"
				if why := update.Excluded(v, self); why != "" {
					svc.Schedule = "no, " + why
				}
			}
			out.Services = append(out.Services, svc)
		}
	}
	slices.SortFunc(out.Services, func(a, b api.ImageService) int {
		if c := strings.Compare(a.Stack, b.Stack); c != 0 {
			return c
		}
		if c := strings.Compare(a.Service, b.Service); c != 0 {
			return c
		}
		return strings.Compare(a.Swarm, b.Swarm)
	})
	return out
}

// schedules is the automatic work, so a caller can show the wait that Check images skips.
func (s *Server) schedules(now time.Time) api.Schedules {
	out := api.Schedules{Scan: "any time"}
	if s.cfg.Scan.Window != "" {
		out.Scan = s.cfg.Scan.Window
	}
	if spec := s.cfg.Update.Schedule; spec != "" {
		out.Images = whenOf(spec, now)
	}
	if spec := s.cfg.Clean.Schedule; spec != "" {
		out.Clean = whenOf(spec, now)
	}
	return out
}

func whenOf(spec string, now time.Time) api.When {
	w := api.When{Cron: spec, Text: cron.Describe(spec)}
	parsed, err := cron.Parse(spec)
	if err != nil {
		return w
	}
	if next, ok := parsed.Next(now); ok {
		w.Next = next
	}
	return w
}
