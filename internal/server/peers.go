package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ardean/swarmwatch/internal/swarm"
)

// exposureDoc is what /api/exposure serves: the Traefik file routes this instance found,
// so another swarm's instance can match them to its own services.
type exposureDoc struct {
	Swarm  string        `json:"swarm"`
	Addrs  []string      `json:"addrs"`
	Routes []swarm.Route `json:"routes"`
}

func (s *Server) handleExposure(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	docs := make([]exposureDoc, 0, len(s.snaps))
	for _, sn := range s.snaps {
		docs = append(docs, exposureDoc{Swarm: sn.Name, Addrs: sn.Host.Addrs, Routes: sn.Routes})
	}
	writeJSON(w, docs)
}

// fetchPeers collects routes from the configured peer instances. A peer that is down keeps its
// last known routes, so a brief outage does not flip services to "internal".
func (s *Server) fetchPeers(ctx context.Context) []swarm.Route {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peers == nil {
		s.peers = map[string][]swarm.Route{}
	}
	client := &http.Client{Timeout: 5 * time.Second}
	var all []swarm.Route
	for _, base := range s.cfg.Serve.Peers {
		url := strings.TrimRight(base, "/") + "/api/exposure"
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			var docs []exposureDoc
			if json.NewDecoder(resp.Body).Decode(&docs) == nil {
				var routes []swarm.Route
				for _, d := range docs {
					routes = append(routes, d.Routes...)
				}
				s.peers[base] = routes
			}
		} else if err != nil {
			log.Printf("peer %s: %v", base, err)
		}
		if resp != nil {
			resp.Body.Close()
		}
		all = append(all, s.peers[base]...)
	}
	return all
}
