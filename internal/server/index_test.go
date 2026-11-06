package server

import (
	"strings"
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/exposure"
	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/pkg/api"
)

func TestIndexGroupsFindingsByExposure(t *testing.T) {
	now := time.Now()
	cfg := &config.Config{Swarms: []config.Swarm{{Name: "prod", SSH: "local"}}}
	cfg.Serve.Refresh = 2 * time.Minute
	findings := []swarm.Finding{
		{Level: swarm.Crit, Kind: api.KindVuln, Swarm: "prod", Service: "kavita", Message: "kavita public", Exposure: exposure.Internet},
		{Level: swarm.Warn, Kind: api.KindVuln, Swarm: "prod", Service: "speedtest", Message: "speedtest behind login", Exposure: exposure.InternetSSO},
		{Level: swarm.Crit, Kind: api.KindDisk, Swarm: "prod", Subject: "/media/Data", Message: "disk full"},
		{Level: swarm.Crit, Kind: api.KindVuln, Swarm: "prod", Service: "seerr", Message: "seerr at home", Exposure: exposure.LAN},
		{Level: swarm.Warn, Kind: api.KindVuln, Swarm: "prod", Service: "db", Message: "database inside", Exposure: exposure.Internal},
	}
	s := &Server{cfg: cfg, firstSeen: loadFirstSeen(t.TempDir()), updates: loadUpdateLog(t.TempDir()), updated: now,
		snaps: []*swarm.Snapshot{{Name: "prod"}}, findings: findings, seen: map[string]time.Time{}}
	body := get(t, s.routes(), "/", "").Body.String()

	internet := strings.Index(body, `class="crit">2 on the internet`)
	host := strings.Index(body, `class="crit">1 on the host`)
	home := strings.Index(body, `class="dim">2 not on the internet`)
	if internet < 0 || host < internet || home < host {
		t.Fatalf("summary order internet=%d host=%d home=%d\n%s", internet, host, home, body)
	}
	internetHead := strings.Index(body, `<div class="group crit">on the internet</div>`)
	hostHead := strings.Index(body, `<div class="group crit">on the host</div>`)
	homeHead := strings.Index(body, `<div class="group dim">not on the internet</div>`)
	at := func(s string) int { return strings.Index(body, s) }
	if internetHead < 0 || hostHead < internetHead || homeHead < hostHead {
		t.Fatalf("group headings internet=%d host=%d home=%d", internetHead, hostHead, homeHead)
	}
	if at("kavita public") < internetHead || at("kavita public") > hostHead ||
		at("speedtest behind login") < internetHead || at("speedtest behind login") > hostHead {
		t.Fatal("a public finding is outside the internet group")
	}
	if at("disk full") < hostHead || at("disk full") > homeHead {
		t.Fatal("the disk finding is outside the host group")
	}
	if at("seerr at home") < homeHead || at("database inside") < homeHead {
		t.Fatal("a home-only finding is outside the last group")
	}
	if !strings.Contains(body, "<title>swarmwatch · crit</title>") {
		t.Fatal("overall status no longer follows the worst finding")
	}
}
