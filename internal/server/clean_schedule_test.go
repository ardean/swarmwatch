package server

import (
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/swarm"
)

func TestPickCleanKeepsWhatIsYoungOrOfUnknownAge(t *testing.T) {
	now := time.Date(2026, 11, 4, 3, 30, 0, 0, time.UTC)
	u := &swarm.Unused{
		Images: []swarm.UnusedImage{
			{ID: "old", Created: now.Add(-8 * 24 * time.Hour)},
			{ID: "edge", Created: now.Add(-7 * 24 * time.Hour)},
			{ID: "young", Created: now.Add(-6 * 24 * time.Hour)},
			{ID: "unknown"},
		},
		Containers: []swarm.StoppedContainer{
			{ID: "c-old", Created: now.Add(-30 * time.Hour)},
			{ID: "c-young", Created: now.Add(-2 * time.Hour)},
			{ID: "c-unknown"},
		},
	}
	images, containers := pickClean(u, now, 7*24*time.Hour, 24*time.Hour)
	if got := len(images); got != 2 || images[0] != "old" || images[1] != "edge" {
		t.Errorf("images = %v; want old and edge (young and unknown stay)", images)
	}
	if len(containers) != 1 || containers[0] != "c-old" {
		t.Errorf("containers = %v; want c-old only", containers)
	}
	if i, c := pickClean(nil, now, time.Hour, time.Hour); i != nil || c != nil {
		t.Error("nothing known means nothing removed")
	}
}
