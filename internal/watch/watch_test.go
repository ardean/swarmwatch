package watch

import (
	"context"
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/swarm"
)

func snapshotOf(image, digest string) []*swarm.Snapshot {
	return []*swarm.Snapshot{{Name: "m", Services: []*swarm.Service{{Name: "web", Image: image, Digest: digest}}}}
}

func TestResetForgetsRememberedRegistryResults(t *testing.T) {
	const image, digest = "registry.invalid/team/web:prod", "sha256:aaa"
	c := NewChecker(time.Hour)
	c.entries[key{image, digest}] = entry{res: &registry.Result{State: registry.StateCurrent}, at: time.Now()}

	snaps := snapshotOf(image, digest)
	c.Apply(context.Background(), snaps)
	if got := snaps[0].Services[0].Update; got == nil || got.State != registry.StateCurrent {
		t.Fatalf("a result within the TTL is reused, got %+v", got)
	}

	c.Reset()
	snaps = snapshotOf(image, digest)
	c.Apply(context.Background(), snaps)
	got := snaps[0].Services[0].Update
	if got == nil || got.State == registry.StateCurrent {
		t.Fatalf("after Reset the registry is asked again (unreachable here), got %+v", got)
	}
}
