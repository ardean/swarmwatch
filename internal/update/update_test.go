package update

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/swarm"
)

func svc(name, stack, image, state string, labels map[string]string) *swarm.Service {
	return &swarm.Service{Name: name, Stack: stack, Image: image, Labels: labels, Update: &registry.Result{State: state, Remote: "sha256:" + name}}
}

func TestPlan(t *testing.T) {
	snap := &swarm.Snapshot{Name: "m", Services: []*swarm.Service{
		svc("a_web", "a", "nginx:1", registry.StateOutdated, nil),
		svc("a_cur", "a", "nginx:2", registry.StateCurrent, nil),
		svc("a_unk", "a", "nginx:3", registry.StateUnknown, nil),
		svc("a_off", "a", "nginx:4", registry.StateOutdated, map[string]string{LabelUpdate: "false"}),
		svc("a_old", "a", "nginx:5", registry.StateOutdated, map[string]string{legacyDisable: "true"}),
		svc("sw_sw", "sw", "ghcr.io/ardean/swarmwatch:1", registry.StateOutdated, nil),
		svc("c1", swarm.Standalone, "nginx:6", registry.StateOutdated, nil),
		svc("zigbee_mqtt", "zigbee", "eclipse-mosquitto:2", registry.StateOutdated,
			map[string]string{legacyThen: "zigbee_z2m, bad name;rm", legacyWait: "30"}),
		svc("b_new", "b", "app:1", registry.StateOutdated,
			map[string]string{LabelThen: "b_other", LabelWait: "5", legacyThen: "ignored"}),
		svc("b_evil", "b", "app:1; rm -rf /", registry.StateOutdated, nil),
		svc("a_db", "a", "mongo:8", registry.StateOutdated, map[string]string{LabelUpdate: "night"}),
	}}
	got := Plan(snap, "sw_sw")
	names := []string{}
	for _, g := range got {
		names = append(names, g.Service)
	}
	if want := "a_web zigbee_mqtt b_new"; strings.Join(names, " ") != want {
		t.Fatalf("planned %v; want %s", names, want)
	}
	if Excluded(snap.Services[0], "sw_sw") != "" || Excluded(snap.Services[1], "sw_sw") != "" {
		t.Error("a current image is still watched; only an outdated one is rolled")
	}
	for _, c := range []struct {
		i   int
		why string
	}{
		{3, "excluded by label"}, {4, "excluded by label"}, {5, "swarmwatch cannot update itself"}, {6, "not a swarm service"}, {9, "unusual service or image name"},
	} {
		if got := Excluded(snap.Services[c.i], "sw_sw"); got != c.why {
			t.Errorf("%s excluded = %q, want %q", snap.Services[c.i].Name, got, c.why)
		}
	}
	if got[0].Digest != "sha256:a_web" {
		t.Errorf("target digest = %q; the failed attempt is remembered by it", got[0].Digest)
	}
	if z := got[1]; len(z.Then) != 1 || z.Then[0] != "zigbee_z2m" || z.Wait != 30*time.Second {
		t.Errorf("legacy labels: %+v", z)
	}
	if b := got[2]; len(b.Then) != 1 || b.Then[0] != "b_other" || b.Wait != 5*time.Second {
		t.Errorf("new labels win: %+v", b)
	}
	night := PlanNight(snap, "sw_sw")
	if len(night) != 1 || night[0].Service != "a_db" || night[0].Image != "mongo:8" {
		t.Fatalf("night plan = %+v", night)
	}
}

type fake struct {
	cmds []string
	fail map[string]bool // substring of a command -> fails
}

func (f *fake) Run(_ context.Context, script string) ([]byte, error) {
	f.cmds = append(f.cmds, script)
	for k := range f.fail {
		if strings.Contains(script, k) {
			return nil, errors.New("host: update paused due to failure or early termination of task x\nservice update failed")
		}
	}
	return nil, nil
}

func TestRun(t *testing.T) {
	f := &fake{fail: map[string]bool{"--image 'x:1'": true}}
	var slept []time.Duration
	o := Options{Pause: time.Minute, Sleep: func(_ context.Context, d time.Duration) { slept = append(slept, d) }}
	digest := "sha256:" + strings.Repeat("ab", 32)
	targets := []Target{
		{Swarm: "m", Service: "mqtt", Image: "mosquitto:2", Then: []string{"z2m"}, Wait: 30 * time.Second},
		{Swarm: "m", Service: "bad", Image: "x:1"},
		{Swarm: "m", Service: "web", Image: "nginx:1", Digest: digest},
		{Swarm: "m", Service: "last", Image: "y:1"},
	}
	var res []Result
	Run(context.Background(), f, targets, o, func(r Result) { res = append(res, r) })

	if len(res) != 5 {
		t.Fatalf("%d results: %+v", len(res), res)
	}
	if !res[0].OK || !res[1].Restart || !res[1].OK || res[1].Service != "z2m" {
		t.Errorf("mqtt then z2m: %+v %+v", res[0], res[1])
	}
	if res[2].OK || !res[2].RolledBack || !strings.Contains(res[2].Message, "service update failed") {
		t.Errorf("bad should fail and roll back: %+v", res[2])
	}
	if !res[3].OK || !res[4].OK {
		t.Errorf("run goes on after a failure: %+v %+v", res[3], res[4])
	}
	// 30s after mqtt (own label), none after the failure, a pause after web, none after the last.
	if len(slept) != 2 || slept[0] != 30*time.Second || slept[1] != time.Minute {
		t.Errorf("sleeps = %v", slept)
	}
	want := []string{
		"docker service update --with-registry-auth --detach=false --image 'mosquitto:2' 'mqtt'",
		"docker service update --force --detach=false 'z2m'",
		"docker service update --with-registry-auth --detach=false --image 'x:1' 'bad'",
		"docker service rollback --detach=false 'bad'",
		"docker service update --with-registry-auth --detach=false --image 'nginx:1@" + digest + "' 'web'",
	}
	for i, w := range want {
		if f.cmds[i] != w {
			t.Errorf("cmd %d = %q; want %q", i, f.cmds[i], w)
		}
	}
	for _, c := range f.cmds {
		if strings.Contains(c, "update-failure-action") {
			t.Errorf("must not change the service's update policy: %s", c)
		}
	}
}

func TestBeforeIsPassedThroughAndABadOneIsExcluded(t *testing.T) {
	snap := &swarm.Snapshot{Name: "m", Services: []*swarm.Service{
		svc("a_web", "a", "nginx:1", registry.StateOutdated, map[string]string{LabelBefore: "/usr/local/bin/snap --if-running"}),
		svc("a_bad", "a", "nginx:1", registry.StateOutdated, map[string]string{LabelBefore: "snap; rm -rf /"}),
		svc("a_night", "a", "mongo:8", registry.StateOutdated, map[string]string{LabelUpdate: "night", LabelBefore: "/media/data/docker/bin/immich-snapshot"}),
	}}
	got := Plan(snap, "")
	if len(got) != 1 || got[0].Service != "a_web" || got[0].Before != "/usr/local/bin/snap --if-running" {
		t.Fatalf("plan = %+v", got)
	}
	if why := Excluded(snap.Services[1], ""); why != "before command rejected" {
		t.Fatalf("bad before = %q", why)
	}
	night := PlanNight(snap, "")
	if len(night) != 1 || night[0].Before != "/media/data/docker/bin/immich-snapshot" {
		t.Fatalf("night = %+v", night)
	}
}

func TestBeforeRunsBeforeTheImageAndAFailureSkipsTheRoll(t *testing.T) {
	f := &fake{}
	var res []Result
	Run(context.Background(), f, []Target{{Swarm: "m", Service: "web", Image: "nginx:1", Before: "/opt/snap"}},
		Options{Pause: time.Hour, Sleep: func(context.Context, time.Duration) {}}, func(r Result) { res = append(res, r) })
	if len(f.cmds) != 2 || !strings.Contains(f.cmds[0], "--entrypoint /usr/sbin/chroot") || !strings.Contains(f.cmds[0], "'/opt/snap'") || !strings.HasPrefix(f.cmds[1], "docker service update ") {
		t.Fatalf("cmds = %#v", f.cmds)
	}
	if len(res) != 1 || !res[0].OK {
		t.Fatalf("res = %+v", res)
	}

	f = &fake{fail: map[string]bool{"chroot": true}}
	res = nil
	Run(context.Background(), f, []Target{{Swarm: "m", Service: "web", Image: "nginx:1", Before: "/opt/snap"}},
		Options{Pause: time.Hour, Sleep: func(context.Context, time.Duration) {}}, func(r Result) { res = append(res, r) })
	if len(f.cmds) != 1 || len(res) != 1 || res[0].OK || res[0].RolledBack || !strings.HasPrefix(res[0].Message, "before:") {
		t.Fatalf("failure cmds=%#v res=%+v", f.cmds, res)
	}
}

func TestImageRefPinsADigestAndLeavesAnythingElse(t *testing.T) {
	digest := "sha256:" + strings.Repeat("cd", 32)
	if got := imageRef("nginx:1", digest); got != "nginx:1@"+digest {
		t.Errorf("pin = %q", got)
	}
	if got := imageRef("nginx:1", "sha256:short"); got != "nginx:1" {
		t.Errorf("a short digest must not be pinned, got %q", got)
	}
	if got := imageRef("nginx:1@"+digest, digest); got != "nginx:1@"+digest {
		t.Errorf("an image that is already pinned stays, got %q", got)
	}
	if got := imageRef("nginx:1", ""); got != "nginx:1" {
		t.Errorf("no digest stays the tag, got %q", got)
	}
}
