package update

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ardean/swarmwatch/internal/registry"
	"github.com/ardean/swarmwatch/internal/sshx"
	"github.com/ardean/swarmwatch/internal/swarm"
)

// Service labels read by the updater. The dockupdater.* names are the labels of the tool this replaces
// and are accepted so existing stack files keep working.
const (
	LabelUpdate = "swarmwatch.update" // "false": never. "night": only the night schedule. Empty: the fast schedule.
	LabelThen   = "swarmwatch.then"   // services to restart after this one was updated, comma separated
	LabelWait   = "swarmwatch.wait"   // seconds to wait after updating this service, before the restarts and the next service

	legacyDisable = "dockupdater.disable"
	legacyThen    = "dockupdater.starts"
	legacyWait    = "dockupdater.wait"
)

var (
	serviceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	imageRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`)
	// digestRe is a sha256 manifest or index digest, the form Docker accepts after @.
	digestRe = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)
)

// Target is one service to roll to the newest image behind its tag.
type Target struct {
	Swarm   string
	Service string
	Image   string        // name:tag, as the service runs it
	Digest  string        // the registry digest it is rolled to; a failed attempt is remembered by it
	Then    []string      // services to restart afterwards
	Wait    time.Duration // wait after the update; zero means the run's default pause
}

// Result is what happened to one service.
type Result struct {
	Time       time.Time `json:"time"`
	Swarm      string    `json:"swarm"`
	Service    string    `json:"service"`
	Image      string    `json:"image"`
	Digest     string    `json:"digest,omitempty"`  // registry digest the update went to
	Restart    bool      `json:"restart,omitempty"` // a restart after another update, not an image update
	OK         bool      `json:"ok"`
	RolledBack bool      `json:"rolled_back,omitempty"`
	Message    string    `json:"message,omitempty"`
	Manual     bool      `json:"manual,omitempty"` // started from the page, not by the schedule
	Seconds    int       `json:"seconds"`
}

// Runner runs a shell snippet on the manager; sshx.Runner is the real one.
type Runner interface {
	Run(ctx context.Context, script string) ([]byte, error)
}

// Options tunes a run.
type Options struct {
	Pause   time.Duration // wait between services (default 60s)
	Timeout time.Duration // per service (default 15m)
	Manual  bool
	// Sleep waits d or until ctx ends; nil uses real time. Tests replace it.
	Sleep func(ctx context.Context, d time.Duration)
}

// Excluded explains why a service is never updated, even when its image is outdated.
// "" means the schedule and the button may roll it once the tag moves.
func Excluded(v *swarm.Service, self string) string {
	switch {
	case v.Standalone():
		return "not a swarm service"
	case self != "" && v.Name == self:
		return "swarmwatch cannot update itself"
	case strings.EqualFold(v.Labels[LabelUpdate], "false") || strings.EqualFold(v.Labels[legacyDisable], "true"):
		return "excluded by label"
	case !serviceRe.MatchString(v.Name) || !imageRe.MatchString(v.Image):
		return "unusual service or image name"
	}
	return ""
}

// Skipped explains why a service is not updated right now, or "" when it is eligible.
func Skipped(v *swarm.Service, self string) string {
	if why := Excluded(v, self); why != "" {
		return why
	}
	if v.Update == nil || v.Update.State != registry.StateOutdated {
		return "up to date"
	}
	return ""
}

// Night reports whether this service waits for the night schedule instead of the fast one.
func Night(v *swarm.Service) bool {
	return v != nil && strings.EqualFold(v.Labels[LabelUpdate], "night")
}

// Plan lists the services of a snapshot that have a newer image behind their tag and may be updated
// by the fast schedule or the button. A service labeled night is left for PlanNight.
// self is the name of the swarm service swarmwatch itself runs as ("" if unknown). A zero Target.Wait
// means "the run's pause".
func Plan(s *swarm.Snapshot, self string) []Target {
	return plan(s, self, false)
}

// PlanNight lists outdated services labeled night. The fast schedule and the button do not roll these.
func PlanNight(s *swarm.Snapshot, self string) []Target {
	return plan(s, self, true)
}

func plan(s *swarm.Snapshot, self string, night bool) []Target {
	var out []Target
	for _, v := range s.Services {
		if Night(v) != night || Skipped(v, self) != "" {
			continue
		}
		t := Target{Swarm: s.Name, Service: v.Name, Image: v.Image, Digest: v.Update.Remote}
		for _, name := range strings.Split(first(v.Labels[LabelThen], v.Labels[legacyThen]), ",") {
			if name = strings.TrimSpace(name); serviceRe.MatchString(name) && name != v.Name {
				t.Then = append(t.Then, name)
			}
		}
		if w := first(v.Labels[LabelWait], v.Labels[legacyWait]); w != "" {
			if sec, err := strconv.Atoi(w); err == nil && sec >= 0 {
				t.Wait = time.Duration(sec) * time.Second
			}
		}
		out = append(out, t)
	}
	return out
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Self returns the swarm service the running process belongs to, read from its own container's labels.
// It is empty when not running in a container of a service.
func Self(ctx context.Context, r Runner) string {
	out, err := r.Run(ctx, `docker inspect "$(hostname)" --format '{{index .Config.Labels "com.docker.swarm.service.name"}}' 2>/dev/null`)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Run updates the targets one after the other. A service that fails to update is rolled back and the
// run goes on with the next one. on is called after each step.
func Run(ctx context.Context, r Runner, targets []Target, o Options, on func(Result)) {
	if o.Pause == 0 {
		o.Pause = 60 * time.Second
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Minute
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	for i, t := range targets {
		if ctx.Err() != nil {
			return
		}
		res := updateOne(ctx, r, t, o)
		on(res)
		if !res.OK {
			continue
		}
		last := i == len(targets)-1
		if len(t.Then) == 0 && last {
			continue
		}
		wait := t.Wait
		if wait == 0 {
			wait = o.Pause
		}
		o.Sleep(ctx, wait)
		for _, name := range t.Then {
			if ctx.Err() != nil {
				return
			}
			on(restartOne(ctx, r, t.Swarm, name, o))
		}
	}
}

func updateOne(ctx context.Context, r Runner, t Target, o Options) Result {
	start := time.Now()
	res := Result{Time: start, Swarm: t.Swarm, Service: t.Service, Image: t.Image, Digest: t.Digest, Manual: o.Manual}
	cctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	// Not --update-failure-action rollback: that would change the service's own update policy for good.
	// A failed update leaves the service paused; it is rolled back explicitly below.
	// imageRef pins the digest. A bare tag is a no-op when the service already uses that tag:
	// Docker leaves the old task running and exits 0.
	_, err := r.Run(cctx, "docker service update --with-registry-auth --detach=false --image "+sshx.Quote(imageRef(t.Image, t.Digest))+" "+sshx.Quote(t.Service))
	if err != nil {
		res.Message = tail(err.Error())
		if _, rerr := r.Run(ctx, "docker service rollback --detach=false "+sshx.Quote(t.Service)); rerr == nil {
			res.RolledBack = true
			res.Message += " (rolled back)"
		} else {
			res.Message += " (rollback failed: " + tail(rerr.Error()) + ")"
		}
	} else {
		res.OK = true
	}
	res.Seconds = int(time.Since(start).Seconds())
	return res
}

func restartOne(ctx context.Context, r Runner, swarmName, service string, o Options) Result {
	start := time.Now()
	res := Result{Time: start, Swarm: swarmName, Service: service, Restart: true, Manual: o.Manual}
	cctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	if _, err := r.Run(cctx, "docker service update --force --detach=false "+sshx.Quote(service)); err != nil {
		res.Message = tail(err.Error())
	} else {
		res.OK = true
	}
	res.Seconds = int(time.Since(start).Seconds())
	return res
}

// imageRef is the --image value. With a sha256 digest it is tag@digest, so the service spec
// changes and Docker pulls. Anything else (no digest, or the image is already pinned) stays the tag.
func imageRef(image, digest string) string {
	if !digestRe.MatchString(digest) || strings.Contains(image, "@") {
		return image
	}
	return image + "@" + digest
}

// tail keeps the end of a command's error text, where docker puts the reason.
func tail(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 && len(s)-i < 300 {
		s = strings.TrimSpace(s[i+1:])
	}
	if len(s) > 300 {
		s = "…" + s[len(s)-300:]
	}
	return s
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// String summarises a result for logs.
func (r Result) String() string {
	what := "update"
	if r.Restart {
		what = "restart"
	}
	state := "ok"
	if !r.OK {
		state = "FAILED: " + r.Message
	}
	return fmt.Sprintf("%s %s/%s %s (%ds)", what, r.Swarm, r.Service, state, r.Seconds)
}
