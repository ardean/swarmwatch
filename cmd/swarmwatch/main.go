// swarmwatch: read-only overview of Docker Swarms — what runs, what is
// outdated or vulnerable, and how many resources it uses.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ardean/swarmwatch/internal/config"
	"github.com/ardean/swarmwatch/internal/report"
	"github.com/ardean/swarmwatch/internal/server"
	"github.com/ardean/swarmwatch/internal/swarm"
	"github.com/ardean/swarmwatch/internal/version"
	"github.com/ardean/swarmwatch/internal/vuln"
	"github.com/ardean/swarmwatch/internal/watch"
)

const usage = `swarmwatch — read-only Docker Swarm overview

usage: swarmwatch [command] [flags]

commands:
  overview   swarms, stacks, resources, outdated images, vulnerabilities (default)
  check      only what needs attention; exit 0 ok, 1 warnings, 2 critical
  scan       run Trivy on each swarm's images and cache the results
  serve      run as a service: web overview, JSON API, scheduled refresh and scans
  version    print the version

flags (all commands):
  -config PATH   config file (default $SWARMWATCH_CONFIG or ~/.config/swarmwatch/config.yaml)
  -swarm NAMES   comma-separated swarm names to include
  -json          machine-readable output (overview)
  -offline       skip registry lookups for outdated images
  -no-color      plain output
  -force         scan: rescan even if cached results are fresh

Inside a container, set SWARMWATCH_NAME (and optionally SWARMWATCH_HOST_ROOT,
SWARMWATCH_DISKS, SWARMWATCH_LISTEN, SWARMWATCH_TOKEN or SWARMWATCH_TOKEN_FILE,
SWARMWATCH_DISABLE_UI, SWARMWATCH_SCAN_WINDOW) instead of using a config file.
`

func main() {
	args := os.Args[1:]
	cmd := "overview"
	if len(args) > 0 && (args[0] == "--version" || args[0] == "-version") {
		args[0] = "version"
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "help":
		fmt.Print(usage)
		return
	case "version":
		fmt.Println("swarmwatch", version.Version)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	cfgPath := fs.String("config", config.DefaultPath(), "")
	swarmsF := fs.String("swarm", "", "")
	asJSON := fs.Bool("json", false, "")
	offline := fs.Bool("offline", false, "")
	noColor := fs.Bool("no-color", false, "")
	force := fs.Bool("force", false, "")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}
	cfg.Swarms = filterSwarms(cfg.Swarms, *swarmsF)
	if len(cfg.Swarms) == 0 {
		fatal(fmt.Errorf("no swarms match -swarm %q", *swarmsF))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p := report.Printer{W: os.Stdout, Color: !*noColor && isTTY()}
	cache := vuln.LoadCache(config.CacheDir())

	switch cmd {
	case "overview", "check":
		var checker *watch.Checker
		if !*offline {
			checker = watch.NewChecker(0)
		}
		snaps := watch.Gather(ctx, cfg, cache, checker, nil)
		findings := watch.Findings(cfg, snaps)
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(snaps)
		} else if cmd == "check" {
			p.Findings(findings)
		} else {
			p.Overview(snaps, findings)
		}
		os.Exit(exitCode(findings))
	case "scan":
		snaps := watch.Gather(ctx, cfg, cache, nil, nil)
		for _, s := range snaps {
			if s.Err != "" {
				fmt.Fprintf(os.Stderr, "%s: skipped, %s\n", s.Name, s.Err)
			}
		}
		watch.ScanStale(ctx, cfg, snaps, cache, *force, func(e watch.Event) {
			if e.Err != nil {
				fmt.Fprintf(os.Stderr, "%s [%d/%d] %s: %v\n", e.Swarm, e.Done, e.Total, e.Image, e.Err)
				return
			}
			fmt.Fprintf(os.Stderr, "%s [%d/%d] %s: %d finding(s), %d critical fixable\n",
				e.Swarm, e.Done, e.Total, e.Image, e.Summary.Total(), e.Summary.Fixable["CRITICAL"])
		})
	case "serve":
		if err := server.New(cfg, cache).Run(ctx); err != nil {
			fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(64)
	}
}

func exitCode(fs []swarm.Finding) int {
	code := 0
	for _, f := range fs {
		switch f.Level {
		case swarm.Crit:
			return 2
		case swarm.Warn:
			code = 1
		}
	}
	return code
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "swarmwatch:", err)
	os.Exit(1)
}

func isTTY() bool {
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == ""
}

func filterSwarms(ss []config.Swarm, names string) []config.Swarm {
	if names == "" {
		return ss
	}
	want := map[string]bool{}
	for _, n := range strings.Split(names, ",") {
		want[strings.TrimSpace(n)] = true
	}
	var out []config.Swarm
	for _, s := range ss {
		if want[s.Name] {
			out = append(out, s)
		}
	}
	return out
}
