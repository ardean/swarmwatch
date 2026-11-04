// Package sshx runs shell snippets on a host over ssh (or locally).
package sshx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Runner struct {
	Dest string // "" or "local" runs on this machine
}

func (r Runner) Local() bool { return r.Dest == "" || r.Dest == "local" }

// Run executes script and returns stdout. stderr is folded into the error.
func (r Runner) Run(ctx context.Context, script string) ([]byte, error) {
	var cmd *exec.Cmd
	if r.Local() {
		cmd = exec.CommandContext(ctx, "sh", "-c", script)
	} else {
		dir := filepath.Join(os.TempDir(), fmt.Sprintf("swarmwatch-%d", os.Getuid()))
		_ = os.MkdirAll(dir, 0o700)
		cmd = exec.CommandContext(ctx, "ssh",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=10",
			"-o", "ControlMaster=auto",
			"-o", "ControlPath="+filepath.Join(dir, "%C"),
			"-o", "ControlPersist=120",
			// always a POSIX shell: the login shell may be zsh, which aborts on unmatched globs
			r.Dest, "sh -c "+Quote(script))
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.Bytes(), fmt.Errorf("%s: %s", r.Dest, msg)
	}
	return out.Bytes(), nil
}

// Quote single-quotes s for a POSIX shell.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
