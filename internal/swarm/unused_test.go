package swarm

import "testing"

func TestNormalizeRef(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":                                "nginx:latest",
		"nginx:1.27":                           "nginx:1.27",
		"docker.io/library/nginx:1.27":         "nginx:1.27",
		"library/redis":                        "redis:latest",
		"ghcr.io/ardean/swarmwatch:latest":     "ghcr.io/ardean/swarmwatch:latest",
		"nginx:1.27@sha256:abcdef":             "nginx:1.27",
		"localhost:5000/app":                   "localhost:5000/app:latest",
		"registry.example:5000/app:2@sha256:x": "registry.example:5000/app:2",
	} {
		if got := normalizeRef(in); got != want {
			t.Errorf("normalizeRef(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestFindUnused(t *testing.T) {
	const (
		running = "sha256:" + "aaaaaaaaaaaa"
		stopped = "sha256:" + "bbbbbbbbbbbb"
		svcOnly = "sha256:" + "cccccccccccc"
		orphan  = "sha256:" + "dddddddddddd"
		multi   = "sha256:" + "eeeeeeeeeeee"
		dangl   = "sha256:" + "ffffffffffff"
		pinned  = "sha256:" + "999999999999"
	)
	images := []byte(running + "\tapp\t1\t100MB\t2026-11-01 10:00:00 +0100 CET\n" +
		stopped + "\tjob\tv1\t10MB\t2026-11-01 10:00:00 +0100 CET\n" +
		svcOnly + "\tghcr.io/x/web\tlatest\t50MB\t2026-11-01 10:00:00 +0100 CET\n" +
		orphan + "\told\t0.9\t200MB\t2026-01-01 10:00:00 +0100 CET\n" +
		multi + "\tmulti\ta\t20MB\t2026-01-01 10:00:00 +0100 CET\n" +
		multi + "\tmulti\tb\t20MB\t2026-01-01 10:00:00 +0100 CET\n" +
		dangl + "\t<none>\t<none>\t5MB\t2026-01-01 10:00:00 +0100 CET\n" +
		pinned + "\told-ver\t1\t30MB\t2026-01-01 10:00:00 +0100 CET\n")
	ps := []byte("c1\tapp_1\trunning\tUp 2 days\t\tapp:1\t2026-11-01 10:00:00 +0100 CET\n" +
		"c2\tjob-run\texited\tExited (0) 3 days ago\t\tjob:v1\t2026-11-01 10:00:00 +0100 CET\n" +
		"c3\tweb.1.abc\texited\tExited (1)\tweb\tghcr.io/x/web\t2026-11-01 10:00:00 +0100 CET\n" +
		"c4\tnew\tcreated\tCreated\t\tapp:1\t2026-11-01 10:00:00 +0100 CET\n" +
		"c5\told.1.x\texited\tExited (0)\tweb\told-ver:1\t2026-01-01 10:00:00 +0100 CET\n")
	used := []byte("c1\t" + running + "\nc2\t" + stopped + "\nc3\t" + svcOnly + "\nc4\t" + running + "\nc5\t" + pinned + "\n")

	u := findUnused(images, ps, used, []string{"ghcr.io/x/web:latest@sha256:abc"})
	var ids []string
	for _, i := range u.Images {
		ids = append(ids, i.ID)
	}
	want := []string{orphan, multi, dangl, pinned}
	if len(ids) != len(want) || ids[0] != want[0] || ids[1] != want[1] || ids[2] != want[2] || ids[3] != want[3] {
		t.Errorf("unused images = %v; want %v", ids, want)
	}
	if b := u.Images[3].Blockers; len(b) != 1 || b[0] != "c5" {
		t.Errorf("blockers = %v; want the stopped swarm task c5", b)
	}
	if len(u.Images[1].Tags) != 2 {
		t.Errorf("multi-tag image tags = %v", u.Images[1].Tags)
	}
	if u.ImageBytes != 255e6 {
		t.Errorf("bytes = %d", u.ImageBytes)
	}
	// stopped swarm tasks (c3, c5) are swarm's business, not listed as containers
	if len(u.Containers) != 2 || u.Containers[0].ID != "c2" || u.Containers[1].ID != "c4" {
		t.Errorf("containers = %+v", u.Containers)
	}
	if u.Images[0].Created.IsZero() {
		t.Error("created time not parsed")
	}
}

func TestFindUnusedNothing(t *testing.T) {
	if u := findUnused(nil, nil, nil, nil); !u.Empty() {
		t.Errorf("expected empty, got %+v", u)
	}
}

func TestIDRe(t *testing.T) {
	for id, ok := range map[string]bool{
		"sha256:" + "0123456789ab": true,
		"0123456789abcdef":         true,
		"nginx":                    false,
		"abc; rm -rf /":            false,
		"$(id)":                    false,
		"sha256:0123456789ab\nfoo": false,
		"":                         false,
	} {
		if idRe.MatchString(id) != ok {
			t.Errorf("idRe(%q) = %v", id, !ok)
		}
	}
}
