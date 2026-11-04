package swarm

import "testing"

func TestParseSize(t *testing.T) {
	mib, gib := float64(1<<20), float64(1<<30) // variables: constant float->uint64 conversion would not compile
	for in, want := range map[string]uint64{
		"73.36MiB": uint64(73.36 * mib), "31.1GiB": uint64(31.1 * gib),
		"0B": 0, "1kB": 1000, "2MB": 2000000, "bogus": 0,
	} {
		if got := parseSize(in); got != want {
			t.Errorf("parseSize(%q) = %d; want %d", in, got, want)
		}
	}
}

func TestParseHostStripsRoot(t *testing.T) {
	out := []byte(`##load
0.5 0.4 0.3 1/200 1
##uptime
86400.5
##mem
MemTotal:       1000 kB
MemAvailable:    250 kB
##cpus
4
##df
/dev/sda1 1000 900 100 90% /host
/dev/sdb1 2000 500 1500 25% /host/mnt/data
`)
	h := parseHost(out, "/host")
	if h.CPUs != 4 || h.MemTotal != 1000*1024 || h.MemUsedPercent() != 75 {
		t.Errorf("host basics wrong: %+v", h)
	}
	if len(h.Disks) != 2 || h.Disks[0].Mount != "/" || h.Disks[1].Mount != "/mnt/data" {
		t.Fatalf("disks = %+v", h.Disks)
	}
	if p := h.Disks[0].Percent; p != 90 {
		t.Errorf("percent = %v", p)
	}
}

func TestParseServicesSplitsDigest(t *testing.T) {
	inspect := []byte(`[{"Spec":{"Name":"web_app","Labels":{"com.docker.stack.namespace":"web"},
		"TaskTemplate":{"ContainerSpec":{"Image":"traefik:v3.7@sha256:aaa"}}}}]`)
	ls := []byte(`{"Name":"web_app","Replicas":"1/2"}` + "\n")
	svcs := parseServices(ls, inspect)
	if len(svcs) != 1 {
		t.Fatalf("got %d services", len(svcs))
	}
	s := svcs[0]
	if s.Stack != "web" || s.Image != "traefik:v3.7" || s.Digest != "sha256:aaa" || s.Running != 1 || s.Desired != 2 {
		t.Errorf("service = %+v", s)
	}
}

func TestApplyTasksCountsOnlyRecentFailures(t *testing.T) {
	svc := &Service{Name: "web_app"}
	out := []byte(`{"Name":"web_app.1","CurrentState":"Failed 3 minutes ago"}
{"Name":"web_app.1","CurrentState":"Failed 2 days ago"}
{"Name":"web_app.1","CurrentState":"Running 5 hours ago"}
{"Name":"web_app.1","CurrentState":"Rejected about an hour ago"}
`)
	applyTasks(map[string]*Service{"web_app": svc}, out)
	if svc.RecentFailures != 2 {
		t.Errorf("RecentFailures = %d; want 2", svc.RecentFailures)
	}
}

func TestContainerDigests(t *testing.T) {
	got := containerDigests([]byte("c1\timgA\nc2\timgB\n"), []byte("imgA\tsha256:111\nimgB\t<none>\n"))
	if got["c1"] != "sha256:111" || got["c2"] != "" {
		t.Errorf("digests = %v", got)
	}
}

func TestParseContainerPorts(t *testing.T) {
	got := parseContainerPorts("0.0.0.0:8096->8096/tcp, [::]:8096->8096/tcp, 127.0.0.1:5432->5432/tcp, 8920/tcp")
	if len(got) != 1 || got[0].Published != 8096 || got[0].Target != 8096 {
		t.Errorf("ports = %+v", got)
	}
}
