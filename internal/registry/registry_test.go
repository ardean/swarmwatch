package registry

import "testing"

func TestParseRef(t *testing.T) {
	for _, c := range []struct{ ref, host, repo, tag string }{
		{"traefik:v3.7", "registry-1.docker.io", "library/traefik", "v3.7"},
		{"traefik:v3.7@sha256:abc", "registry-1.docker.io", "library/traefik", "v3.7"},
		{"lissy93/dashy:latest", "registry-1.docker.io", "lissy93/dashy", "latest"},
		{"redis", "registry-1.docker.io", "library/redis", "latest"},
		{"ghcr.io/ardean/swarmwatch:latest", "ghcr.io", "ardean/swarmwatch", "latest"},
		{"docker.io/valkey/valkey:9", "registry-1.docker.io", "valkey/valkey", "9"},
		{"lscr.io/linuxserver/bazarr", "lscr.io", "linuxserver/bazarr", "latest"},
		{"localhost:5000/app:1", "localhost:5000", "app", "1"},
	} {
		host, repo, tag := ParseRef(c.ref)
		if host != c.host || repo != c.repo || tag != c.tag {
			t.Errorf("ParseRef(%q) = %q %q %q; want %q %q %q", c.ref, host, repo, tag, c.host, c.repo, c.tag)
		}
	}
}

func TestAddDockerConfig(t *testing.T) {
	c := New()
	c.AddDockerConfig([]byte(`{"auths":{"https://index.docker.io/v1/":{"auth":"a"},"ghcr.io":{"auth":"b"},"x.io":{}}}`))
	if c.auth["registry-1.docker.io"] != "a" || c.auth["ghcr.io"] != "b" || len(c.auth) != 2 {
		t.Errorf("unexpected auth map %v", c.auth)
	}
}
