package registry

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
)

func TestPlatformDigestSkipsAttestations(t *testing.T) {
	body := []byte(`{"manifests":[
		{"digest":"sha256:attest","platform":{"os":"unknown","architecture":"unknown"},"annotations":{"vnd.docker.reference.type":"attestation-manifest"}},
		{"digest":"sha256:arm","platform":{"os":"linux","architecture":"arm64","variant":"v8"}},
		{"digest":"sha256:amd","platform":{"os":"linux","architecture":"amd64"}}
	]}`)
	mt := "application/vnd.oci.image.index.v1+json"
	if got := platformDigest(mt, body, "linux", "amd64"); got != "sha256:amd" {
		t.Fatalf("amd64 = %q", got)
	}
	if got := platformDigest(mt, body, "linux", "arm64"); got != "sha256:arm" {
		t.Fatalf("arm64 = %q", got)
	}
	if got := platformDigest("application/vnd.oci.image.manifest.v1+json", body, "linux", "amd64"); got != "" {
		t.Fatalf("single manifest = %q", got)
	}
}

// A republished index has a new digest and the same linux image. The service stores the old index digest.
func TestRepublishedIndexIsCurrent(t *testing.T) {
	const plat = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	index := fmt.Sprintf(`{"manifests":[
		{"digest":"sha256:attest","platform":{"os":"unknown","architecture":"unknown"},"annotations":{"vnd.docker.reference.type":"attestation-manifest"}},
		{"digest":%q,"platform":{"os":%q,"architecture":%q}}
	]}`, plat, runtime.GOOS, runtime.GOARCH)
	const oldIndex = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const newIndex = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	gets := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		switch {
		case r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/manifests/8.3.13"):
			w.Header().Set("Docker-Content-Digest", newIndex)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/manifests/"+newIndex):
			gets++
			w.Header().Set("Docker-Content-Digest", newIndex)
			_, _ = io.WriteString(w, index)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/manifests/"+oldIndex):
			gets++
			w.Header().Set("Docker-Content-Digest", oldIndex)
			_, _ = io.WriteString(w, index)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := clientFor(t, srv)
	got := c.Check(t.Context(), "mongo:8.3.13", oldIndex)
	if got.State != StateCurrent || got.Remote != newIndex {
		t.Fatalf("republished index: %+v", got)
	}
	if gets != 2 {
		t.Fatalf("GETs = %d, want the new index and the running index", gets)
	}

	got = c.Check(t.Context(), "mongo:8.3.13", plat)
	if got.State != StateCurrent {
		t.Fatalf("running the platform digest: %+v", got)
	}
}

func TestChangedPlatformIsOutdated(t *testing.T) {
	const oldPlat = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const newPlat = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	oldIndex := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	newIndex := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	body := func(plat string) string {
		return fmt.Sprintf(`{"manifests":[{"digest":%q,"platform":{"os":%q,"architecture":%q}}]}`, plat, runtime.GOOS, runtime.GOARCH)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/manifests/7.4.12-alpine") && r.Method == http.MethodHead:
			w.Header().Set("Docker-Content-Digest", newIndex)
		case strings.HasSuffix(r.URL.Path, "/manifests/"+newIndex):
			w.Header().Set("Docker-Content-Digest", newIndex)
			_, _ = io.WriteString(w, body(newPlat))
		case strings.HasSuffix(r.URL.Path, "/manifests/"+oldIndex):
			w.Header().Set("Docker-Content-Digest", oldIndex)
			_, _ = io.WriteString(w, body(oldPlat))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got := clientFor(t, srv).Check(t.Context(), "redis:7.4.12-alpine", oldIndex)
	if got.State != StateOutdated || got.Remote != newIndex {
		t.Fatalf("changed platform: %+v", got)
	}
}

func TestSingleManifestDigestChangeIsOutdated(t *testing.T) {
	const running = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const remote = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.Header().Set("Docker-Content-Digest", remote)
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `{"schemaVersion":2}`)
		}
	}))
	defer srv.Close()
	got := clientFor(t, srv).Check(t.Context(), "ghcr.io/acme/api:prod", running)
	if got.State != StateOutdated || got.Remote != remote {
		t.Fatalf("single manifest: %+v", got)
	}
}

func TestUnreadableIndexIsUnknown(t *testing.T) {
	const running = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const remote = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Docker-Content-Digest", remote)
			return
		}
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer srv.Close()
	got := clientFor(t, srv).Check(t.Context(), "mongo:8.3.13", running)
	if got.State != StateUnknown || got.Reason == "" {
		t.Fatalf("unreadable index: %+v", got)
	}
}

func TestEqualDigestDoesNotFetchTheBody(t *testing.T) {
	const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method %s", r.Method)
		}
		w.Header().Set("Docker-Content-Digest", digest)
	}))
	defer srv.Close()
	got := clientFor(t, srv).Check(t.Context(), "traefik:v3.7.17", digest)
	if got.State != StateCurrent {
		t.Fatalf("%+v", got)
	}
}

func clientFor(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c := New()
	base, _ := url.Parse(srv.URL)
	c.http = &http.Client{Transport: rewriteHost{base: base, next: http.DefaultTransport}}
	return c
}

// rewriteHost sends the registry client at the test server. The client always builds an https URL.
type rewriteHost struct {
	base *url.URL
	next http.RoundTripper
}

func (r rewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = r.base.Scheme
	req.URL.Host = r.base.Host
	return r.next.RoundTrip(req)
}

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
