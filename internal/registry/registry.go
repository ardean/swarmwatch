// Package registry compares a running image digest with the registry's current one.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	StateCurrent  = "current"
	StateOutdated = "outdated"
	StateUnknown  = "unknown"
)

type Result struct {
	State  string `json:"state"`
	Remote string `json:"remote_digest,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Client struct {
	http   *http.Client
	mu     sync.Mutex
	tokens map[string]string
	auth   map[string]string // registry host -> base64 "user:password"
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 20 * time.Second}, tokens: map[string]string{}, auth: map[string]string{}}
}

// AddDockerConfig reads inline credentials from a docker config.json. They stay in memory.
// Entries that rely on a credential helper have no inline auth and are skipped.
func (c *Client) AddDockerConfig(b []byte) {
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range cfg.Auths {
		if v.Auth == "" {
			continue
		}
		k = strings.TrimPrefix(strings.TrimPrefix(k, "https://"), "http://")
		k, _, _ = strings.Cut(k, "/")
		if k == "docker.io" || k == "index.docker.io" {
			k = "registry-1.docker.io"
		}
		if _, ok := c.auth[k]; !ok {
			c.auth[k] = v.Auth
		}
	}
}

var accept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

// Check reports whether the tag in image now points at a different image than running.
//
// Official images are a multi-arch index. Registries republish that index (new attestations)
// without changing the per-platform image, and a service often stores the index digest from
// the day it was deployed. Those two index digests differ while the image this machine runs
// is the same. The platform manifest inside the index is what gets compared.
func (c *Client) Check(ctx context.Context, image, running string) Result {
	if running == "" {
		return Result{State: StateUnknown, Reason: "running digest unknown"}
	}
	host, repo, tag := ParseRef(image)
	remote, err := c.fetch(ctx, host, repo, tag, false)
	if err != nil {
		return Result{State: StateUnknown, Reason: err.Error()}
	}
	if remote.digest == running {
		return Result{State: StateCurrent, Remote: remote.digest}
	}
	same, err := c.samePlatform(ctx, host, repo, remote.digest, running)
	if err != nil {
		// The digests differ and the index could not be read. Unknown, not outdated:
		// an updater must not roll a service it could not compare.
		return Result{State: StateUnknown, Reason: err.Error()}
	}
	if same {
		return Result{State: StateCurrent, Remote: remote.digest}
	}
	return Result{State: StateOutdated, Remote: remote.digest}
}

// samePlatform reports whether tagDigest and running name the same image for this
// machine. A single-manifest image has no platform list, so only an equal digest
// (already handled by Check) counts. An error means the registry could not be read.
func (c *Client) samePlatform(ctx context.Context, host, repo, tagDigest, running string) (bool, error) {
	tag, err := c.fetch(ctx, host, repo, tagDigest, true)
	if err != nil {
		return false, err
	}
	want := platformDigest(tag.mediaType, tag.body, runtime.GOOS, runtime.GOARCH)
	if want == "" {
		return false, nil
	}
	if want == running {
		return true, nil
	}
	have, err := c.fetch(ctx, host, repo, running, true)
	if err != nil {
		return false, err
	}
	// A service may store the index digest. A single manifest's own digest is itself.
	got := platformDigest(have.mediaType, have.body, runtime.GOOS, runtime.GOARCH)
	if got == "" {
		got = running
	}
	return got == want, nil
}

// platformDigest is the manifest in an index that this OS and arch would run.
// A non-index, or an index with no such manifest, returns "".
func platformDigest(mediaType string, body []byte, goos, goarch string) string {
	if !isIndex(mediaType) {
		return ""
	}
	var idx struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant"`
			} `json:"platform"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if json.Unmarshal(body, &idx) != nil {
		return ""
	}
	for _, m := range idx.Manifests {
		if m.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		if m.Platform.OS != goos || m.Platform.Architecture != goarch {
			continue
		}
		if goarch == "arm64" && m.Platform.Variant != "" && m.Platform.Variant != "v8" {
			continue
		}
		if goarch == "arm" && m.Platform.Variant != "" && m.Platform.Variant != "v7" {
			continue
		}
		return m.Digest
	}
	return ""
}

func isIndex(mediaType string) bool {
	mt := strings.ToLower(mediaType)
	return strings.Contains(mt, "image.index") || strings.Contains(mt, "manifest.list")
}

// ParseRef splits an image reference into registry host, repository and tag.
func ParseRef(ref string) (host, repo, tag string) {
	tag = "latest"
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		tag = ref[i+1:]
		ref = ref[:i]
	}
	host, repo = "registry-1.docker.io", ref
	if i := strings.Index(ref, "/"); i >= 0 {
		if first := ref[:i]; strings.ContainsAny(first, ".:") || first == "localhost" {
			host, repo = first, ref[i+1:]
			if host == "docker.io" || host == "index.docker.io" {
				host = "registry-1.docker.io"
			}
		}
	}
	if host == "registry-1.docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	return host, repo, tag
}

type fetched struct {
	digest    string
	mediaType string
	body      []byte
}

// fetch reads one manifest. ref is a tag or a digest. withBody uses GET; a HEAD is enough
// when only the digest is needed.
func (c *Client) fetch(ctx context.Context, host, repo, ref string, withBody bool) (fetched, error) {
	u := fmt.Sprintf("https://%s/v2/%s/manifests/%s", host, repo, ref)
	method := http.MethodHead
	if withBody {
		method = http.MethodGet
	}
	token := c.cachedToken(host + "|" + repo)
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			return fetched{}, err
		}
		req.Header.Set("Accept", accept)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return fetched{}, fmt.Errorf("registry %s: %w", host, err)
		}
		var body []byte
		if withBody {
			body, err = io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		}
		resp.Body.Close()
		if err != nil {
			return fetched{}, fmt.Errorf("registry %s: %w", host, err)
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			d := resp.Header.Get("Docker-Content-Digest")
			if d == "" {
				return fetched{}, fmt.Errorf("registry %s sent no digest", host)
			}
			return fetched{digest: d, mediaType: resp.Header.Get("Content-Type"), body: body}, nil
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			token, err = c.fetchToken(ctx, resp.Header.Get("Www-Authenticate"), host, repo)
			if err != nil {
				return fetched{}, err
			}
			c.mu.Lock()
			c.tokens[host+"|"+repo] = token
			c.mu.Unlock()
		case resp.StatusCode == http.StatusUnauthorized:
			return fetched{}, fmt.Errorf("private or unauthenticated (401)")
		default:
			return fetched{}, fmt.Errorf("registry %s: HTTP %d", host, resp.StatusCode)
		}
	}
	return fetched{}, fmt.Errorf("registry %s: auth failed", host)
}

func (c *Client) cachedToken(key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tokens[key]
}

var authParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

func (c *Client) fetchToken(ctx context.Context, header, host, repo string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return "", fmt.Errorf("unsupported registry auth %q", header)
	}
	p := map[string]string{}
	for _, m := range authParam.FindAllStringSubmatch(header, -1) {
		p[m[1]] = m[2]
	}
	if p["realm"] == "" {
		return "", fmt.Errorf("registry auth has no realm")
	}
	scope := p["scope"]
	if scope == "" {
		scope = "repository:" + repo + ":pull"
	}
	q := url.Values{"service": {p["service"]}, "scope": {scope}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p["realm"]+"?"+q.Encode(), nil)
	c.mu.Lock()
	basic := c.auth[host]
	c.mu.Unlock()
	if basic != "" {
		req.Header.Set("Authorization", "Basic "+basic)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token: HTTP %d (private image?)", resp.StatusCode)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	if t.Token != "" {
		return t.Token, nil
	}
	return t.AccessToken, nil
}
