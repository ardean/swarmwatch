// Package registry compares a running image digest with the registry's current one.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
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

// Check reports whether the tag in image now points at a different digest than running.
func (c *Client) Check(ctx context.Context, image, running string) Result {
	if running == "" {
		return Result{State: StateUnknown, Reason: "running digest unknown"}
	}
	host, repo, tag := ParseRef(image)
	remote, err := c.digest(ctx, host, repo, tag)
	if err != nil {
		return Result{State: StateUnknown, Reason: err.Error()}
	}
	if remote == running {
		return Result{State: StateCurrent, Remote: remote}
	}
	return Result{State: StateOutdated, Remote: remote}
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

func (c *Client) digest(ctx context.Context, host, repo, tag string) (string, error) {
	u := fmt.Sprintf("https://%s/v2/%s/manifests/%s", host, repo, tag)
	token := c.cachedToken(host + "|" + repo)
	for attempt := 0; attempt < 2; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
		req.Header.Set("Accept", accept)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return "", fmt.Errorf("registry %s: %w", host, err)
		}
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			d := resp.Header.Get("Docker-Content-Digest")
			if d == "" {
				return "", fmt.Errorf("registry %s sent no digest", host)
			}
			return d, nil
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			token, err = c.fetchToken(ctx, resp.Header.Get("Www-Authenticate"), host, repo)
			if err != nil {
				return "", err
			}
			c.mu.Lock()
			c.tokens[host+"|"+repo] = token
			c.mu.Unlock()
		case resp.StatusCode == http.StatusUnauthorized:
			return "", fmt.Errorf("private or unauthenticated (401)")
		default:
			return "", fmt.Errorf("registry %s: HTTP %d", host, resp.StatusCode)
		}
	}
	return "", fmt.Errorf("registry %s: auth failed", host)
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
