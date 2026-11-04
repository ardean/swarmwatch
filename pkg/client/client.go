// Package client is a small typed client for the swarmwatch HTTP API, version 1.
//
//	c := client.New("http://swarmwatch:8590", token)
//	sum, err := c.Summary(ctx)
//
// The token is sent as a bearer token on every request. Use https, or a network you trust, when the
// token has to cross one: it travels in clear text over plain http.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ardean/swarmwatch/pkg/api"
)

// maxBody caps what the client reads from a response, so a wrong or hostile server cannot exhaust memory.
const maxBody = 64 << 20

// Client talks to one swarmwatch instance.
type Client struct {
	base  string
	token string
	// HTTP is the client used for requests. Replace it to set a transport, proxy or timeout; the default
	// has a timeout of 15 seconds.
	HTTP *http.Client
}

// New returns a client for the instance at baseURL, for example "http://swarmwatch:8590". The token may
// be empty when the instance has none.
func New(baseURL, token string) *Client {
	return &Client{base: strings.TrimRight(baseURL, "/"), token: token, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// StatusError is returned for a response with a status other than 200.
type StatusError struct {
	Code    int
	Message string // the "error" field of the response body, when it has one
}

func (e *StatusError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("swarmwatch: %d %s: %s", e.Code, http.StatusText(e.Code), e.Message)
	}
	return fmt.Sprintf("swarmwatch: %d %s", e.Code, http.StatusText(e.Code))
}

// IsNotFound reports whether err is a 404, for example a service that does not exist or an image that
// has not been scanned yet.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}

// FindingsQuery narrows the findings. Empty fields do not filter.
type FindingsQuery struct {
	MinLevel string // info, warn or crit
	Swarm    string
	Stack    string
	Service  string
	Kind     string
}

// Findings returns what needs attention. The status of the result covers the findings returned.
func (c *Client) Findings(ctx context.Context, q FindingsQuery) (*api.Findings, error) {
	v := url.Values{}
	for k, val := range map[string]string{"min_level": q.MinLevel, "swarm": q.Swarm, "stack": q.Stack,
		"service": q.Service, "kind": q.Kind} {
		if val != "" {
			v.Set(k, val)
		}
	}
	var out api.Findings
	return &out, c.get(ctx, "/api/v1/findings", v, &out)
}

// Summary returns the overall status and the counts, a small response meant for polling.
func (c *Client) Summary(ctx context.Context) (*api.Summary, error) {
	var out api.Summary
	return &out, c.get(ctx, "/api/v1/summary", nil, &out)
}

// Vulns returns every vulnerability of the image of one service.
func (c *Client) Vulns(ctx context.Context, swarm, service string) (*api.Vulns, error) {
	var out api.Vulns
	return &out, c.get(ctx, "/api/v1/vulns", url.Values{"swarm": {swarm}, "service": {service}}, &out)
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		se := &StatusError{Code: resp.StatusCode}
		var e api.Error
		if json.Unmarshal(body, &e) == nil {
			se.Message = e.Error
		}
		return se
	}
	return json.Unmarshal(body, out)
}
