// Package vuln scans images with Trivy and stores the results, one file per image.
package vuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ardean/swarmwatch/internal/sshx"
)

var Severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

// Rank orders severities, higher is worse.
func Rank(sev string) int {
	for i, s := range Severities {
		if s == sev {
			return len(Severities) - i
		}
	}
	return 0
}

// Item is one vulnerability found in an image.
type Item struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Package   string `json:"package"`
	Installed string `json:"installed,omitempty"`
	Fixed     string `json:"fixed,omitempty"`
	Title     string `json:"title,omitempty"`
	URL       string `json:"url,omitempty"`
}

// Link returns a page that explains the vulnerability.
func (i Item) Link() string {
	switch {
	case i.URL != "":
		return i.URL
	case strings.HasPrefix(i.ID, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + i.ID
	case strings.HasPrefix(i.ID, "GHSA-"):
		return "https://github.com/advisories/" + i.ID
	}
	return ""
}

// Summary counts findings per severity; Fixable only counts those with a fixed version.
// Items holds the individual findings; it is kept out of the overview API (see Cache).
type Summary struct {
	Counts    map[string]int `json:"counts"`
	Fixable   map[string]int `json:"fixable"`
	ScannedAt time.Time      `json:"scanned_at"`
	Items     []Item         `json:"-"`
}

func (s *Summary) Total() int {
	n := 0
	for _, v := range s.Counts {
		n += v
	}
	return n
}

// Key identifies an image for caching: digest if known, else the reference.
func Key(image, digest string) string {
	if digest != "" {
		return digest
	}
	return image
}

// ScanRef is the Docker reference Trivy should open. A service updated by digest is stored
// locally as name@digest with the tag removed, so name:tag is not in the daemon. Trivy then
// pulls that tag from the registry and a rate limit fails the scan. The digest form is the
// image that is actually running.
func ScanRef(image, digest string) string {
	if digest == "" {
		return image
	}
	return stripTag(image) + "@" + digest
}

// stripTag drops ":tag" but keeps a registry port ("localhost:5000/name").
func stripTag(image string) string {
	if i := strings.LastIndex(image, ":"); i >= 0 && !strings.Contains(image[i:], "/") {
		return image[:i]
	}
	return image
}

// Cache keeps scan results in memory and persists each image to its own file in dir.
type Cache struct {
	dir  string
	mu   sync.Mutex
	data map[string]*Summary
}

type stored struct {
	Key string `json:"key"`
	*Summary
	Items []Item `json:"items"`
}

func LoadCache(dir string) *Cache {
	c := &Cache{dir: filepath.Join(dir, "vulns"), data: map[string]*Summary{}}
	files, _ := filepath.Glob(filepath.Join(c.dir, "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var st stored
		if json.Unmarshal(b, &st) != nil || st.Summary == nil || st.Key == "" {
			continue
		}
		st.Summary.Items = st.Items
		c.data[st.Key] = st.Summary
	}
	return c
}

func (c *Cache) Get(key string) *Summary {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data[key]
}

func (c *Cache) Put(key string, s *Summary) error {
	c.mu.Lock()
	c.data[key] = s
	c.mu.Unlock()
	b, err := json.Marshal(stored{Key: key, Summary: s, Items: s.Items})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(key))
	path := filepath.Join(c.dir, hex.EncodeToString(sum[:8])+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Scan runs Trivy against ref (from ScanRef: name@digest, or name:tag when no digest is known).
// When running locally with a trivy binary on PATH (the swarmwatch container) it is used directly;
// otherwise Trivy runs as a container on the host.
func Scan(ctx context.Context, r sshx.Runner, trivyImage, image string) (*Summary, error) {
	script := ""
	if _, err := exec.LookPath("trivy"); err == nil && r.Local() {
		// Trivy exports the image from the Docker daemon into the temp directory. In the container /tmp is
		// RAM-backed, so a multi-GB image would exhaust the memory cap and get the whole container OOM-killed;
		// the image sets TMPDIR to disk (/data/tmp). Create it, and drop leftovers of a killed scan.
		script = `t="${TMPDIR:-/tmp}"; mkdir -p "$t"; find "$t" -mindepth 1 -maxdepth 1 -mmin +30 -exec rm -rf {} + 2>/dev/null; ` +
			"trivy image --quiet --format json --scanners vuln --timeout 10m " + sshx.Quote(image)
	} else {
		script = fmt.Sprintf("docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "+
			"-v swarmwatch-trivy:/root/.cache %s image --quiet --format json --scanners vuln --timeout 10m %s",
			sshx.Quote(trivyImage), sshx.Quote(image))
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	out, err := r.Run(ctx, script)
	if err != nil {
		return nil, err
	}
	return parse(out)
}

type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			ID           string `json:"VulnerabilityID"`
			Pkg          string `json:"PkgName"`
			Installed    string `json:"InstalledVersion"`
			Severity     string `json:"Severity"`
			FixedVersion string `json:"FixedVersion"`
			Title        string `json:"Title"`
			Description  string `json:"Description"`
			PrimaryURL   string `json:"PrimaryURL"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func parse(b []byte) (*Summary, error) {
	var rep trivyReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}
	s := &Summary{Counts: map[string]int{}, Fixable: map[string]int{}, ScannedAt: time.Now()}
	seen := map[string]bool{}
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			k := v.ID + "|" + v.Pkg + "|" + v.Installed
			if seen[k] {
				continue
			}
			seen[k] = true
			sev := strings.ToUpper(v.Severity)
			s.Counts[sev]++
			if v.FixedVersion != "" {
				s.Fixable[sev]++
			}
			title := v.Title
			if title == "" {
				title = firstSentence(v.Description, 200)
			}
			s.Items = append(s.Items, Item{
				ID: v.ID, Severity: sev, Package: v.Pkg, Installed: v.Installed,
				Fixed: v.FixedVersion, Title: title, URL: v.PrimaryURL,
			})
		}
	}
	// worst first, fixable before unfixable, then stable by id/package
	sort.SliceStable(s.Items, func(i, j int) bool {
		a, b := s.Items[i], s.Items[j]
		if ra, rb := Rank(a.Severity), Rank(b.Severity); ra != rb {
			return ra > rb
		}
		if (a.Fixed != "") != (b.Fixed != "") {
			return a.Fixed != ""
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Package < b.Package
	})
	return s, nil
}

func firstSentence(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if i := strings.Index(s, ". "); i > 0 && i < max {
		return s[:i+1]
	}
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
