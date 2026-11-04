package vuln

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	s, err := parse([]byte(`{"Results":[
	 {"Vulnerabilities":[
	  {"VulnerabilityID":"CVE-1","PkgName":"a","Severity":"CRITICAL","FixedVersion":"1.2"},
	  {"VulnerabilityID":"CVE-1","PkgName":"a","Severity":"CRITICAL","FixedVersion":"1.2"},
	  {"VulnerabilityID":"CVE-2","PkgName":"b","Severity":"HIGH"}]},
	 {"Vulnerabilities":null}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Counts["CRITICAL"] != 1 || s.Fixable["CRITICAL"] != 1 || s.Counts["HIGH"] != 1 || s.Fixable["HIGH"] != 0 || s.Total() != 2 {
		t.Errorf("summary = %+v", s)
	}
}

func TestKey(t *testing.T) {
	if Key("a:1", "sha256:x") != "sha256:x" || Key("a:1", "") != "a:1" {
		t.Error("Key should prefer the digest")
	}
}

func TestParseItemsSortedWorstFirst(t *testing.T) {
	s, err := parse([]byte(`{"Results":[{"Vulnerabilities":[
	  {"VulnerabilityID":"CVE-3","PkgName":"c","Severity":"LOW","FixedVersion":"1"},
	  {"VulnerabilityID":"CVE-2","PkgName":"b","Severity":"CRITICAL","Title":"nope"},
	  {"VulnerabilityID":"CVE-1","PkgName":"a","Severity":"CRITICAL","FixedVersion":"2","Title":"boom","PrimaryURL":"https://x/CVE-1"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, it := range s.Items {
		ids = append(ids, it.ID)
	}
	// fixable critical, unfixable critical, then low
	if got := strings.Join(ids, ","); got != "CVE-1,CVE-2,CVE-3" {
		t.Errorf("order = %s", got)
	}
	if s.Items[0].Link() != "https://x/CVE-1" || s.Items[1].Link() != "https://nvd.nist.gov/vuln/detail/CVE-2" {
		t.Errorf("links = %q %q", s.Items[0].Link(), s.Items[1].Link())
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := LoadCache(dir)
	s, _ := parse([]byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"a","Severity":"HIGH","Title":"t"}]}]}`))
	if err := c.Put("sha256:abc", s); err != nil {
		t.Fatal(err)
	}
	got := LoadCache(dir).Get("sha256:abc")
	if got == nil || got.Counts["HIGH"] != 1 || len(got.Items) != 1 || got.Items[0].Title != "t" {
		t.Errorf("reloaded = %+v", got)
	}
	if b, _ := json.Marshal(got); strings.Contains(string(b), "CVE-1") {
		t.Error("items must not leak into the overview JSON")
	}
}
