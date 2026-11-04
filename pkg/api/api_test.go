package api

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// keys returns the JSON field names of a value, including those omitempty would hide.
func keys(t *testing.T, v any) []string {
	t.Helper()
	typ := reflect.TypeOf(v)
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := splitTag(typ.Field(i).Tag.Get("json"))
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func splitTag(tag string) (name string, rest string, ok bool) {
	for i := 0; i < len(tag); i++ {
		if tag[i] == ',' {
			return tag[:i], tag[i+1:], true
		}
	}
	return tag, "", false
}

// TestV1FieldNamesAreFrozen is the contract. Fields may be added, so adding one means adding it here;
// renaming or removing one breaks every consumer and needs /api/v2 instead.
func TestV1FieldNamesAreFrozen(t *testing.T) {
	for name, c := range map[string]struct {
		v    any
		want []string
	}{
		"Finding":     {Finding{}, []string{"count", "exposure", "first_seen", "id", "image", "kind", "level", "message", "service", "severity", "stack", "swarm"}},
		"Findings":    {Findings{}, []string{"findings", "stale", "status", "updated"}},
		"Counts":      {Counts{}, []string{"crit", "info", "warn"}},
		"Scan":        {Scan{}, []string{"current", "done", "last_end", "last_error", "running", "total"}},
		"SwarmStatus": {SwarmStatus{}, []string{"error", "name", "status"}},
		"Summary":     {Summary{}, []string{"age_seconds", "counts", "scan", "stale", "status", "swarms", "updated", "version"}},
		"Vuln":        {Vuln{}, []string{"fixed", "id", "installed", "package", "severity", "title", "url"}},
		"Vulns":       {Vulns{}, []string{"counts", "fixable", "image", "items", "scanned_at", "service", "swarm"}},
		"Error":       {Error{}, []string{"error"}},
	} {
		got := keys(t, c.v)
		sort.Strings(c.want)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s fields = %v, want %v", name, got, c.want)
		}
	}
}

func TestConstantsAreStable(t *testing.T) {
	for got, want := range map[string]string{
		LevelOK: "ok", LevelInfo: "info", LevelWarn: "warn", LevelCrit: "crit",
		KindUnreachable: "unreachable", KindNode: "node", KindMemory: "memory", KindDisk: "disk",
		KindReplicas: "replicas", KindFailedTasks: "failed_tasks", KindOutdated: "outdated",
		KindVuln: "vulnerability", KindStaleScan: "stale_scan", KindUnused: "unused",
	} {
		if got != want {
			t.Errorf("%q != %q", got, want)
		}
	}
}

func TestEmptyFindingsMarshalAsAnArray(t *testing.T) {
	b, _ := json.Marshal(Findings{Findings: []Finding{}})
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if string(m["findings"]) != "[]" {
		t.Errorf("findings = %s", m["findings"])
	}
}
