package report

import (
	"reflect"
	"testing"

	"github.com/ardean/swarmwatch/internal/swarm"
)

func TestPortLabels(t *testing.T) {
	got := PortLabels([]swarm.Port{
		{Published: 53, Target: 53, Proto: "tcp"},
		{Published: 8096, Target: 8096, Proto: "tcp"},
		{Published: 53, Target: 53, Proto: "udp"},
		{Published: 8282, Target: 8080, Proto: "tcp"},
		{Published: 8096, Target: 8096, Proto: "tcp"},
	})
	want := []string{"53", "53/udp", "8096", "8282→8080"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
}
