package report

import (
	"testing"

	"github.com/ardean/swarmwatch/internal/exposure"
)

func TestAttentionOf(t *testing.T) {
	cases := []struct{ level, want string }{
		{exposure.Internet, AttentionInternet},
		{exposure.InternetSSO, AttentionInternet},
		{exposure.LAN, AttentionHome},
		{exposure.Internal, AttentionHome},
		{"", AttentionHost},
		{"somewhere", AttentionHost},
	}
	for _, c := range cases {
		if got := AttentionOf(c.level); got != c.want {
			t.Errorf("AttentionOf(%q) = %q, want %q", c.level, got, c.want)
		}
	}
	order := AttentionOrder()
	if len(order) != 3 || order[0] != AttentionInternet || order[1] != AttentionHost || order[2] != AttentionHome {
		t.Errorf("order = %v", order)
	}
}
