package cron

import (
	"testing"
	"time"
)

func TestSchedule(t *testing.T) {
	at := func(s string) time.Time {
		tm, err := time.Parse("2006-01-02 15:04", s)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	for _, c := range []struct {
		spec string
		when string
		want bool
	}{
		{"0 4 1 * *", "2026-12-01 04:00", true},
		{"0 4 1 * *", "2026-12-01 04:01", false},
		{"0 4 1 * *", "2026-12-02 04:00", false},
		{"*/15 * * * *", "2026-12-02 10:45", true},
		{"*/15 * * * *", "2026-12-02 10:46", false},
		{"30 3 * * sun", "2026-11-01 03:30", true}, // a Sunday
		{"30 3 * * 7", "2026-11-01 03:30", true},
		{"30 3 * * mon-fri", "2026-11-01 03:30", false},
		{"0 4 1,15 jan,dec *", "2026-12-15 04:00", true},
		{"0 4 1,15 jan,dec *", "2026-11-15 04:00", false},
		{"0 4 1 * mon", "2026-12-07 04:00", true}, // day-of-month OR day-of-week
		{"0 4 1 * mon", "2026-12-01 04:00", true},
		{"0 4 1 * mon", "2026-12-02 04:00", false},
		{"0-10/5 0 * * *", "2026-12-02 00:10", true},
	} {
		cr, err := Parse(c.spec)
		if err != nil {
			t.Errorf("%q: %v", c.spec, err)
			continue
		}
		if got := cr.Match(at(c.when)); got != c.want {
			t.Errorf("%q at %s = %v; want %v", c.spec, c.when, got, c.want)
		}
	}
}

func TestDescribeAndNext(t *testing.T) {
	for spec, want := range map[string]string{
		"*/5 * * * *":  "every 5 minutes",
		"* * * * *":    "every minute",
		"0 * * * *":    "every hour",
		"30 * * * *":   "every hour at :30",
		"30 3 * * *":   "every day at 03:30",
		"0 4 1 * *":    "0 4 1 * *",
		"30 3 * * sun": "30 3 * * sun",
	} {
		if got := Describe(spec); got != want {
			t.Errorf("Describe(%q) = %q, want %q", spec, got, want)
		}
	}
	at := func(s string) time.Time {
		tm, err := time.Parse("2006-01-02 15:04", s)
		if err != nil {
			t.Fatal(err)
		}
		return tm.UTC()
	}
	c, err := Parse("*/5 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	next, ok := c.Next(at("2026-11-06 14:32"))
	if !ok || !next.Equal(at("2026-11-06 14:35")) {
		t.Fatalf("*/5 next = %v %v", next, ok)
	}
	daily, err := Parse("30 3 * * *")
	if err != nil {
		t.Fatal(err)
	}
	next, ok = daily.Next(at("2026-11-06 14:32"))
	if !ok || !next.Equal(at("2026-11-07 03:30")) {
		t.Fatalf("daily next = %v %v", next, ok)
	}
}

func TestBadSchedules(t *testing.T) {
	for _, bad := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "*/0 * * * *", "a * * * *", "5-1 * * * *"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
