// Package cron parses five-field cron schedules.
package cron

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a five-field cron schedule: minute hour day-of-month month day-of-week. Each field takes
// "*", a number, a range "a-b", a list "a,b", and a step "*/n" or "a-b/n". Months and weekdays may be
// written as names (jan, mon). Sunday is 0 or 7. As in cron(8), when both day-of-month and
// day-of-week are restricted, a day matches if either does.
type Schedule struct {
	min, hour, dom, month, dow uint64
	domAny, dowAny             bool
}

var monthNames = []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}
var dayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// Parse parses a schedule such as "0 4 1 * *" (04:00 on the first of every month).
func Parse(spec string) (*Schedule, error) {
	f := strings.Fields(spec)
	if len(f) != 5 {
		return nil, fmt.Errorf("%q: want 5 fields (minute hour day-of-month month day-of-week)", spec)
	}
	var c Schedule
	var err error
	if c.min, _, err = parseField(f[0], 0, 59, nil); err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	if c.hour, _, err = parseField(f[1], 0, 23, nil); err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	if c.dom, c.domAny, err = parseField(f[2], 1, 31, nil); err != nil {
		return nil, fmt.Errorf("day of month: %w", err)
	}
	if c.month, _, err = parseField(f[3], 1, 12, monthNames); err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	if c.dow, c.dowAny, err = parseField(f[4], 0, 7, dayNames); err != nil {
		return nil, fmt.Errorf("day of week: %w", err)
	}
	if c.dow&(1<<7) != 0 { // 7 is Sunday too
		c.dow |= 1
	}
	return &c, nil
}

// parseField returns the set of allowed values as a bit set, and whether the field was a bare "*".
func parseField(s string, lo, hi int, names []string) (set uint64, star bool, err error) {
	if s == "*" {
		star = true
	}
	for _, part := range strings.Split(s, ",") {
		rng, stepStr, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			if step, err = strconv.Atoi(stepStr); err != nil || step < 1 {
				return 0, false, fmt.Errorf("bad step in %q", part)
			}
		}
		from, to := lo, hi
		if rng != "*" {
			a, b, isRange := strings.Cut(rng, "-")
			if from, err = fieldValue(a, names, lo); err != nil {
				return 0, false, err
			}
			to = from
			if isRange {
				if to, err = fieldValue(b, names, lo); err != nil {
					return 0, false, err
				}
			} else if hasStep {
				to = hi // "5/10" means 5 to the end, every 10
			}
		}
		if from < lo || to > hi || from > to {
			return 0, false, fmt.Errorf("%q is outside %d-%d", part, lo, hi)
		}
		for v := from; v <= to; v += step {
			set |= 1 << uint(v)
		}
	}
	return set, star, nil
}

func fieldValue(s string, names []string, lo int) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	for i, name := range names {
		if strings.EqualFold(s, name) {
			return i + lo, nil
		}
	}
	return 0, fmt.Errorf("bad value %q", s)
}

// Describe returns a short phrase for the schedules swarmwatch itself uses.
// A schedule it cannot say that way is returned unchanged.
func Describe(spec string) string {
	c, err := Parse(spec)
	if err != nil {
		return spec
	}
	if phrase, ok := c.phrase(); ok {
		return phrase
	}
	return spec
}

// Next is the next minute after t at which the schedule fires, in t's location.
func (c *Schedule) Next(after time.Time) (time.Time, bool) {
	t := after.In(after.Location()).Truncate(time.Minute).Add(time.Minute)
	end := t.Add(366 * 24 * time.Hour)
	for !t.After(end) {
		if c.Match(t) {
			return t, true
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, false
}

func (c *Schedule) phrase() (string, bool) {
	if !c.domAny || !c.dowAny || !bitsCover(c.month, 1, 12) {
		return "", false
	}
	if bitsCover(c.hour, 0, 23) {
		if step, ok := minuteStep(c.min); ok {
			if step == 1 {
				return "every minute", true
			}
			return fmt.Sprintf("every %d minutes", step), true
		}
		if minute, ok := singleBit(c.min, 0, 59); ok {
			if minute == 0 {
				return "every hour", true
			}
			return fmt.Sprintf("every hour at :%02d", minute), true
		}
	}
	minute, mok := singleBit(c.min, 0, 59)
	hour, hok := singleBit(c.hour, 0, 23)
	if mok && hok {
		return fmt.Sprintf("every day at %02d:%02d", hour, minute), true
	}
	return "", false
}

func bitsCover(set uint64, lo, hi int) bool {
	for i := lo; i <= hi; i++ {
		if set&(1<<uint(i)) == 0 {
			return false
		}
	}
	return true
}

func singleBit(set uint64, lo, hi int) (int, bool) {
	v := -1
	for i := lo; i <= hi; i++ {
		if set&(1<<uint(i)) == 0 {
			continue
		}
		if v >= 0 {
			return 0, false
		}
		v = i
	}
	if v < 0 {
		return 0, false
	}
	return v, true
}

// minuteStep reports n when the set is exactly the minutes 0, n, 2n, … below 60.
func minuteStep(set uint64) (int, bool) {
	if set&1 == 0 {
		return 0, false
	}
	step := 0
	for i := 1; i < 60; i++ {
		if set&(1<<uint(i)) != 0 {
			step = i
			break
		}
	}
	if step == 0 {
		return 0, false
	}
	for i := 0; i < 60; i++ {
		if (set&(1<<uint(i)) != 0) != (i%step == 0) {
			return 0, false
		}
	}
	return step, true
}

// Match reports whether t, to the minute, is a time the schedule fires.
func (c *Schedule) Match(t time.Time) bool {
	if c.min&(1<<uint(t.Minute())) == 0 || c.hour&(1<<uint(t.Hour())) == 0 || c.month&(1<<uint(t.Month())) == 0 {
		return false
	}
	domOK := c.dom&(1<<uint(t.Day())) != 0
	dowOK := c.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case c.domAny && c.dowAny:
		return true
	case c.domAny:
		return dowOK
	case c.dowAny:
		return domOK
	}
	return domOK || dowOK
}
