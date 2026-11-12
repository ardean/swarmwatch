package report

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ardean/swarmwatch/internal/exposure"
)

// Column is one sortable service-table header.
type Column struct {
	Key, Label string
	HighFirst  bool // the first click puts the largest value on top
}

// Columns is the service table, left to right.
var Columns = []Column{
	{Key: "stack", Label: "STACK"},
	{Key: "service", Label: "SERVICE"},
	{Key: "exposure", Label: "EXPOSURE", HighFirst: true},
	{Key: "ports", Label: "PORTS"},
	{Key: "repl", Label: "REPL"},
	{Key: "cpu", Label: "CPU", HighFirst: true},
	{Key: "mem", Label: "MEM", HighFirst: true},
	{Key: "image", Label: "IMAGE"},
	{Key: "update", Label: "UPDATE"},
	{Key: "vulns", Label: "VULNS (fixable)", HighFirst: true},
}

// Header is the column titles, for callers that only print them.
var Header = func() []string {
	out := make([]string, len(Columns))
	for i, c := range Columns {
		out[i] = c.Label
	}
	return out
}()

// ColumnByKey reports the column and whether the key is one of Columns.
func ColumnByKey(key string) (Column, bool) {
	for _, c := range Columns {
		if c.Key == key {
			return c, true
		}
	}
	return Column{}, false
}

// SortRows orders rows by a column. An unknown column leaves the slice as it is
// and returns false. Equal rows keep their previous order. A value the column
// cannot read stays at the bottom. Stack names that were blanked for grouping
// are filled in, because the rows are no longer grouped.
func SortRows(rows []Row, column string, desc bool) bool {
	if _, ok := ColumnByKey(column); !ok {
		return false
	}
	for i := range rows {
		if rows[i].Stack.Text == "" {
			if name := stackName(rows[i]); name != "" {
				rows[i].Stack.Text = name
				rows[i].Stack.Tone = ToneBold
			}
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rowBefore(rows[i], rows[j], column, desc)
	})
	return true
}

func stackName(r Row) string {
	name := r.Name.Text
	suffix := "_" + name
	if name != "" && strings.HasSuffix(r.Service, suffix) && len(r.Service) > len(suffix) {
		return strings.TrimSuffix(r.Service, suffix)
	}
	return ""
}

func rowBefore(a, b Row, column string, desc bool) bool {
	cmp, aok, bok := rowCmp(a, b, column)
	if aok != bok {
		return aok
	}
	if !aok || cmp == 0 {
		return false
	}
	if desc {
		return cmp > 0
	}
	return cmp < 0
}

func rowCmp(a, b Row, column string) (cmp int, aok, bok bool) {
	switch column {
	case "stack":
		return strings.Compare(stackNameOrText(a), stackNameOrText(b)), true, true
	case "service":
		return strings.Compare(a.Name.Text, b.Name.Text), true, true
	case "exposure":
		ar, br := exposure.Rank(a.Level), exposure.Rank(b.Level)
		return ar - br, a.Level != "", b.Level != ""
	case "ports":
		an, aok := leadingInt(strings.Join(a.Ports, " "))
		bn, bok := leadingInt(strings.Join(b.Ports, " "))
		return an - bn, aok, bok
	case "repl":
		ar, ad, aok := replNums(a.Repl.Text)
		br, bd, bok := replNums(b.Repl.Text)
		if ar != br {
			return ar - br, aok, bok
		}
		return ad - bd, aok, bok
	case "cpu":
		an, aok := trailingFloat(strings.TrimSuffix(a.CPU.Text, "%"))
		bn, bok := trailingFloat(strings.TrimSuffix(b.CPU.Text, "%"))
		return floatCmp(an, bn), aok, bok
	case "mem":
		an, aok := parseSize(a.Mem.Text)
		bn, bok := parseSize(b.Mem.Text)
		return floatCmp(an, bn), aok, bok
	case "image":
		return strings.Compare(a.Image.Text, b.Image.Text), a.Image.Text != "", b.Image.Text != ""
	case "update":
		return strings.Compare(strings.ToLower(a.Update.Text), strings.ToLower(b.Update.Text)), a.Update.Text != "" && a.Update.Text != "-", b.Update.Text != "" && b.Update.Text != "-"
	case "vulns":
		an, aok := vulnScore(a.Vulns.Text)
		bn, bok := vulnScore(b.Vulns.Text)
		return intCmp64(an, bn), aok, bok
	default:
		return 0, false, false
	}
}

func stackNameOrText(r Row) string {
	if r.Stack.Text != "" {
		return r.Stack.Text
	}
	return stackName(r)
}

func leadingInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, false
	}
	return n, true
}

func replNums(s string) (running, desired int, ok bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	left, right, found := strings.Cut(s, "/")
	if !found {
		return 0, 0, false
	}
	running, err1 := strconv.Atoi(left)
	desired, err2 := strconv.Atoi(right)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return running, desired, true
}

func trailingFloat(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0, false
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseSize(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0, false
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return 0, false
	}
	unit := s[len(s)-1]
	mult := 1.0
	switch unit {
	case 'B':
		mult = 1
	case 'K':
		mult = 1024
	case 'M':
		mult = 1024 * 1024
	case 'G':
		mult = 1024 * 1024 * 1024
	case 'T':
		mult = 1024 * 1024 * 1024 * 1024
	default:
		if unit < '0' || unit > '9' {
			return 0, false
		}
	}
	num := s
	if unit < '0' || unit > '9' {
		num = s[:len(s)-1]
	}
	n, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, false
	}
	return n * mult, true
}

func vulnScore(s string) (int64, bool) {
	switch s {
	case "", "-", "not scanned":
		return 0, false
	case "none":
		return 0, true
	}
	var c, h, m, l int
	for _, f := range strings.Fields(s) {
		if len(f) < 2 {
			continue
		}
		n := 0
		for _, r := range f[1:] {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		switch f[0] {
		case 'C':
			c = n
		case 'H':
			h = n
		case 'M':
			m = n
		case 'L':
			l = n
		}
	}
	return int64(c)<<48 | int64(h)<<32 | int64(m)<<16 | int64(l), true
}

func floatCmp(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func intCmp64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
