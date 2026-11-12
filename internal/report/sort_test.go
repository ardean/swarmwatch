package report

import (
	"testing"

	"github.com/ardean/swarmwatch/internal/exposure"
)

func TestSortRowsByCPUAndKeepsStack(t *testing.T) {
	rows := []Row{
		{Service: "a_one", Stack: Cell{"a", ToneBold}, Name: Cell{Text: "one"}, CPU: Cell{Text: "1.0%"}},
		{Service: "a_two", Name: Cell{Text: "two"}, CPU: Cell{Text: "9.5%"}},
		{Service: "b_quiet", Stack: Cell{"b", ToneBold}, Name: Cell{Text: "quiet"}, CPU: Cell{Text: "-"}},
	}
	if !SortRows(rows, "cpu", true) {
		t.Fatal("cpu is a column")
	}
	if rows[0].Name.Text != "two" || rows[1].Name.Text != "one" || rows[2].Name.Text != "quiet" {
		t.Fatalf("order %s %s %s", rows[0].Name.Text, rows[1].Name.Text, rows[2].Name.Text)
	}
	if rows[0].Stack.Text != "a" {
		t.Fatalf("blanked stack was not filled: %q", rows[0].Stack.Text)
	}
	if SortRows(rows, "nope", false) {
		t.Fatal("unknown column sorted")
	}
}

func TestSortRowsVulnsAndExposure(t *testing.T) {
	rows := []Row{
		{Service: "a_none", Name: Cell{Text: "none"}, Vulns: Cell{Text: "none"}, Level: exposure.Internal},
		{Service: "a_bad", Name: Cell{Text: "bad"}, Vulns: Cell{Text: "C2(1) H1(0)"}, Level: exposure.LAN},
		{Service: "a_high", Name: Cell{Text: "high"}, Vulns: Cell{Text: "H9(3)"}, Level: exposure.Internet},
		{Service: "a_miss", Name: Cell{Text: "miss"}, Vulns: Cell{Text: "not scanned"}},
	}
	SortRows(rows, "vulns", true)
	if rows[0].Name.Text != "bad" || rows[1].Name.Text != "high" || rows[2].Name.Text != "none" || rows[3].Name.Text != "miss" {
		t.Fatalf("vuln order %s %s %s %s", rows[0].Name.Text, rows[1].Name.Text, rows[2].Name.Text, rows[3].Name.Text)
	}
	SortRows(rows, "exposure", true)
	if rows[0].Name.Text != "high" || rows[len(rows)-1].Name.Text != "miss" {
		t.Fatalf("exposure order starts %s ends %s", rows[0].Name.Text, rows[len(rows)-1].Name.Text)
	}
}

func TestSortRowsMemoryAndRepl(t *testing.T) {
	rows := []Row{
		{Service: "a_small", Name: Cell{Text: "small"}, Mem: Cell{Text: "512K"}, Repl: Cell{Text: "1/1"}},
		{Service: "a_big", Name: Cell{Text: "big"}, Mem: Cell{Text: "1.5G / 2.0G"}, Repl: Cell{Text: "0/1 !2"}},
		{Service: "a_mid", Name: Cell{Text: "mid"}, Mem: Cell{Text: "20.0M"}, Repl: Cell{Text: "2/2"}},
	}
	SortRows(rows, "mem", true)
	if rows[0].Name.Text != "big" || rows[1].Name.Text != "mid" || rows[2].Name.Text != "small" {
		t.Fatalf("mem order %s %s %s", rows[0].Name.Text, rows[1].Name.Text, rows[2].Name.Text)
	}
	SortRows(rows, "repl", false)
	if rows[0].Name.Text != "big" {
		t.Fatalf("down replica first, got %s", rows[0].Name.Text)
	}
}
