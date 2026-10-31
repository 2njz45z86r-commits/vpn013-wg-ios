package r013traffic

import (
	"math"
	"testing"
)

func TestAdaptiveUnits(t *testing.T) {
	for _, c := range []struct {
		bytes float64
		want  string
	}{
		{0, "0 бит/с"}, {1, "8 бит/с"}, {125, "1 Кбит/с"}, {1250, "10 Кбит/с"},
		{125000, "1 Мбит/с"}, {250000, "2 Мбит/с"}, {2500000, "20 Мбит/с"},
		{125000000, "1 Гбит/с"}, {125000000000, "1 Тбит/с"},
		{124987.5, "999,9 Кбит/с"}, {124993.75, "1 Мбит/с"},
		{math.NaN(), "—"}, {math.Inf(1), "—"}, {-1, "—"},
	} {
		if got := Speed(c.bytes); got != c.want {
			t.Errorf("rate %v: %q != %q", c.bytes, got, c.want)
		}
	}
	for _, c := range []struct {
		bytes uint64
		want  string
	}{
		{0, "0 Б"}, {999, "999 Б"}, {1000, "1 КБ"}, {1500, "1,5 КБ"},
		{999950, "1 МБ"}, {1000000, "1 МБ"}, {2500000, "2,5 МБ"}, {1000000000, "1 ГБ"},
		{math.MaxUint64, "18,4 ЭБ"},
	} {
		if got := Amount(c.bytes); got != c.want {
			t.Errorf("amount %v: %q != %q", c.bytes, got, c.want)
		}
	}
}

func TestRealCounterDeltasAndSessionBoundaries(t *testing.T) {
	var s Sampler
	check := func(id string, at float64, rx, tx uint64) *Rate { return s.Sample(id, at, &rx, &tx) }
	if check("a", 0, 0, 0) != nil {
		t.Fatal("first sample fabricated a rate")
	}
	r := check("a", 2, 500000, 125000)
	if r == nil || Speed(r.Received) != "2 Мбит/с" || Speed(r.Sent) != "500 Кбит/с" {
		t.Fatal("wrong real delta")
	}
	if check("a", 2.1, 510000, 126000) != r {
		t.Fatal("rapid UI refresh discarded baseline")
	}
	if r = check("a", 4, 500000, 125000); r == nil || Speed(r.Received) != "0 бит/с" {
		t.Fatal("idle traffic is not zero")
	}
	if check("a", 6, 1000, 1000) != nil {
		t.Fatal("reset counters fabricated rate")
	}
	if check("b", 8, 5000000, 5000000) != nil {
		t.Fatal("new server inherited previous counters")
	}
	if check("b", 40, 6000000, 6000000) != nil {
		t.Fatal("stale sample used")
	}
	if s.Sample("b", 41, nil, nil) != nil {
		t.Fatal("missing telemetry invented zero")
	}
	if check("b", 42, 6000000, 6000000) != nil {
		t.Fatal("missing telemetry did not reset baseline")
	}
	if check("b", 41, 7000000, 7000000) != nil {
		t.Fatal("backwards clock used")
	}
	if s.Sample("b", math.NaN(), nil, nil) != nil {
		t.Fatal("invalid clock used")
	}
}
