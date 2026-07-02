package harness

import (
	"testing"

	"chtester/internal/schema"
)

type nopLog struct{}

func (nopLog) Logf(string, ...any) {}

func ctxWith(tier int, f schema.RunFlags) *RunContext {
	return NewRunContext(schema.ProfileAudit, tier, "dev", f, nil, nopLog{}, 1, 0)
}

func TestRiskScore(t *testing.T) {
	cases := []struct {
		name   string
		risk   string
		result string
		det    string
		want   int
	}{
		{"allowed-critical-undetected", schema.RiskCritical, schema.ResultAllowed, schema.DetectedNo, 100},
		{"blocked-critical", schema.RiskCritical, schema.ResultBlocked, schema.DetectedUnknown, 0},
		{"allowed-high-detected", schema.RiskHigh, schema.ResultAllowed, schema.DetectedYes, 48}, // 80*1*0.6
		{"partial-medium-unknown", schema.RiskMedium, schema.ResultPartial, schema.DetectedUnknown, 23}, // 55*0.5*0.85=23.4
		{"na-info", schema.RiskInfo, schema.ResultNotApplicable, schema.DetectedUnknown, 0},
	}
	for _, c := range cases {
		r := &schema.Result{RiskWhenOpen: c.risk, Result: c.result, Detected: c.det}
		if got := RiskScore(r); got != c.want {
			t.Errorf("%s: RiskScore=%d, beklenen %d", c.name, got, c.want)
		}
	}
}

func TestGateActiveTierInsufficient(t *testing.T) {
	c := ctxWith(1, schema.RunFlags{PassiveOnly: false})
	r := c.NewResult("X", "cat", "n")
	if c.GateActive(r, 2, false) {
		t.Fatal("Tier 1 iken Tier 2 gerektiren vektor gecmemeli")
	}
	if r.SkipReason != schema.SkipTierInsufficient {
		t.Errorf("SkipReason=%q, beklenen %q", r.SkipReason, schema.SkipTierInsufficient)
	}
}

func TestGateActivePassiveBlocksActive(t *testing.T) {
	c := ctxWith(3, schema.RunFlags{PassiveOnly: true})
	r := c.NewResult("X", "cat", "n")
	if c.GateActive(r, 2, false) {
		t.Fatal("PassiveOnly iken aktif vektor gecmemeli")
	}
	if r.SkipReason != schema.SkipPassiveOnly {
		t.Errorf("SkipReason=%q, beklenen %q", r.SkipReason, schema.SkipPassiveOnly)
	}
}

func TestGateActiveNoisyNeedsEnableNoisy(t *testing.T) {
	c := ctxWith(3, schema.RunFlags{PassiveOnly: false, EnableNoisy: false})
	r := c.NewResult("X", "cat", "n")
	if c.GateActive(r, 2, true) {
		t.Fatal("EnableNoisy yokken gurultulu vektor gecmemeli")
	}
	if r.SkipReason != schema.SkipNoiseGateClosed {
		t.Errorf("SkipReason=%q, beklenen %q", r.SkipReason, schema.SkipNoiseGateClosed)
	}
}

func TestGateActiveWhatIf(t *testing.T) {
	c := ctxWith(3, schema.RunFlags{PassiveOnly: false, WhatIf: true})
	r := c.NewResult("X", "cat", "n")
	if c.GateActive(r, 2, false) {
		t.Fatal("WhatIf iken aktif vektor calismamali")
	}
	if r.SkipReason != schema.SkipWhatIf {
		t.Errorf("SkipReason=%q, beklenen %q", r.SkipReason, schema.SkipWhatIf)
	}
}

func TestGateActiveAllowed(t *testing.T) {
	c := ctxWith(2, schema.RunFlags{PassiveOnly: false})
	r := c.NewResult("X", "cat", "n")
	if !c.GateActive(r, 2, false) {
		t.Fatal("Tier yeterli + aktif izin varken vektor gecmeli")
	}
}

// TestRunnerRecoversPanic, bir modulun panigi tum calismayi cokertmemeli.
func TestRunnerRecoversPanic(t *testing.T) {
	c := ctxWith(2, schema.RunFlags{})
	rn := NewRunner(c, panicModule{}, okModule{})
	res := rn.Run()
	var sawPanic, sawOK bool
	for _, r := range res {
		if r.Result == schema.ResultError && r.TestID == "CHT-PM-PANIC" {
			sawPanic = true
		}
		if r.TestID == "CHT-OK-001" {
			sawOK = true
		}
	}
	if !sawPanic {
		t.Error("panik yapan modul Error sonucu uretmeliydi")
	}
	if !sawOK {
		t.Error("panikten SONRAKI modul yine de calismaliydi")
	}
}

type panicModule struct{}

func (panicModule) ID() string   { return "PM" }
func (panicModule) Name() string { return "panik" }
func (panicModule) Run(*RunContext) []schema.Result {
	panic("test panigi")
}

type okModule struct{}

func (okModule) ID() string   { return "OK" }
func (okModule) Name() string { return "ok" }
func (okModule) Run(c *RunContext) []schema.Result {
	r := c.NewResult("CHT-OK-001", "ok", "ok")
	r.Result = schema.ResultBlocked
	return []schema.Result{*r}
}
