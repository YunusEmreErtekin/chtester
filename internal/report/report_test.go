package report

import (
	"strings"
	"testing"

	"chtester/internal/schema"
)

func TestRenderHTMLEscapesXSS(t *testing.T) {
	rep := &schema.Report{
		DeviceID: "<script>alert(1)</script>",
		Profile:  schema.ProfileAudit,
		Results: []schema.Result{{
			TestID:       "CHT-X-001",
			Name:         "<img src=x onerror=alert(1)>",
			Result:       schema.ResultAllowed,
			Evidence:     "<b>evil</b>",
			RiskWhenOpen: schema.RiskHigh,
		}},
	}
	out := renderHTML(rep)
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("deviceID XSS olarak kacirilmamis")
	}
	if strings.Contains(out, "<img src=x onerror") {
		t.Error("vektor adi XSS olarak kacirilmamis")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("escape edilmis (&lt;script&gt;) hali bulunmali")
	}
}

func TestRenderTXTCounts(t *testing.T) {
	rep := &schema.Report{
		Profile: schema.ProfileAudit,
		Results: []schema.Result{
			{Result: schema.ResultAllowed},
			{Result: schema.ResultBlocked},
			{Result: schema.ResultAllowed},
		},
	}
	txt := renderTXT(rep)
	if !strings.Contains(txt, "Allowed=2") || !strings.Contains(txt, "Blocked=1") {
		t.Errorf("ozet sayimlari hatali:\n%s", txt)
	}
}
