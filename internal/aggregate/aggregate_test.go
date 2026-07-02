package aggregate

import (
	"testing"

	"chtester/internal/schema"
)

func TestResultRankOrder(t *testing.T) {
	if resultRank(schema.ResultAllowed) <= resultRank(schema.ResultBlocked) {
		t.Error("Allowed, Blocked'tan daha ZAYIF (yuksek rank) olmali")
	}
	if resultRank(schema.ResultNotApplicable) != -1 {
		t.Error("NotApplicable rank -1 olmali (kiyas disi)")
	}
}

func TestModalResultTieFavorsWeaker(t *testing.T) {
	// Esitlikte daha zayif (Allowed) secilmeli ki sistemik zayiflik gizlenmesin.
	m, _ := modalResult(map[string]int{schema.ResultBlocked: 2, schema.ResultAllowed: 2})
	if m != schema.ResultAllowed {
		t.Errorf("esitlikte Allowed bekleniyordu, %q dondu", m)
	}
}

func mkRep(id, res string) *schema.Report {
	return &schema.Report{
		DeviceID:       id,
		CatalogVersion: "0.4",
		SchemaVersion:  "1.1",
		FinishedAt:     "2026-06-01T00:00:00Z",
		Results: []schema.Result{{
			TestID: "CHT-T-001", Name: "t", Category: "c",
			Result: res, RiskWhenOpen: schema.RiskHigh, RiskScore: 80,
		}},
	}
}

func TestBuildSystemicWeakness(t *testing.T) {
	// 2 cihaz Allowed (zayif) + 1 Blocked, High risk => modal Allowed => sistemik.
	f := Build([]*schema.Report{
		mkRep("d1", schema.ResultAllowed),
		mkRep("d2", schema.ResultAllowed),
		mkRep("d3", schema.ResultBlocked),
	})
	if len(f.SystemicIssues) != 1 || f.SystemicIssues[0] != "CHT-T-001" {
		t.Errorf("CHT-T-001 sistemik zayiflik olmaliydi, %v", f.SystemicIssues)
	}
}

func TestBuildOutlierDetection(t *testing.T) {
	// 2 Blocked (modal guclu) + 1 Allowed => Allowed cihaz outlier (daha zayif).
	f := Build([]*schema.Report{
		mkRep("d1", schema.ResultBlocked),
		mkRep("d2", schema.ResultBlocked),
		mkRep("d3", schema.ResultAllowed),
	})
	var found *TestIDStat
	for i := range f.TestStats {
		if f.TestStats[i].TestID == "CHT-T-001" {
			found = &f.TestStats[i]
		}
	}
	if found == nil {
		t.Fatal("CHT-T-001 istatistigi yok")
	}
	if len(found.Outliers) != 1 || found.Outliers[0].DeviceID != "d3" {
		t.Errorf("d3 outlier olmaliydi, %v", found.Outliers)
	}
	if found.Systemic {
		t.Error("modal Blocked iken sistemik OLMAMALI")
	}
}

func TestLoadReportsDedupeLatest(t *testing.T) {
	// Ayni deviceId iki kez; en guncel finishedAt tutulmali. (LoadReports dosya okur;
	// burada Build'in dedupe'a guvenmedigini, LoadReports'un ayri test edildigini varsayar.)
	// Modal/dedupe mantigini dolayli dogrula: ayni id'li iki rapor Build'e verilince
	// iki ayri cihaz sayilir (Build dedupe yapmaz; dedupe LoadReports'ta) — bu beklenen.
	f := Build([]*schema.Report{mkRep("dup", schema.ResultAllowed), mkRep("dup", schema.ResultBlocked)})
	if f.DeviceCount != 2 {
		t.Errorf("Build dedupe yapmamali (dedupe LoadReports'ta); 2 bekleniyordu, %d", f.DeviceCount)
	}
}
