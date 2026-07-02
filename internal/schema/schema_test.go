package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fleet (aggregate) diff'i bu JSON alan adlarinin STABIL kalmasina dayanir; kazara
// yeniden adlandirma fleet karsilastirmasini sessizce bozar. Bu test alan adlarini kilitler.
func TestResultJSONFieldsStable(t *testing.T) {
	r := Result{
		TestID:   "CHT-05-001",
		Result:   ResultAllowed,
		RiskWhenOpen: RiskHigh,
		RiskScore: 80,
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, key := range []string{
		`"testId"`, `"category"`, `"result"`, `"riskWhenOpen"`,
		`"riskScore"`, `"mapping"`, `"detected"`, `"tierRequired"`, `"deviceId"`,
	} {
		if !strings.Contains(s, key) {
			t.Errorf("results.json'da beklenen stabil alan eksik: %s", key)
		}
	}
}

// omitempty alanlari (skipReason/target) deger bossa cikti DISINDA kalmali — fleet
// CSV/HTML kolon sayisini sisirmesin.
func TestResultOmitemptyFields(t *testing.T) {
	data, _ := json.Marshal(Result{TestID: "CHT-00-001"})
	s := string(data)
	if strings.Contains(s, `"skipReason"`) {
		t.Error("bos skipReason omitempty ile cikmamaliydi")
	}
	if strings.Contains(s, `"target"`) {
		t.Error("bos target omitempty ile cikmamaliydi")
	}
}

// Surum sabitleri bos olmamali (rapor ust-verisi + fleet katalog-diff bunlara dayanir).
func TestVersionConstantsPresent(t *testing.T) {
	for name, v := range map[string]string{
		"SchemaVersion": SchemaVersion, "CatalogVersion": CatalogVersion, "ToolVersion": ToolVersion,
	} {
		if strings.TrimSpace(v) == "" {
			t.Errorf("%s bos", name)
		}
	}
	// NotImplemented skip sebebi, durust "iskelet" raporlama icin tanimli olmali.
	if SkipNotImplemented == "" {
		t.Error("SkipNotImplemented sabiti bos")
	}
}
