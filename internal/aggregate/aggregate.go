// Package aggregate, N cihazin results.json ciktilarini Test-ID bazli birlestirir ve
// outlier (kör nokta / sapma) tespiti yapar. Plan §Faz 5 — Ölçek & saha.
// Katalog surumlenir; birlestirme STABIL Test-ID uzerinden yapilir (vektor eklemeleri
// fleet karsilastirmasini bozmaz).
package aggregate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"chtester/internal/schema"
)

// DeviceSummary, tek bir cihazin ozeti.
type DeviceSummary struct {
	DeviceID         string         `json:"deviceId"`
	Hostname         string         `json:"hostname,omitempty"`
	Tier             int            `json:"tier"`
	Profile          string         `json:"profile"`
	OSBuild          string         `json:"osBuild"`
	Arch             string         `json:"arch"`
	DomainJoin       string         `json:"domainJoin"`
	EDR              []string       `json:"edrDetected"`
	FinishedAt       string         `json:"finishedAt"`
	Counts           map[string]int `json:"counts"`
	TotalVectors     int            `json:"totalVectors"`
	AvgRisk          float64        `json:"avgRisk"`
	MaxRisk          int            `json:"maxRisk"`
	CriticalFindings int            `json:"criticalFindings"` // Allowed + risk High/Critical
}

// Outlier, bir Test-ID'de fleet'in cogunlugundan ZAYIF yonde sapan cihaz.
type Outlier struct {
	DeviceID  string `json:"deviceId"`
	Hostname  string `json:"hostname,omitempty"`
	Result    string `json:"result"`
	RiskScore int    `json:"riskScore"`
}

// TestIDStat, bir Test-ID'nin fleet genelindeki dagilimi.
type TestIDStat struct {
	TestID       string         `json:"testId"`
	Name         string         `json:"name"`
	Category     string         `json:"category"`
	RiskWhenOpen string         `json:"riskWhenOpen"`
	Total        int            `json:"total"`
	ResultCounts map[string]int `json:"resultCounts"`
	ModalResult  string         `json:"modalResult"`
	Outliers     []Outlier      `json:"outliers"`
	WeakRatio    float64        `json:"weakRatio"` // Allowed oranı (0..1)
	Systemic     bool           `json:"systemic"`  // fleet geneli zayıf + yüksek risk
}

// Fleet, birlestirilmis filo modeli.
type Fleet struct {
	DeviceCount     int             `json:"deviceCount"`
	Devices         []DeviceSummary `json:"devices"`
	TestStats       []TestIDStat    `json:"testStats"`
	CatalogVersions []string        `json:"catalogVersions"`
	SchemaVersions  []string        `json:"schemaVersions"`
	SystemicIssues  []string        `json:"systemicIssues"`  // en kritik fleet-geneli zayıflıklar (Test-ID)
	TotalOutliers   int             `json:"totalOutliers"`
}

// resultRank, sonuc "aciklik/zayiflik" sirasi: yuksek = daha zayif (kontrol acik).
// Blocked en guclu (0); Allowed en zayif (3). NotApplicable kıyas disi (-1).
func resultRank(res string) int {
	switch res {
	case schema.ResultBlocked:
		return 0
	case schema.ResultError:
		return 1
	case schema.ResultPartial:
		return 2
	case schema.ResultAllowed:
		return 3
	default: // NotApplicable / bilinmeyen
		return -1
	}
}

// LoadReports, verilen yollardan (dosya/dizin) results.json'lari yukler.
// Ayni deviceId'nin birden cok kosmasinda en GUNCEL (finishedAt) tutulur.
func LoadReports(paths []string) ([]*schema.Report, error) {
	var files []string
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			_ = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if strings.EqualFold(d.Name(), "results.json") {
					files = append(files, path)
				}
				return nil
			})
		} else {
			files = append(files, p)
		}
	}

	latest := map[string]*schema.Report{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		data = stripBOM(data)
		var rep schema.Report
		if json.Unmarshal(data, &rep) != nil || rep.DeviceID == "" {
			continue
		}
		if prev, ok := latest[rep.DeviceID]; !ok || rep.FinishedAt > prev.FinishedAt {
			r := rep
			latest[rep.DeviceID] = &r
		}
	}
	var out []*schema.Report
	for _, r := range latest {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}

// Build, raporlardan filo modelini olusturur (outlier tespiti dahil).
func Build(reports []*schema.Report) *Fleet {
	f := &Fleet{DeviceCount: len(reports)}
	catSet, schSet := map[string]bool{}, map[string]bool{}

	// Per-Test-ID toplama
	type agg struct {
		name, category, risk string
		counts               map[string]int
		perDevice            []Outlier
	}
	stats := map[string]*agg{}

	for _, rep := range reports {
		catSet[rep.CatalogVersion] = true
		schSet[rep.SchemaVersion] = true

		ds := DeviceSummary{
			DeviceID: rep.DeviceID, Hostname: rep.Hostname, Tier: rep.Tier,
			Profile: rep.Profile, OSBuild: rep.OSBuild, Arch: rep.Arch,
			DomainJoin: rep.DomainJoin, EDR: rep.EDRDetected, FinishedAt: rep.FinishedAt,
			Counts: map[string]int{},
		}
		var riskSum int
		for _, r := range rep.Results {
			ds.Counts[r.Result]++
			ds.TotalVectors++
			riskSum += r.RiskScore
			if r.RiskScore > ds.MaxRisk {
				ds.MaxRisk = r.RiskScore
			}
			if r.Result == schema.ResultAllowed && (r.RiskWhenOpen == schema.RiskCritical || r.RiskWhenOpen == schema.RiskHigh) {
				ds.CriticalFindings++
			}

			a := stats[r.TestID]
			if a == nil {
				a = &agg{name: r.Name, category: r.Category, risk: r.RiskWhenOpen, counts: map[string]int{}}
				stats[r.TestID] = a
			}
			a.counts[r.Result]++
			a.perDevice = append(a.perDevice, Outlier{
				DeviceID: rep.DeviceID, Hostname: rep.Hostname, Result: r.Result, RiskScore: r.RiskScore,
			})
		}
		if ds.TotalVectors > 0 {
			ds.AvgRisk = float64(riskSum) / float64(ds.TotalVectors)
		}
		f.Devices = append(f.Devices, ds)
	}

	// Test-ID istatistikleri + outlier tespiti
	for id, a := range stats {
		modal, modalRank := modalResult(a.counts)
		total := 0
		for _, c := range a.counts {
			total += c
		}
		st := TestIDStat{
			TestID: id, Name: a.name, Category: a.category, RiskWhenOpen: a.risk,
			Total: total, ResultCounts: a.counts, ModalResult: modal,
		}
		if total > 0 {
			st.WeakRatio = float64(a.counts[schema.ResultAllowed]) / float64(total)
		}
		// Outlier: modal'dan DAHA ZAYIF yonde sapan (rank > modalRank ve >= Partial).
		for _, d := range a.perDevice {
			dr := resultRank(d.Result)
			if dr >= 2 && dr > modalRank {
				st.Outliers = append(st.Outliers, d)
			}
		}
		sort.Slice(st.Outliers, func(i, j int) bool { return st.Outliers[i].RiskScore > st.Outliers[j].RiskScore })
		f.TotalOutliers += len(st.Outliers)

		// Sistemik: fleet'in cogunlugu zayif (Allowed modal) + yuksek risk.
		if (modal == schema.ResultAllowed) && (a.risk == schema.RiskCritical || a.risk == schema.RiskHigh) {
			st.Systemic = true
			f.SystemicIssues = append(f.SystemicIssues, id)
		}
		f.TestStats = append(f.TestStats, st)
	}

	sort.Slice(f.TestStats, func(i, j int) bool {
		// Once sistemik, sonra outlier sayisi, sonra Test-ID.
		if f.TestStats[i].Systemic != f.TestStats[j].Systemic {
			return f.TestStats[i].Systemic
		}
		if len(f.TestStats[i].Outliers) != len(f.TestStats[j].Outliers) {
			return len(f.TestStats[i].Outliers) > len(f.TestStats[j].Outliers)
		}
		return f.TestStats[i].TestID < f.TestStats[j].TestID
	})
	sort.Slice(f.Devices, func(i, j int) bool { return f.Devices[i].CriticalFindings > f.Devices[j].CriticalFindings })

	f.CatalogVersions = keys(catSet)
	f.SchemaVersions = keys(schSet)
	sort.Strings(f.SystemicIssues)
	return f
}

// modalResult, en sik gorulen sonucu (NotApplicable haric) ve rank'ini doner.
func modalResult(counts map[string]int) (string, int) {
	best, bestN, bestRank := schema.ResultNotApplicable, -1, -2
	for _, res := range []string{schema.ResultBlocked, schema.ResultAllowed, schema.ResultPartial, schema.ResultError, schema.ResultNotApplicable} {
		n, rk := counts[res], resultRank(res)
		// Esitlikte DAHA ZAYIF sonucu (yuksek rank) sec — sistemik zayifligi gizlemez.
		if n > bestN || (n == bestN && rk > bestRank) {
			bestN, best, bestRank = n, res, rk
		}
	}
	return best, resultRank(best)
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}
