package aggregate

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

// WriteAll, fleet raporunu uc formatta yazar: fleet.json + fleet.csv + fleet.html.
func WriteAll(dir string, f *Fleet) (jsonPath, csvPath, htmlPath string, err error) {
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	jsonPath = filepath.Join(dir, "fleet.json")
	csvPath = filepath.Join(dir, "fleet.csv")
	htmlPath = filepath.Join(dir, "fleet.html")

	data, e := json.MarshalIndent(f, "", "  ")
	if e != nil {
		return jsonPath, csvPath, htmlPath, e
	}
	if err = os.WriteFile(jsonPath, data, 0o600); err != nil {
		return
	}
	if err = os.WriteFile(csvPath, []byte(renderCSV(f)), 0o600); err != nil {
		return
	}
	err = os.WriteFile(htmlPath, []byte(renderHTML(f)), 0o600)
	return
}

// renderCSV, Test-ID x sonuc dagilimi (Excel pivot icin).
func renderCSV(f *Fleet) string {
	var b strings.Builder
	b.WriteString("testId,category,name,riskWhenOpen,total,allowed,blocked,partial,error,na,outliers,systemic\n")
	for _, s := range f.TestStats {
		name := strings.ReplaceAll(s.Name, ",", " ")
		fmt.Fprintf(&b, "%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%v\n",
			s.TestID, s.Category, name, s.RiskWhenOpen, s.Total,
			s.ResultCounts["Allowed"], s.ResultCounts["Blocked"], s.ResultCounts["Partial"],
			s.ResultCounts["Error"], s.ResultCounts["NotApplicable"], len(s.Outliers), s.Systemic)
	}
	return b.String()
}

func renderHTML(f *Fleet) string {
	esc := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="tr"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1"><title>chtester filo raporu</title>`)
	b.WriteString(`<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}
header{background:#1b2430;padding:18px 26px;border-bottom:2px solid #2d8cf0}
h1{margin:0;font-size:19px;color:#fff}h2{color:#7fb6ff;padding:14px 26px 4px;margin:0;font-size:15px}
.kpis{display:flex;gap:12px;padding:14px 26px;flex-wrap:wrap}
.kpi{background:#141b24;border:1px solid #233040;border-radius:10px;padding:12px 18px;min-width:120px}
.kpi b{display:block;font-size:24px;color:#fff}.kpi span{font-size:12px;color:#9fb4c4}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #1f2a36;vertical-align:top}
th{background:#192330;color:#9fb6d0;position:sticky;top:0}
tr:hover{background:#172230}
.sys{background:#3a1414}.tag{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.risk-Critical{background:#7a0d0d;color:#fff}.risk-High{background:#9a3b12;color:#fff}
.risk-Medium{background:#7a5a12;color:#fff}.risk-Low{background:#14502a;color:#cfe}.risk-Info{background:#23303a;color:#9fb4c4}
.bad{color:#ff9a9a;font-weight:600}.good{color:#8ce99a}small{color:#8aa0b4}
.controls{padding:8px 26px}.controls input{padding:7px 10px;width:300px;border-radius:6px;border:1px solid #2d3a48;background:#0b1117;color:#fff}
</style></head><body>`)

	b.WriteString(`<header><h1>Client Cihaz Sertleştirme — Filo (Fleet) Raporu</h1>`)
	fmt.Fprintf(&b, `<small>%d cihaz · katalog %s · şema %s</small></header>`,
		f.DeviceCount, esc(strings.Join(f.CatalogVersions, ",")), esc(strings.Join(f.SchemaVersions, ",")))

	b.WriteString(`<div class="kpis">`)
	kpi := func(v, label string) { fmt.Fprintf(&b, `<div class="kpi"><b>%s</b><span>%s</span></div>`, esc(v), esc(label)) }
	kpi(itoa(f.DeviceCount), "cihaz")
	kpi(itoa(len(f.TestStats)), "benzersiz Test-ID")
	kpi(itoa(len(f.SystemicIssues)), "sistemik zayıflık")
	kpi(itoa(f.TotalOutliers), "outlier (sapma)")
	b.WriteString(`</div>`)

	// Sistemik zayifliklar
	b.WriteString(`<h2>Sistemik zayıflıklar (fleet geneli açık + yüksek risk)</h2>`)
	b.WriteString(`<table><thead><tr><th>Test-ID</th><th>İsim</th><th>Risk</th><th>Açık (Allowed)</th><th>Toplam</th></tr></thead><tbody>`)
	any := false
	for _, s := range f.TestStats {
		if !s.Systemic {
			continue
		}
		any = true
		fmt.Fprintf(&b, `<tr class="sys"><td><code>%s</code></td><td>%s</td><td><span class="tag risk-%s">%s</span></td><td class="bad">%d</td><td>%d</td></tr>`,
			esc(s.TestID), esc(s.Name), esc(s.RiskWhenOpen), esc(s.RiskWhenOpen), s.ResultCounts["Allowed"], s.Total)
	}
	if !any {
		b.WriteString(`<tr><td colspan="5" class="good">Sistemik zayıflık yok.</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)

	// Outlier'lar (Test-ID bazli sapan cihazlar)
	b.WriteString(`<h2>Outlier'lar (fleet çoğunluğundan zayıf yönde sapan cihazlar)</h2>`)
	b.WriteString(`<div class="controls"><input id="q" placeholder="filtrele..." onkeyup="flt()"></div>`)
	b.WriteString(`<table id="t"><thead><tr><th>Test-ID</th><th>İsim</th><th>Modal</th><th>Risk</th><th>Sapan cihazlar</th></tr></thead><tbody>`)
	for _, s := range f.TestStats {
		if len(s.Outliers) == 0 {
			continue
		}
		var devs []string
		for _, o := range s.Outliers {
			label := o.Hostname
			if label == "" {
				label = o.DeviceID
			}
			devs = append(devs, fmt.Sprintf("%s=%s", esc(label), esc(o.Result)))
		}
		fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td><span class="tag risk-%s">%s</span></td><td class="bad">%s</td></tr>`,
			esc(s.TestID), esc(s.Name), esc(s.ModalResult), esc(s.RiskWhenOpen), esc(s.RiskWhenOpen), strings.Join(devs, "; "))
	}
	b.WriteString(`</tbody></table>`)

	// Cihaz skor tablosu
	b.WriteString(`<h2>Cihazlar (kritik bulguya göre)</h2>`)
	b.WriteString(`<table><thead><tr><th>Cihaz</th><th>Tier</th><th>OS/Mimari</th><th>Domain</th><th>EDR</th><th>Kritik bulgu</th><th>Ort. risk</th><th>Allowed/Blocked</th></tr></thead><tbody>`)
	for _, d := range f.Devices {
		label := d.Hostname
		if label == "" {
			label = d.DeviceID
		}
		fmt.Fprintf(&b, `<tr><td>%s<br><small>%s</small></td><td>%d</td><td>%s/%s</td><td>%s</td><td>%s</td><td class="bad">%d</td><td>%.0f</td><td>%d/%d</td></tr>`,
			esc(label), esc(d.DeviceID), d.Tier, esc(d.OSBuild), esc(d.Arch), esc(d.DomainJoin),
			esc(joinOrDash(d.EDR)), d.CriticalFindings, d.AvgRisk, d.Counts["Allowed"], d.Counts["Blocked"])
	}
	b.WriteString(`</tbody></table>`)
	b.WriteString(`<script>function flt(){var q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('#t tbody tr').forEach(function(tr){tr.style.display=tr.innerText.toLowerCase().indexOf(q)>-1?'':'none'})}</script>`)
	b.WriteString(`</body></html>`)
	return b.String()
}

func joinOrDash(s []string) string {
	if len(s) == 0 {
		return "—"
	}
	return strings.Join(s, ",")
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
