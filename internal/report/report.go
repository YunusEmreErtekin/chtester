// Package report, results.json + report.txt + report.html uretir.
// Plan: insan-okunur tek-cihaz raporu + makine-okunur fleet JSON'u.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"chtester/internal/schema"
)

// WriteAll, ucu de yazar. dir = Results dizini. Dosya yollarini doner.
func WriteAll(dir string, rep *schema.Report) (jsonPath, txtPath, htmlPath string, err error) {
	jsonPath = filepath.Join(dir, "results.json")
	txtPath = filepath.Join(dir, "report.txt")
	htmlPath = filepath.Join(dir, "report.html")

	if err = writeJSON(jsonPath, rep); err != nil {
		return
	}
	if err = os.WriteFile(txtPath, []byte(renderTXT(rep)), 0o600); err != nil {
		return
	}
	err = os.WriteFile(htmlPath, []byte(renderHTML(rep)), 0o600)
	return
}

func writeJSON(path string, rep *schema.Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func renderTXT(rep *schema.Report) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("================ CLIENT HARDENING TEST RAPORU ================\n")
	w("Arac           : chtester %s (sema %s, katalog %s)\n", rep.ToolVersion, rep.SchemaVersion, rep.CatalogVersion)
	w("Profil         : %s\n", rep.Profile)
	w("DeviceId       : %s\n", rep.DeviceID)
	w("OS / Mimari    : %s / %s\n", rep.OSBuild, rep.Arch)
	w("Domain / Intune: %s / %v\n", rep.DomainJoin, rep.IntuneManaged)
	w("EDR Tespit     : %s\n", joinOrNone(rep.EDRDetected))
	w("Capability Tier: %d (%s)\n", rep.Tier, rep.TierReason)
	w("Bootstrap      : %s\n", rep.BootstrapVector)
	w("Bayraklar      : passiveOnly=%v enableNoisy=%v skipDestructive=%v whatIf=%v\n",
		rep.Flags.PassiveOnly, rep.Flags.EnableNoisy, rep.Flags.SkipDestructive, rep.Flags.WhatIf)
	w("Baslangic/Bitis: %s -> %s\n", rep.StartedAt, rep.FinishedAt)
	w("Toplam vektor  : %d\n", len(rep.Results))
	w("=============================================================\n\n")

	// Ozet sayim
	counts := map[string]int{}
	for _, r := range rep.Results {
		counts[r.Result]++
	}
	w("OZET: Allowed=%d Blocked=%d Partial=%d Error=%d NotApplicable=%d\n\n",
		counts[schema.ResultAllowed], counts[schema.ResultBlocked], counts[schema.ResultPartial],
		counts[schema.ResultError], counts[schema.ResultNotApplicable])

	// Risk siralamasi (en yuksek once)
	sorted := append([]schema.Result(nil), rep.Results...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].RiskScore > sorted[j].RiskScore })

	w("---- BULGULAR (Test-ID sirasi) ----\n")
	byID := append([]schema.Result(nil), rep.Results...)
	sort.SliceStable(byID, func(i, j int) bool { return byID[i].TestID < byID[j].TestID })
	for _, r := range byID {
		w("\n[%s] %s\n", r.TestID, r.Name)
		w("  Sonuc      : %s", r.Result)
		if r.BlockingMechanism != schema.BlockNone && r.BlockingMechanism != "" {
			w("  | Engelleyen: %s", r.BlockingMechanism)
		}
		w("  | Risk: %s (%d)\n", r.RiskWhenOpen, r.RiskScore)
		if len(r.AttemptedMethods) > 0 {
			w("  Denenen    : %s\n", strings.Join(r.AttemptedMethods, "; "))
		}
		if r.Evidence != "" {
			w("  Kanit      : %s\n", r.Evidence)
		}
		if r.SkipReason != "" {
			w("  Atlama     : %s\n", r.SkipReason)
		}
		if r.Detected != schema.DetectedUnknown {
			w("  Tespit     : %s\n", r.Detected)
		}
		if rep.Profile == schema.ProfileStealth {
			w("  Telemetri  : %s | Evasion: %s\n", r.TelemetryWeight, joinOrNone(r.EvasionApplied))
		}
		if r.Recommendation != "" {
			w("  Oneri      : %s\n", r.Recommendation)
		}
		if (r.Mapping != schema.Mapping{}) {
			w("  Esleme     : ATT&CK=%s CIS=%s ASR=%s\n", r.Mapping.Attack, r.Mapping.CIS, r.Mapping.ASRID)
		}
	}
	w("\n==================== RAPOR SONU ====================\n")
	return b.String()
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "(yok)"
	}
	return strings.Join(s, ", ")
}

// --- Turkce gosterim yardimcilari ---

type resInfo struct{ Label, Class, Desc string }

var resultMeta = map[string]resInfo{
	schema.ResultAllowed:       {"İzin Verildi", "res-allowed", "Zararlı eylem gerçekleştirilebildi — kontrol zayıf veya yok (kötü)."},
	schema.ResultBlocked:       {"Engellendi", "res-blocked", "Eylem cihaz tarafından önlendi — kontrol düzgün çalışıyor (iyi)."},
	schema.ResultPartial:       {"Kısmi", "res-partial", "Eylem kısmen engellendi; geriye açık bir saldırı yüzeyi kaldı."},
	schema.ResultError:         {"Hata", "res-error", "Test yürütülürken hata oluştu; sonuç kesin değil."},
	schema.ResultNotApplicable: {"Uygulanamaz", "res-na", "Bu cihaz/işletim sistemi için geçerli değil."},
}

var resultOrder = []string{schema.ResultAllowed, schema.ResultBlocked, schema.ResultPartial, schema.ResultError, schema.ResultNotApplicable}

func resLabel(r string) string {
	if m, ok := resultMeta[r]; ok {
		return m.Label
	}
	return r
}

func resClass(r string) string {
	if m, ok := resultMeta[r]; ok {
		return m.Class
	}
	return "res-na"
}

var riskMeta = map[string]struct{ Label, Class string }{
	schema.RiskCritical: {"Kritik", "risk-crit"},
	schema.RiskHigh:     {"Yüksek", "risk-high"},
	schema.RiskMedium:   {"Orta", "risk-med"},
	schema.RiskLow:      {"Düşük", "risk-low"},
	schema.RiskInfo:     {"Bilgi", "risk-info"},
}

func riskLabel(r string) string {
	if m, ok := riskMeta[r]; ok {
		return m.Label
	}
	return r
}

func riskClass(r string) string {
	if m, ok := riskMeta[r]; ok {
		return m.Class
	}
	return "risk-info"
}

func detectedTR(d string) string {
	switch d {
	case schema.DetectedYes:
		return "Evet"
	case schema.DetectedNo:
		return "Hayır"
	default:
		return "Bilinmiyor"
	}
}

func blockTR(b string) string {
	switch b {
	case schema.BlockNone, "":
		return "—"
	case schema.BlockUnknown:
		return "Bilinmiyor"
	default:
		return b
	}
}

func telemetryTR(t string) string {
	switch t {
	case schema.TelemetryHigh:
		return "Yüksek"
	case schema.TelemetryMed:
		return "Orta"
	case schema.TelemetryLow:
		return "Düşük"
	default:
		return "Yok"
	}
}

func profileTR(p string) string {
	switch p {
	case schema.ProfileStealth:
		return "Gizli (Stealth)"
	case schema.ProfileAudit:
		return "Denetim (Audit)"
	default:
		return p
	}
}

func boolTR(v bool) string {
	if v {
		return "Evet"
	}
	return "Hayır"
}

var skipReasonTR = map[string]string{
	schema.SkipTierInsufficient: "Yetenek seviyesi yetersiz",
	schema.SkipNoiseGateClosed:  "Gürültü kapısı kapalı",
	schema.SkipNotApplicableOS:  "İşletim sistemi için geçerli değil",
	schema.SkipTimeout:          "Zaman aşımı",
	schema.SkipBudgetExhausted:  "Süre bütçesi tükendi",
	schema.SkipPassiveOnly:      "Yalnızca pasif modda atlandı",
	schema.SkipWhatIf:           "WhatIf (deneme) modunda atlandı",
	schema.SkipNotImplemented:   "Henüz uygulanmadı",
}

func skipTR(s string) string {
	if v, ok := skipReasonTR[s]; ok {
		return v
	}
	return s
}

func flagsTR(f schema.RunFlags) string {
	var parts []string
	if f.PassiveOnly {
		parts = append(parts, "Yalnızca pasif (salt-okunur)")
	}
	if f.EnableNoisy {
		parts = append(parts, "Gürültülü testler açık")
	}
	if f.WhatIf {
		parts = append(parts, "WhatIf (deneme)")
	}
	if f.SkipDestructive {
		parts = append(parts, "Yıkıcı testler atlandı")
	}
	if len(parts) == 0 {
		return "Standart"
	}
	return strings.Join(parts, " · ")
}

var categoryNames = map[int]string{
	0:  "Bağlam / Envanter",
	1:  "Kod Çalıştırma",
	2:  "Uygulama Kontrolü (AppLocker/WDAC)",
	3:  "Microsoft Defender / ASR",
	4:  "Yetki Yükseltme",
	5:  "Kalıcılık (Persistence)",
	6:  "Veri Sızıntısı Önleme (DLP)",
	7:  "Ağ Kontrolleri",
	8:  "Disk Şifreleme (BitLocker)",
	9:  "Kimlik Bilgisi Koruması",
	10: "Dosya Sistemi",
	11: "Tarayıcı Güvenliği",
	12: "İşletim Sistemi Sertleştirme",
	13: "Yatay Hareket / Active Directory",
	14: "Kullanıcı Kilitleme",
	15: "MDM / Intune",
	16: "Genişletilmiş Sertleştirme",
	17: "Ek Konfigürasyon",
	18: "Sıkılaştırma Derinliği",
	19: "Veri Sızıntısı Derinliği",
	20: "Kimlik & Kalıcılık",
	21: "Yürütme Kaçış & Fiziksel",
	22: "Ağ Saldırı Yüzeyi",
	23: "Güncelleme & Kablosuz",
	24: "Görünürlük & Politika",
	25: "Kimlik Doğrulama & Oturum",
	26: "Tarayıcı Saldırı Yüzeyi",
}

func catNum(cat string) int {
	if i := strings.IndexByte(cat, '-'); i > 0 {
		if n, err := strconv.Atoi(cat[:i]); err == nil {
			return n
		}
	}
	return 99
}

func categoryTR(cat string) string {
	n := catNum(cat)
	if name, ok := categoryNames[n]; ok {
		return fmt.Sprintf("%02d · %s", n, name)
	}
	return cat
}

// --- Severity: Bilgi < Düşük < Orta < Yüksek < Kritik < Acil ---
// Acik (Allowed) + yarim-agirlikli Partial bulgularin risk agirligindan seviye uretir.

var riskWeight = map[string]int{
	schema.RiskCritical: 100, schema.RiskHigh: 40, schema.RiskMedium: 10, schema.RiskLow: 3, schema.RiskInfo: 1,
}

type sevLevel struct {
	Label, Class string
	Min, Fill    int
}

var sevLevels = []sevLevel{
	{"Bilgi", "sev-info", 0, 10},
	{"Düşük", "sev-low", 1, 28},
	{"Orta", "sev-med", 10, 48},
	{"Yüksek", "sev-high", 40, 66},
	{"Kritik", "sev-crit", 100, 84},
	{"Acil", "sev-urgent", 200, 100},
}

func severityOf(results []schema.Result) sevLevel {
	score := 0.0
	for _, r := range results {
		w := float64(riskWeight[r.RiskWhenOpen])
		switch r.Result {
		case schema.ResultAllowed:
			score += w
		case schema.ResultPartial:
			score += w * 0.4
		}
	}
	sev := sevLevels[0]
	for _, x := range sevLevels {
		if score >= float64(x.Min) {
			sev = x
		}
	}
	return sev
}

func sevBg(cls string) string {
	return map[string]string{"sev-info": "#eceff1", "sev-low": "#e7f5ec", "sev-med": "#fff8e1",
		"sev-high": "#fff3e0", "sev-crit": "#fdecea", "sev-urgent": "#f4c9c9"}[cls]
}
func sevColor(cls string) string {
	return map[string]string{"sev-info": "#90a4ae", "sev-low": "#2e9e4b", "sev-med": "#f0c020",
		"sev-high": "#ef8a3c", "sev-crit": "#e0533f", "sev-urgent": "#a11111"}[cls]
}

// impactByCat, kategori bazinda SADE DIL etki aciklamasi (bir zafiyet acıksa ne olur).
var impactByCat = map[int]string{
	0:  "Bilgilendirme amaçlıdır; cihaz ve ortam hakkında temel bilgi verir.",
	1:  "Kullanıcı ya da kötü niyetli biri cihazda onaysız program/komut çalıştırabilir; zararlı yazılım veya saldırı araçları buradan devreye girebilir.",
	2:  "Onaysız programlar engellenmiyor; çalışan indirdiği herhangi bir uygulamayı (zararlı olsa bile) çalıştırabilir.",
	3:  "Virüs/zararlı yazılım koruması zayıf veya kapatılabilir; cihaz zararlı yazılıma açık kalır.",
	4:  "Standart bir kullanıcı, cihazın tam kontrolünü (yönetici/SYSTEM) ele geçirecek şekilde yetkisini yükseltebilir.",
	5:  "Zararlı yazılım cihaza yerleşip her açılışta kendiliğinden çalışacak şekilde kalıcı hale gelebilir.",
	6:  "Şirket verisi cihazdan dışarı (USB, ağ vb.) sızdırılabilir.",
	7:  "Ağ güvenlik kontrolleri atlatılabilir; internet trafiği yönlendirilebilir veya dinlenebilir.",
	8:  "Disk şifrelenmemiş/zayıfsa, cihaz çalınır ya da elden çıkarsa içindeki tüm veriler okunabilir.",
	9:  "Cihazda kayıtlı parolalar ve kimlik bilgileri çalınabilir.",
	10: "Hassas dosyalara veya başka kullanıcıların verilerine erişilebilir.",
	11: "Tarayıcı üzerinden veri sızıntısı ya da zararlı içerik/indirme riski oluşur.",
	12: "İşletim sistemi ayarları zayıf bırakılmış; bilinen yaygın saldırılara açık.",
	13: "Bir saldırgan bu cihazı basamak yapıp ağdaki diğer bilgisayarlara ve şirket etki alanına (domain) yayılabilir.",
	14: "Kullanıcı, erişmemesi gereken ayarlara/araçlara ulaşabilir ve cihaz politikalarını gevşetebilir.",
	15: "Cihaz merkezi yönetim (Intune/MDM) ile yeterince kısıtlanmamış.",
	16: "Ek sertleştirme adımları eksik; çeşitli saldırı yüzeyleri açık kalıyor.",
	17: "Yaygın bir yanlış/eksik yapılandırma mevcut; ilgili saldırıya kapı aralar.",
	18: "Çalışan yetkisiz yazılım kurabilir, cihaz ayarlarını değiştirebilir veya yetkisini yükseltebilir.",
	19: "Şirket verisi USB/telefon, kişisel bulut, şifreli arşiv veya yerleşik araçlarla dışarı çıkarılabilir.",
	20: "Kimlik bilgileri çalınabilir ya da kalıcı bir arka kapı/yetki yükseltme kurulabilir.",
	21: "İzleme/EDR atlatılarak fark edilmeden çalışılabilir ya da fiziksel/kurtarma erişimiyle cihaz ele geçirilebilir.",
	22: "Aynı ağdaki bir saldırgan bu cihazın kimliğini çalıp şirket etki alanına saldırabilir (Responder/mitm6 gibi).",
	23: "Sahte güncelleme ya da sahte Wi-Fi ile cihaz ele geçirilebilir; ayrıca zararlı USB (BadUSB) takılabilir.",
	24: "Bir saldırı olduğunda izler yeterince tutulmaz; olay fark edilmeyebilir veya saldırgan izini gizleyebilir.",
	25: "Zayıf oturum/kimlik doğrulama; yetkisiz erişim veya kullanıcının veriyi gizlemesi mümkün olur.",
	26: "Çalışan kurumsal veriyi (parola, yer imi) kişisel hesabına aktarabilir veya tarayıcı güvenlik politikasını baypas edebilir.",
}

func impactTR(r schema.Result) string {
	switch r.Result {
	case schema.ResultBlocked:
		return "Bu kontrol düzgün çalışıyor — bu yönde bir risk yok."
	case schema.ResultError:
		return "Test tamamlanamadı; sonuç kesin değil."
	}
	c := impactByCat[catNum(r.Category)]
	if c == "" {
		c = "Bu kontrol açık; ilgili saldırı yüzeyi mevcut."
	}
	if r.Result == schema.ResultPartial {
		return "Kısmen açık — " + c
	}
	return c
}

func resultPlainTR(res string) string {
	switch res {
	case schema.ResultAllowed:
		return "Bu işlem/ayar AÇIK bulundu — yani engellenmiyor; kullanıcı (ya da zararlı yazılım) bunu yapabiliyor."
	case schema.ResultBlocked:
		return "Bu işlem ENGELLENDİ — cihazdaki güvenlik kontrolü devrede ve çalışıyor."
	case schema.ResultPartial:
		return "Bu kontrol KISMEN açık — bir kısmı engelleniyor ama geriye açık bir yön kalıyor."
	case schema.ResultError:
		return "Test sırasında bir hata oluştu; sonuç kesin değil."
	}
	return ""
}

var trMonths = [...]string{"Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"}

// trDate, ISO tarihi (2026-07-01T...) "1 Temmuz 2026" formatina cevirir.
func trDate(iso string) string {
	if len(iso) < 10 {
		return iso
	}
	y, e1 := strconv.Atoi(iso[0:4])
	m, e2 := strconv.Atoi(iso[5:7])
	d, e3 := strconv.Atoi(iso[8:10])
	if e1 != nil || e2 != nil || e3 != nil || m < 1 || m > 12 {
		return iso
	}
	return fmt.Sprintf("%d %s %d", d, trMonths[m-1], y)
}

const cssLight = `
:root{--bg:#eef2f7;--card:#fff;--ink:#1f2933;--muted:#6b7a8d;--line:#e4e9f0;--accent:#1565c0;--brand:#c62828}
*{box-sizing:border-box}
body{font-family:'Segoe UI',Arial,sans-serif;margin:0;background:var(--bg);color:var(--ink);line-height:1.55}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px 60px}
header{background:linear-gradient(135deg,#fff,#eaf2ff);border-bottom:3px solid var(--accent);padding:16px 0 12px}
header .wrap{padding-bottom:0}
.brand{color:var(--brand);font-weight:800;letter-spacing:.6px;font-size:12px;text-transform:uppercase}
h1{margin:4px 0 2px;font-size:22px;color:#0f2a4a}
header small{display:block;margin-top:1px;color:var(--muted)}
section{margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 22px;box-shadow:0 1px 3px rgba(20,40,80,.05)}
.wrap>section:first-child{margin-top:14px}
h2{font-size:15px;margin:0 0 14px;color:#0f2a4a;border-left:4px solid var(--accent);padding-left:10px;text-transform:uppercase;letter-spacing:.3px}
.devbar{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.devbar .k{font-size:10.5px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted)}
.devbar .v{font-size:13.5px;font-weight:600}
.overall{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
.gauge{width:120px;height:120px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;flex:0 0 auto;text-align:center}
.gauge b{font-size:19px;line-height:1.1}.gauge span{font-size:11px;opacity:.85;margin-top:4px}
.pills{display:flex;gap:8px;flex-wrap:wrap}
.pill{display:inline-block;padding:6px 13px;border-radius:20px;font-size:13px;font-weight:600;border:1px solid transparent}
.res-Allowed{background:#fdecea;color:#c62828;border-color:#f3c7c2}
.res-Blocked{background:#e7f5ec;color:#1e7d34;border-color:#bfe4cc}
.res-Partial{background:#fff5e2;color:#a5670a;border-color:#f3dcae}
.res-Error{background:#f2e9fb;color:#6a1b9a;border-color:#dcc7ee}
.sev-info{color:#546e7a}.sev-low{color:#2e7d32}.sev-med{color:#b8860b}.sev-high{color:#ef6c00}.sev-crit{color:#c62828}.sev-urgent{color:#7f0000}
.sevpill{display:inline-block;padding:3px 12px;border-radius:20px;font-size:12px;font-weight:800;letter-spacing:.3px}
.sevpill.sev-info{background:#eceff1;color:#546e7a}.sevpill.sev-low{background:#e7f5ec;color:#2e7d32}
.sevpill.sev-med{background:#fff8e1;color:#a5670a}.sevpill.sev-high{background:#fff3e0;color:#ef6c00}
.sevpill.sev-crit{background:#fdecea;color:#c62828}.sevpill.sev-urgent{background:#f4c9c9;color:#7f0000;box-shadow:0 0 0 2px #e0a3a3 inset}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
th{background:#f2f6fc;color:#3a536e;font-weight:600}
tr:hover td{background:#f7fafd}
.tag{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:700}
.risk-crit{background:#b71c1c;color:#fff}.risk-high{background:#e64a19;color:#fff}
.risk-med{background:#f6a41b;color:#3a2600}.risk-low{background:#2e9e4b;color:#fff}.risk-info{background:#cfd8e0;color:#37474f}
.minibar{height:7px;width:90px;background:#e6ecf3;border-radius:5px;display:inline-block;vertical-align:middle;overflow:hidden}
.minibar>i{display:block;height:100%}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.controls input,.controls select,.controls button{padding:8px 11px;border-radius:8px;border:1px solid #cdd8e3;font-size:14px;background:#fff}
.controls input{flex:1;min-width:220px;max-width:380px}.controls button{cursor:pointer}
.catgroup{border:1px solid var(--line);border-radius:10px;margin:10px 0;overflow:hidden}
.cathead{display:flex;align-items:center;gap:10px;padding:11px 14px;background:#f6f9fd;cursor:pointer;font-weight:600}
.cathead .cnt{margin-left:auto;font-size:12px;color:var(--muted);font-weight:400}
.catbody{display:none;padding:4px 0}
.catgroup.open .catbody{display:block}
.chev{transition:transform .15s;display:inline-block}.catgroup.open .chev{transform:rotate(90deg)}
.finding{border-left:5px solid #ccc;padding:11px 16px;margin:2px 0;border-bottom:1px solid #f0f3f7}
.finding.b-Allowed{border-left-color:#e0533f}.finding.b-Blocked{border-left-color:#2e9e4b}
.finding.b-Partial{border-left-color:#e6a71e}.finding.b-Error{border-left-color:#8e44ad}
.finding h4{margin:0 0 5px;font-size:13.5px;font-weight:600}
.finding h4 code{background:#eef2f7;padding:1px 6px;border-radius:5px;font-size:11.5px;color:#334}
.kv{font-size:12.5px;margin:3px 0;color:#3a4a5a}.kv b{color:#42566b}
.imp-bad{background:#fdf0ee;border-left:3px solid #e0533f;padding:6px 10px;border-radius:0 6px 6px 0;margin:5px 0}
.imp-warn{background:#fff8ec;border-left:3px solid #e6a71e;padding:6px 10px;border-radius:0 6px 6px 0;margin:5px 0}
.imp-good{background:#eef7f0;border-left:3px solid #2e9e4b;padding:6px 10px;border-radius:0 6px 6px 0;margin:5px 0;color:#2e7d32}
.kv.tech{color:#8494a4;font-size:11px;font-family:Consolas,'Courier New',monospace;background:#f6f8fa;padding:4px 8px;border-radius:5px;margin-top:5px;word-break:break-word}
.kv.tech b{color:#8494a4;font-family:'Segoe UI',Arial}
footer{color:var(--muted);font-size:12px;text-align:center;padding:24px 0}
`

// trUpper, Turkce-farkinda buyuk harf (i -> İ).
func trUpper(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "i", "İ"))
}

func renderHTML(rep *schema.Report) string {
	var b strings.Builder
	esc := html.EscapeString

	// Uygulanamaz (NotApplicable) raporda HİÇ gösterilmez (kullanici tercihi).
	var results []schema.Result
	for _, r := range rep.Results {
		if r.Result != schema.ResultNotApplicable {
			results = append(results, r)
		}
	}

	// sayimlar + kategori gruplari
	counts := map[string]int{}
	type catStat struct {
		title      string
		list       []schema.Result
		a, bl, p   int
	}
	cats := map[int]*catStat{}
	var catNums []int
	for _, r := range results {
		counts[r.Result]++
		n := catNum(r.Category)
		cs := cats[n]
		if cs == nil {
			cs = &catStat{title: categoryTR(r.Category)}
			cats[n] = cs
			catNums = append(catNums, n)
		}
		cs.list = append(cs.list, r)
		switch r.Result {
		case schema.ResultAllowed:
			cs.a++
		case schema.ResultBlocked:
			cs.bl++
		case schema.ResultPartial:
			cs.p++
		}
	}
	sort.Ints(catNums)

	// acik risk puani ve sort icin severity skoru
	score := func(list []schema.Result) float64 {
		s := 0.0
		for _, r := range list {
			w := float64(riskWeight[r.RiskWhenOpen])
			if r.Result == schema.ResultAllowed {
				s += w
			} else if r.Result == schema.ResultPartial {
				s += w * 0.4
			}
		}
		return s
	}
	overall := severityOf(results)
	openRisk := 0
	for _, r := range results {
		if r.Result == schema.ResultAllowed {
			openRisk += r.RiskScore
		}
	}

	// --- belge basligi ---
	b.WriteString(`<!doctype html><html lang="tr"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>Güvenlik Değerlendirme Raporu — ` + esc(rep.DeviceID) + `</title>`)
	b.WriteString(`<style>` + cssLight + `</style></head><body>`)

	// --- header (marka Türkçe, sadece tarih) ---
	b.WriteString(`<header><div class="wrap">`)
	b.WriteString(`<div class="brand">chtester · İstemci Cihaz Test Aracı</div>`)
	b.WriteString(`<h1>İstemci Cihaz Güvenlik Değerlendirme Raporu</h1>`)
	b.WriteString(`<small>` + esc(trDate(rep.StartedAt)) + `</small>`)
	b.WriteString(`</div></header><div class="wrap">`)

	// --- cihaz bilgileri ---
	b.WriteString(`<section class="card"><h2>Cihaz Bilgileri</h2><div class="devbar">`)
	mrow := func(k, v string) {
		fmt.Fprintf(&b, `<div><div class="k">%s</div><div class="v">%s</div></div>`, esc(k), esc(v))
	}
	mrow("Cihaz Kimliği", rep.DeviceID)
	if rep.Hostname != "" {
		mrow("Ana Bilgisayar", rep.Hostname)
	}
	mrow("İşletim Sistemi / Mimari", rep.OSBuild+" / "+rep.Arch)
	mrow("Etki Alanı / Intune", fmt.Sprintf("%s / %s", rep.DomainJoin, boolTR(rep.IntuneManaged)))
	mrow("Tespit Edilen EDR", joinOrNone(rep.EDRDetected))
	mrow("Yetenek Seviyesi", fmt.Sprintf("Tier %d", rep.Tier))
	mrow("Çalışma Modu", flagsTR(rep.Flags))
	b.WriteString(`</div></section>`)

	// --- genel degerlendirme (severity) ---
	verdict := map[string]string{
		"sev-urgent": "Cihazda ACİL açıklar var; çalışan şirkete/veriye/cihaza doğrudan zarar verebilir — hemen müdahale gerekli.",
		"sev-crit":   "Kritik açıklar mevcut; öncelikli olarak kapatılmalı.",
		"sev-high":   "Yüksek riskli açıklar var; önceliklendirilmeli.",
		"sev-med":    "Orta düzey açıklar mevcut; iyileştirme önerilir.",
		"sev-low":    "Düşük düzey açıklar; küçük iyileştirmeler yeterli.",
		"sev-info":   "Kayda değer açık yok.",
	}[overall.Class]
	b.WriteString(`<section class="card"><h2>Genel Değerlendirme</h2><div class="overall">`)
	fmt.Fprintf(&b, `<div class="gauge" style="background:%s"><b class="%s">%s</b><span>Risk Seviyesi</span></div>`,
		sevBg(overall.Class), overall.Class, esc(trUpper(overall.Label)))
	b.WriteString(`<div style="flex:1;min-width:240px">`)
	fmt.Fprintf(&b, `<div style="font-size:22px;font-weight:800" class="%s">%s</div>`, overall.Class, esc(overall.Label))
	fmt.Fprintf(&b, `<p style="margin:6px 0 12px;font-size:13px">%s</p>`, esc(verdict))
	b.WriteString(`<div class="pills">`)
	for _, k := range []string{schema.ResultAllowed, schema.ResultBlocked, schema.ResultPartial, schema.ResultError} {
		fmt.Fprintf(&b, `<span class="pill res-%s">%s: %d</span>`, k, esc(resLabel(k)), counts[k])
	}
	b.WriteString(`</div></div>`)
	fmt.Fprintf(&b, `<div style="min-width:160px;font-size:13px"><div class="kv">Toplam test: <b>%d</b></div><div class="kv">Açık risk puanı: <b>%d</b></div></div>`, len(results), openRisk)
	b.WriteString(`</div></section>`)

	// --- kategori bazinda (severity, en riskliden basa) ---
	sortedCats := append([]int(nil), catNums...)
	sort.SliceStable(sortedCats, func(i, j int) bool { return score(cats[sortedCats[i]].list) > score(cats[sortedCats[j]].list) })
	b.WriteString(`<section class="card"><h2>Kategori Bazında Sertleştirme</h2><table><thead><tr><th>Kategori</th><th>Test</th><th>İzin</th><th>Engel</th><th>Kısmi</th><th>Seviye</th></tr></thead><tbody>`)
	for _, n := range sortedCats {
		cs := cats[n]
		sv := severityOf(cs.list)
		fmt.Fprintf(&b, `<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td><span class="sevpill %s">%s</span> <span class="minibar"><i style="width:%d%%;background:%s"></i></span></td></tr>`,
			esc(cs.title), len(cs.list), cs.a, cs.bl, cs.p, sv.Class, esc(sv.Label), sv.Fill, sevColor(sv.Class))
	}
	b.WriteString(`</tbody></table></section>`)

	// --- detayli bulgular (katlanabilir + filtre) ---
	b.WriteString(`<section class="card"><h2>Detaylı Bulgular</h2>`)
	b.WriteString(`<div class="controls"><input id="q" placeholder="Filtrele: Test-ID, isim, kanıt…" oninput="flt()">`)
	b.WriteString(`<select id="fres" onchange="flt()"><option value="">Tüm sonuçlar</option>`)
	for _, k := range []string{schema.ResultAllowed, schema.ResultBlocked, schema.ResultPartial, schema.ResultError} {
		fmt.Fprintf(&b, `<option value="%s">%s</option>`, k, esc(resLabel(k)))
	}
	b.WriteString(`</select><button onclick="toggleAll()">Hepsini aç/kapat</button></div><div id="list">`)
	for _, n := range catNums {
		cs := cats[n]
		lst := append([]schema.Result(nil), cs.list...)
		sort.SliceStable(lst, func(i, j int) bool { return lst[i].TestID < lst[j].TestID })
		fmt.Fprintf(&b, `<div class="catgroup"><div class="cathead" onclick="this.parentNode.classList.toggle('open')"><span class="chev">▶</span> %s <span class="cnt">%d test · <span style="color:#c62828">%d açık</span> · <span style="color:#2e7d32">%d engel</span></span></div><div class="catbody">`,
			esc(cs.title), len(cs.list), cs.a, cs.bl)
		for _, r := range lst {
			impCls := "imp-warn"
			switch r.Result {
			case schema.ResultAllowed:
				impCls = "imp-bad"
			case schema.ResultBlocked:
				impCls = "imp-good"
			}
			dataTxt := esc(strings.ToLower(r.TestID + " " + r.Name + " " + r.Evidence))
			fmt.Fprintf(&b, `<div class="finding b-%s" data-txt="%s" data-res="%s">`, r.Result, dataTxt, r.Result)
			fmt.Fprintf(&b, `<h4><code>%s</code> %s</h4>`, esc(r.TestID), esc(r.Name))
			fmt.Fprintf(&b, `<div class="kv"><span class="pill res-%s" style="padding:1px 9px;font-size:11px">%s</span> <span class="tag %s">%s</span>`,
				r.Result, esc(resLabel(r.Result)), riskClass(r.RiskWhenOpen), esc(riskLabel(r.RiskWhenOpen)))
			if bm := blockTR(r.BlockingMechanism); bm != "—" {
				fmt.Fprintf(&b, ` <span style="font-size:12px;color:#3a4a5a"><b>Engelleyen:</b> %s</span>`, esc(bm))
			}
			b.WriteString(`</div>`)
			fmt.Fprintf(&b, `<div class="kv"><b>Sonuç:</b> %s</div>`, esc(resultPlainTR(r.Result)))
			fmt.Fprintf(&b, `<div class="kv %s"><b>Etki:</b> %s</div>`, impCls, esc(impactTR(r)))
			if r.Recommendation != "" {
				fmt.Fprintf(&b, `<div class="kv"><b>Öneri:</b> %s</div>`, esc(r.Recommendation))
			}
			if r.Evidence != "" {
				fmt.Fprintf(&b, `<div class="kv tech"><b>Teknik kanıt:</b> %s</div>`, esc(r.Evidence))
			}
			b.WriteString(`</div>`)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div></section>`)

	b.WriteString(`<footer>Yalnızca yazılı yetkilendirme ve önceden SOC bilgilendirmesi ile çalıştırılır.<br>chtester ` + esc(rep.ToolVersion) + `</footer>`)
	b.WriteString(`</div>`) // .wrap

	b.WriteString(`<script>
function flt(){var q=(document.getElementById('q').value||'').toLowerCase();var fr=document.getElementById('fres').value;
document.querySelectorAll('.catgroup').forEach(function(g){var vis=0;
g.querySelectorAll('.finding').forEach(function(f){var ok=(!q||f.dataset.txt.indexOf(q)>-1)&&(!fr||f.dataset.res===fr);f.style.display=ok?'':'none';if(ok)vis++;});
g.style.display=vis?'':'none';if(q||fr)g.classList.add('open');});}
function toggleAll(){var any=document.querySelector('.catgroup:not(.open)');document.querySelectorAll('.catgroup').forEach(function(g){any?g.classList.add('open'):g.classList.remove('open');});}
</script></body></html>`)
	return b.String()
}
