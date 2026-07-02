package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"chtester/internal/harness"
	"chtester/internal/schema"
)

const cat10 = "10-FileSystem"

// Module10, dosya sistemi & veri erisimini test eder (cogu pasif/yazma probe).
type Module10 struct{}

func NewModule10() *Module10 { return &Module10{} }

func (Module10) ID() string   { return "10" }
func (Module10) Name() string { return "Dosya Sistemi & Veri Erişimi" }

func (m Module10) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat10)
	sr := systemRoot()

	// 10.2 Yazilabilir sistem dizinleri (privesc yüzeyi)
	b.add("CHT-10-002", "Yazılabilir sistem dizinleri (privesc yüzeyi)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1574"
		r.AttemptedMethods = []string{"yazma probe (Program Files/Windows/System32/drivers)"}
		targets := []string{
			os.Getenv("ProgramFiles"),
			os.Getenv("ProgramFiles(x86)"),
			sr,
			filepath.Join(sr, "System32"),
			filepath.Join(sr, "System32", "drivers"),
		}
		var writable []string
		for _, t := range targets {
			if t == "" {
				continue
			}
			if tryWriteProbe(t) {
				writable = append(writable, t)
			}
		}
		if len(writable) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Korunan sistem dizinlerinin hiçbiri yazılabilir değil (iyi)"
			return
		}
		r.Result = schema.ResultAllowed
		r.RiskWhenOpen = schema.RiskCritical
		r.Evidence = fmt.Sprintf("YAZILABILIR sistem dizini(%d): %s", len(writable), strings.Join(writable, "; "))
		r.Recommendation = "Standart kullanıcı korunan sistem dizinlerine yazabiliyor — ACL düzeltilmeli (privesc)."
	})

	// 10.1 Diger kullanici profillerine erisim
	b.add("CHT-10-001", "Diğer kullanıcı profillerine erişim", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1083"
		r.AttemptedMethods = []string{"C:\\Users\\* listeleme/okuma"}
		usersDir := `C:\Users`
		entries, err := os.ReadDir(usersDir)
		if err != nil {
			r.Result = schema.ResultBlocked
			r.Evidence = "C:\\Users listelenemedi: " + err.Error()
			return
		}
		me := strings.ToLower(os.Getenv("USERNAME"))
		var accessible []string
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			low := strings.ToLower(name)
			if low == me || low == "public" || low == "default" || low == "all users" || strings.HasPrefix(low, "default") {
				continue
			}
			// Profil ici bir alt dizini okumayi dene
			if _, err := os.ReadDir(filepath.Join(usersDir, name, "Desktop")); err == nil {
				accessible = append(accessible, name)
			}
		}
		if len(accessible) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Başka kullanıcı profillerinin içeriği okunamıyor (iyi)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "Erişilebilen diğer profiller: " + strings.Join(accessible, ", ")
		r.Recommendation = "Profil ACL'leri diğer kullanıcı verisini koruyacak şekilde sıkılaştırılmalı."
	})

	// 10.5 Hassas dosya arama (hafif pasif tarama, kullanici profili)
	b.add("CHT-10-005", "Hassas dosya avı (kdbx/pem/config)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1552.001"
		r.AttemptedMethods = []string{"kullanıcı profili sınırlı tarama"}
		home, _ := os.UserHomeDir()
		patterns := []string{"*.kdbx", "*.pem", "*.ppk", "id_rsa", "*.ovpn", "*.kdb"}
		var hits []string
		for _, sub := range []string{"", "Documents", "Downloads", "Desktop", ".ssh", ".aws", ".azure"} {
			dir := filepath.Join(home, sub)
			for _, pat := range patterns {
				if matches, _ := filepath.Glob(filepath.Join(dir, pat)); len(matches) > 0 {
					for _, mm := range matches {
						hits = append(hits, filepath.Base(mm))
					}
				}
			}
		}
		if len(hits) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Yaygın konumlarda hassas dosya bulunamadı"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("%d hassas dosya: %s", len(hits), truncate(strings.Join(hits, ", "), 160))
		r.Recommendation = "Anahtar/parola dosyaları şifreli kasada tutulmalı."
	})

	// 10.6 ADS / junction / symlink olusturma yetenegi (aktif)
	b.add("CHT-10-006", "ADS / junction / symlink oluşturma yeteneği", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1564.004"
		r.AttemptedMethods = []string{"ADS yazma probe (Temp)"}
		if !ctx.GateActive(r, 2, false) {
			return
		}
		base := filepath.Join(os.TempDir(), "cht-ads-probe.txt")
		ads := base + ":hidden"
		_ = os.WriteFile(base, []byte("x"), 0o600)
		defer os.Remove(base)
		err := os.WriteFile(ads, []byte("hidden-data"), 0o600)
		if err == nil {
			r.Result = schema.ResultAllowed
			r.Evidence = "Alternate Data Stream yazılabildi — veri gizleme yüzeyi"
			r.Recommendation = "ADS oluşturma EDR ile izlenmeli (T1564.004)."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence = "ADS yazılamadı: " + truncate(err.Error(), 100)
		}
	})

	// 10.10 Hassas yerel artefakt okunabilirligi (PASIF — read-only)
	b.add("CHT-10-010", "Hassas yerel artefakt okunabilirliği", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1552"
		r.AttemptedMethods = []string{"Test-Path + okuma probe (içerik kopyalanmaz)"}
		appdata := os.Getenv("APPDATA")
		local := os.Getenv("LOCALAPPDATA")
		var exposed []string
		var histHits []string
		// PowerShell gecmisi (duz-metin secret VE calistirilan komut izleri tasiyabilir)
		psHist := filepath.Join(appdata, `Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`)
		if readableNonEmpty(psHist) {
			exposed = append(exposed, "PowerShell geçmişi")
			histHits = scanPSHistoryRisk(psHist)
		}
		// RDP bitmap cache (oturum gorselleri)
		if c := dirFileCount(filepath.Join(local, `Microsoft\Terminal Server Client\Cache`)); c > 0 {
			exposed = append(exposed, fmt.Sprintf("RDP bitmap cache(%d)", c))
		}
		// Recent dosyalar (son erisim izleri)
		if c := dirFileCount(filepath.Join(appdata, `Microsoft\Windows\Recent`)); c > 0 {
			exposed = append(exposed, fmt.Sprintf("Recent(%d)", c))
		}
		if len(exposed) == 0 {
			r.Result = schema.ResultPartial
			r.RiskWhenOpen = schema.RiskLow
			r.Evidence = "Hedef artefaktlar bulunamadı/boş (PS history, RDP cache, Recent)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "Kullanıcı tarafından okunabilir hassas artefakt: " + strings.Join(exposed, ", ") +
			" — PS geçmişi/RDP cache düz-metin secret veya görsel sızdırabilir"
		r.Recommendation = "PSReadline geçmişi hassas komutlar için kapatılmalı (HistorySaveStyle SaveNothing); RDP bitmap cache devre dışı; periyodik temizlik."
		if len(histHits) > 0 {
			r.RiskWhenOpen = schema.RiskHigh
			r.Mapping.Attack = "T1552.003"
			r.Evidence += " | PS geçmişinde YÜKSEK-RİSKLİ komut izleri: " + strings.Join(histHits, ", ") +
				" — bu cihazda kimlik-hırsızlığı/istismar komutları çalıştırılmış olabilir"
			r.Recommendation = "ACİL: PS geçmişindeki komutlar incelenmeli (" + strings.Join(histHits, ", ") + "). " + r.Recommendation
		}
	})

	return b.results()
}

// psHistoryRiskPatterns, PowerShell konsol gecmisinde (PSReadline) yuksek-riskli komut
// izleri. Bir etiket icin listelenen tum desenler metinde bulunmalidir (AND). Salt-okunur.
var psHistoryRiskPatterns = []struct {
	label    string
	patterns []string
}{
	{"SAM/hive dökümü (reg save)", []string{"reg save", `hklm\sam`}},
	{"SYSTEM hive dökümü (reg save)", []string{"reg save", `hklm\system`}},
	{"LSASS dökümü (comsvcs MiniDump)", []string{"comsvc", "minidump"}},
	{"LSASS dökümü", []string{"minidump", "lsass"}},
	{"ExecutionPolicy Bypass", []string{"executionpolicy bypass"}},
	{"EncodedCommand (gizli komut)", []string{"-encodedcommand"}},
	{"EncodedCommand (gizli komut)", []string{" -enc "}},
	{"Mimikatz", []string{"mimikatz"}},
	{"İndir-çalıştır (DownloadString)", []string{"downloadstring"}},
	{"İndir-çalıştır (Invoke-Expression)", []string{"invoke-expression"}},
	{"Gölge kopya silme (ransomware)", []string{"vssadmin", "delete"}},
	{"Yerel hesap ekleme", []string{"net user", "/add"}},
}

// scanPSHistoryRisk, ConsoleHost_history.txt icerigini (sinirli, 512KB) tarar ve eslesen
// yuksek-riskli desen etiketlerini (benzersiz) doner. Icerik kopyalanmaz; yalnizca etiket.
func scanPSHistoryRisk(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, 512*1024)
	n, _ := f.Read(buf)
	if n <= 0 {
		return nil
	}
	text := strings.ToLower(string(buf[:n]))
	seen := map[string]bool{}
	var hits []string
	for _, p := range psHistoryRiskPatterns {
		matched := true
		for _, pat := range p.patterns {
			if !strings.Contains(text, pat) {
				matched = false
				break
			}
		}
		if matched && !seen[p.label] {
			seen[p.label] = true
			hits = append(hits, p.label)
		}
	}
	return hits
}
