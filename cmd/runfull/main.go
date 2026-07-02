// Command runfull, cmd.exe / .bat gerektirmeden cift-tiklama ile TAM (pasif+aktif+noisy)
// calismayi baslatir. Kilitli cihazlarda .bat launcher'lar acilip kapaniyorsa (DisableCMD
// olmasa bile USB'den script calistirma engelleniyorsa) bu ikili dogrudan calisir: EXE
// cift-tiklamasi cihazda calisiyor. Scope artefaktini kendisi yazar, onay ister, noisy
// bayraklariyla app.Execute'i cagirir ve pencereyi Enter'a kadar ACIK tutar (cleaned=true
// gorulebilsin). Butun degisiklikler app icinde aninda geri alinir (manifest).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"chtester/internal/app"
	"chtester/internal/schema"
)

type consoleLogger struct{}

func (consoleLogger) Logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// scope, genis-pencereli yetki artefakti. HMAC anahtari (CHTESTER_SCOPE_HMAC_KEY)
// tanimli DEGILSE imza gerekmez; noisy icin validFrom<=now<=validUntil + "noisy"
// sinifi yeterli.
const scopeJSON = `{
  "ticket": "CHT-FULL-RUN",
  "customer": "Yetkili Saha Testi",
  "validFrom": "2020-01-01T00:00:00Z",
  "validUntil": "2035-12-31T23:59:59Z",
  "allowedTestClasses": ["passive", "active-safe", "noisy"],
  "socContact": "soc@example.com",
  "doubleBlindAuthorized": false
}`

func main() {
	in := bufio.NewReader(os.Stdin)

	fmt.Println("============================================================")
	fmt.Println(" Client Device Tester  -  chtester")
	fmt.Println(" MOD: TAM ÇALIŞMA (pasif + aktif + gürültülü [N])")
	fmt.Println(" cmd/.bat GEREKTİRMEZ — bu pencere Enter'a kadar açık kalır.")
	fmt.Println("============================================================")
	fmt.Println()
	fmt.Println(" UYARI: Gürültülü testler kasıtlı olarak sesli çalışır ve EDR/SOC")
	fmt.Println(" alarmı üretir. Tüm değişiklikler ANINDA geri alınır (manifest).")
	fmt.Println(" Yalnızca yazılı yetki + SOC bilgilendirmesi ile çalıştırın.")
	fmt.Println()
	fmt.Print(" Devam etmek için  Y  yazıp Enter'a basın (başka tuş = iptal): ")
	line, _ := in.ReadString('\n')
	if s := strings.TrimSpace(line); !strings.EqualFold(s, "Y") {
		fmt.Println(" İptal edildi. Hiçbir şey çalıştırılmadı.")
		waitEnter(in)
		return
	}

	// Scope artefaktini yazilabilir Temp'e yaz (USB salt-okunur olabilir).
	scopePath := filepath.Join(os.TempDir(), "cdt-scope-full.json")
	if err := os.WriteFile(scopePath, []byte(scopeJSON), 0o600); err != nil {
		fmt.Println(" HATA: scope yazılamadı:", err)
		waitEnter(in)
		return
	}

	fmt.Println()
	fmt.Println(" Çalışma başladı — bu birkaç dakika sürebilir...")
	fmt.Println()

	opts := app.Options{
		Profile:     "Audit",
		PassiveOnly: false,
		EnableNoisy: true,
		ScopePath:   scopePath,
		BudgetSec:   1800,
	}
	out, err := app.Execute(opts, consoleLogger{})
	if err != nil {
		fmt.Println()
		fmt.Println(" HATA:", err)
		waitEnter(in)
		return
	}

	printSummary(out)

	// Temizlik durumunu (manifest.cleaned) belirgin göster.
	cleaned, found := manifestCleaned(out.SinkDir)
	fmt.Println()
	switch {
	case found && cleaned:
		fmt.Println(" ✅ TEMİZLENDİ (cleaned=true): tüm değişiklikler geri alındı.")
	case found && !cleaned:
		fmt.Println(" ⚠️  cleaned=FALSE — geri alınmamış değişiklik olabilir!")
		fmt.Println("     Şunu çalıştırın: Tools\\Cleanup-x64.exe -manifest \"" +
			filepath.Join(out.SinkDir, "manifest.json") + "\"")
	default:
		fmt.Println(" ℹ️  manifest.json bulunamadı (değişiklik yapılmamış olabilir).")
	}

	fmt.Println()
	fmt.Println(" SONUÇLAR:", out.SinkDir)
	fmt.Println(" >> Bu klasörün TAMAMINI USB'ye kopyalayın (results.json, report.html,")
	fmt.Println("    manifest.json). Analiz için bana getirin.")

	// Raporu ac (cmd start; acilmazsa report.html elle acilabilir).
	_ = exec.Command("cmd", "/c", "start", "", out.HTMLPath).Start()

	waitEnter(in)
}

func waitEnter(in *bufio.Reader) {
	fmt.Println()
	fmt.Print(" Kapatmak için Enter'a basın...")
	_, _ = in.ReadString('\n')
}

func manifestCleaned(dir string) (cleaned, found bool) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return false, false
	}
	var m struct {
		Cleaned bool `json:"cleaned"`
	}
	if json.Unmarshal(data, &m) != nil {
		return false, false
	}
	return m.Cleaned, true
}

func printSummary(out *app.RunOutput) {
	rep := out.Report
	counts := map[string]int{}
	for _, r := range rep.Results {
		counts[r.Result]++
	}
	fmt.Println()
	fmt.Println("==================== ÖZET ====================")
	fmt.Printf("DeviceId : %s\n", rep.DeviceID)
	fmt.Printf("Tier     : %d (%s)\n", rep.Tier, rep.TierReason)
	fmt.Printf("Bayrak   : passiveOnly=%v enableNoisy=%v\n", rep.Flags.PassiveOnly, rep.Flags.EnableNoisy)
	fmt.Printf("Vektör   : %d  | Allowed=%d Blocked=%d Partial=%d Error=%d NA=%d\n",
		len(rep.Results), counts[schema.ResultAllowed], counts[schema.ResultBlocked],
		counts[schema.ResultPartial], counts[schema.ResultError], counts[schema.ResultNotApplicable])
	fmt.Println("==============================================")
}
