package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat03 = "03-Defender"

// Module03, Defender/AV/EDR durumunu okur (pasif + ASR per-rule + AMSI + canary, EICAR opsiyonel).
type Module03 struct{}

func NewModule03() *Module03 { return &Module03{} }

func (Module03) ID() string   { return "03" }
func (Module03) Name() string { return "Defender / AV / EDR" }

// asrRules, bilinen Attack Surface Reduction kural GUID->isim eslemesi.
var asrRules = []struct{ guid, name string }{
	{"56a863a9-875e-4185-98a7-b882c64b5ce5", "Abuse of vulnerable signed drivers"},
	{"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Adobe Reader child process"},
	{"d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Office child process"},
	{"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Credential stealing from LSASS"},
	{"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Executable email/webmail content"},
	{"01443614-cd74-433a-b99e-2ecdc07bfc25", "Executable unless prevalence/age/trusted"},
	{"5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Obfuscated scripts"},
	{"d3e037e1-3eb8-44c8-a917-57927947596d", "JS/VBS launching downloaded content"},
	{"3b576869-a4ec-4529-8536-b80a7769e899", "Office creating executable content"},
	{"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Office code injection"},
	{"26190899-1602-49e8-8b27-eb1d0a1ce869", "Office comm app child process"},
	{"e6db77e5-3df2-4cf1-b95a-636979351e5b", "Persistence via WMI event subscription"},
	{"d1e49aac-8f56-4280-b9ba-993a6d77406c", "Process creation from PSExec/WMI"},
	{"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Untrusted/unsigned processes from USB"},
	{"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Win32 API from Office macro"},
	{"c1db55ab-c21a-4637-bb3f-a12568109d35", "Advanced ransomware protection"},
}

func (m Module03) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat03)
	const defRoot = `SOFTWARE\Microsoft\Windows Defender`
	const polRoot = `SOFTWARE\Policies\Microsoft\Windows Defender`

	// 03.1 RTP / Tamper / cloud / PUA / network protection / CFA
	b.add("CHT-03-001", "Defender koruma duruşu (RTP/Tamper/Cloud/PUA/NP/CFA)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1562.001"
		r.AttemptedMethods = []string{"registry Defender (Tamper Protection okumayı kısıtlayabilir)"}
		disRTP, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, defRoot+`\Real-Time Protection`, "DisableRealtimeMonitoring")
		tamper, tErr := nativeapi.RegDword(registry.LOCAL_MACHINE, defRoot+`\Features`, "TamperProtection")
		pua, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, defRoot, "PUAProtection")
		np, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, defRoot+`\Windows Defender Exploit Guard\Network Protection`, "EnableNetworkProtection")
		cfa, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, defRoot+`\Windows Defender Exploit Guard\Controlled Folder Access`, "EnableControlledFolderAccess")
		tamperLabel := "okunamadi(korumali olabilir)"
		if tErr == nil {
			if tamper == 5 {
				tamperLabel = "Açık(5)"
			} else {
				tamperLabel = fmt.Sprintf("%d", tamper)
			}
		}
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("RTP-disabled=%d; Tamper=%s; PUA=%d; NetworkProtection=%d; CFA=%d",
			disRTP, tamperLabel, pua, np, cfa)
		if disRTP == 1 {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskCritical
			r.Recommendation = "Real-time protection KAPALI — kritik."
		} else if tamper == 5 {
			r.Recommendation = "Tamper Protection açık (iyi). NP ve CFA da Block'a alinmali."
		} else {
			r.Recommendation = "Tamper Protection açık değil görünüyor — etkinlestirilmeli."
		}
	})

	// 03.2 ASR kurallari durumu (her GUID pasif okuma)
	b.add("CHT-03-002", "ASR kuralları durumu (per-GUID)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping = schema.Mapping{ASRID: "all-16", Attack: "T1562.001"}
		r.AttemptedMethods = []string{`registry ASR\Rules (GPO + local)`}
		// GPO ve local konumlari birlestir.
		merged := map[string]string{}
		for _, base := range []string{
			polRoot + `\Windows Defender Exploit Guard\ASR\Rules`,
			defRoot + `\Windows Defender Exploit Guard\ASR\Rules`,
		} {
			if vals, err := nativeapi.RegStringValues(registry.LOCAL_MACHINE, base); err == nil {
				for k, v := range vals {
					merged[strings.ToLower(k)] = v
				}
			}
		}
		block, audit, warn, off, unset := 0, 0, 0, 0, 0
		var notConfigured []string
		for _, rule := range asrRules {
			st, ok := merged[strings.ToLower(rule.guid)]
			if !ok {
				unset++
				notConfigured = append(notConfigured, rule.name)
				continue
			}
			switch st {
			case "1":
				block++
			case "2":
				audit++
			case "6":
				warn++
			default:
				off++
			}
		}
		r.Evidence = fmt.Sprintf("toplam=%d; Block=%d Audit=%d Warn=%d Off=%d Yapılandırılmamış=%d",
			len(asrRules), block, audit, warn, off, unset)
		switch {
		case block >= len(asrRules)-2:
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "ASR"
		case block > 0:
			r.Result = schema.ResultPartial
			r.Recommendation = "Eksik ASR kuralları Block'a alinmali: " + truncate(strings.Join(notConfigured, ", "), 200)
		default:
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskHigh
			r.Recommendation = "Hicbir ASR kuralı Block değil — 16 kural Block'a alinmali."
		}
	})

	// 03.3 ASR güvenli kanarya: "obfuscated script" kuralını (5beb7efe) BENIGN bir
	// obfuscated VBS ile test eder — diske gömülü zararlı yok, yalnız Chr()+Execute ile
	// zararsız bir echo. Engellenirse ASR/AMSI çalışıyor; çalışırsa kural kapalı/zayıf.
	b.add("CHT-03-003", "ASR obfuscated-script kanaryası (5beb7efe)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping = schema.Mapping{ASRID: "5beb7efe-fd9a-4556-801d-275e5ffc04cc", Attack: "T1562.001"}
		r.AttemptedMethods = []string{"benign obfuscated VBS (Chr+Execute)", "cscript //B ile çalıştır", "anında sil"}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		asrObfuscatedScriptCanary(ctx, r)
	})

	// 03.4 Kapatma denemesi (aktif) → engellenmeli
	b.add("CHT-03-004", "Defender kapatma denemesi (Set-MpPreference)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskCritical
		r.Mapping.Attack = "T1562.001"
		r.AttemptedMethods = []string{"Set-MpPreference -DisableRealtimeMonitoring $true (+ geri al)"}
		if !ctx.GateActive(r, 2, false) {
			return
		}
		psPath := filepath.Join(systemRoot(), `System32\WindowsPowerShell\v1.0\powershell.exe`)
		if !fileExists(psPath) {
			r.Result = schema.ResultError
			r.Evidence = "powershell.exe yok; deneme yapilamadi"
			return
		}
		// Dene; Tamper Protection bunu engellemeli. Hemen geri al.
		res := runCmd(15*time.Second, psPath, "-NoProfile", "-Command",
			"try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop; 'CHANGED' } catch { 'BLOCKED: ' + $_.Exception.Message } finally { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue }")
		if strings.Contains(res.Output, "CHANGED") {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskCritical
			r.Evidence = "Defender RTP kapatilabildi (geri alindi) — Tamper Protection etkisiz!"
			r.Recommendation = "Tamper Protection acilmalı."
		} else {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "Defender"
			r.Detected = schema.DetectedYes
			r.Evidence = "Kapatma engellendi: " + truncate(res.Output, 160)
		}
	})

	// 03.5 Exclusion ekleme denemesi (aktif) → engellenmeli
	b.add("CHT-03-005", "Defender exclusion ekleme denemesi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1562.001"
		r.AttemptedMethods = []string{"Add-MpPreference -ExclusionPath (+ geri al)"}
		if !ctx.GateActive(r, 2, false) {
			return
		}
		psPath := filepath.Join(systemRoot(), `System32\WindowsPowerShell\v1.0\powershell.exe`)
		if !fileExists(psPath) {
			r.Result = schema.ResultError
			r.Evidence = "powershell.exe yok"
			return
		}
		const excl = `C:\cht-test-exclusion-canary`
		res := runCmd(15*time.Second, psPath, "-NoProfile", "-Command",
			fmt.Sprintf("try { Add-MpPreference -ExclusionPath '%s' -ErrorAction Stop; 'ADDED' } catch { 'BLOCKED: ' + $_.Exception.Message } finally { Remove-MpPreference -ExclusionPath '%s' -ErrorAction SilentlyContinue }", excl, excl))
		if strings.Contains(res.Output, "ADDED") {
			r.Result = schema.ResultAllowed
			r.Evidence = "Exclusion eklenebildi (geri alindi) — kullanici exclusion ekleyebiliyor!"
			r.Recommendation = "Exclusion degisikligi standart kullaniciya kapatilmali."
		} else {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "Defender"
			r.Evidence = "Exclusion ekleme engellendi: " + truncate(res.Output, 160)
		}
	})

	// 03.6 AMSI provider envanteri (pasif/sessiz)
	b.add("CHT-03-006", "AMSI provider envanteri (çoklu tüketici)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskInfo
		r.AttemptedMethods = []string{"registry AMSI\\Providers", "amsi.dll varlik"}
		providers, _ := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\AMSI\Providers`)
		amsiDLL := fileExists(filepath.Join(systemRoot(), `System32\amsi.dll`))
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("amsi.dll=%v; kayitli provider=%d", amsiDLL, len(providers))
		if len(providers) == 0 {
			r.RiskWhenOpen = schema.RiskMedium
			r.Recommendation = "Kayitli AMSI provider yok — script tarama zayif olabilir."
		}
	})

	// 03.11 Exclusion listesi okunabilir mi (saldirgana istihbarat)
	b.add("CHT-03-011", "Mevcut exclusion listesi okunabilirliği", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1518.001"
		r.AttemptedMethods = []string{"registry Defender\\Exclusions"}
		paths, perr := nativeapi.RegValueNames(registry.LOCAL_MACHINE, defRoot+`\Exclusions\Paths`)
		procs, _ := nativeapi.RegValueNames(registry.LOCAL_MACHINE, defRoot+`\Exclusions\Processes`)
		exts, _ := nativeapi.RegValueNames(registry.LOCAL_MACHINE, defRoot+`\Exclusions\Extensions`)
		if perr != nil && len(procs) == 0 && len(exts) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Exclusion listesi standart kullaniciya okunamiyor (iyi)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("OKUNABILIR — path=%d process=%d ext=%d (saldirgana istihbarat)", len(paths), len(procs), len(exts))
		r.Recommendation = "Exclusion'lar standart kullanici tarafindan okunabiliyor; ACL gözden geçirilmeli."
	})

	// 03.10 EICAR (gürültülü [N]) — gerçek tetikleme, gate'li
	b.add("CHT-03-010", "EICAR test dosyası tespiti", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1562.001"
		r.AttemptedMethods = []string{"EICAR runtime üretimi (diske gömülü değil)", "Temp'e yaz", "AV tepkisi gözlemle"}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		eicarTest(ctx, r)
	})

	return b.results()
}

// asrObfuscatedScriptCanary, BENIGN ama obfuscated bir VBS yazip cscript ile calistirir.
// Amac: ASR "obfuscated script" kurali / AMSI bunu engelliyor mu? Zararli is yapmaz —
// yalniz bir marker echo eder. Manifest'e kaydedilir, aninda silinir.
func asrObfuscatedScriptCanary(ctx *harness.RunContext, r *schema.Result) {
	cscript := filepath.Join(systemRoot(), `System32\cscript.exe`)
	if !fileExists(cscript) {
		r.Result = schema.ResultNotApplicable
		r.SkipReason = schema.SkipNotApplicableOS
		r.Evidence = "cscript.exe yok — VBS kanaryası çalıştırılamaz"
		return
	}
	const marker = "ASR_CANARY_OK"
	path := filepath.Join(os.TempDir(), "cht-asr-canary.vbs")
	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(recordFileCreate(path, r.TestID))
	}
	if err := os.WriteFile(path, []byte(obfuscatedVBS(marker)), 0o600); err != nil {
		// Yazma sirasinda engellendiyse bu da bir tespittir.
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = "Defender"
		r.Detected = schema.DetectedYes
		r.Evidence = "Obfuscated VBS yazılamadı — on-access engelledi: " + truncate(err.Error(), 100)
		if ctx.Manifest != nil {
			ctx.Manifest.MarkActionUndone("file:" + path)
		}
		return
	}
	defer func() {
		_ = os.Remove(path)
		if ctx.Manifest != nil {
			ctx.Manifest.MarkActionUndone("file:" + path)
		}
	}()
	res := runCmd(15*time.Second, cscript, "//Nologo", "//B", path)
	switch {
	case strings.Contains(res.Output, marker):
		r.Result = schema.ResultAllowed
		r.Detected = schema.DetectedNo
		r.Evidence = "Obfuscated script ÇALIŞTI (marker üretildi) — ASR 'obfuscated script' kuralı / AMSI engellemedi"
		r.Recommendation = "ASR kuralı 5beb7efe Block'a alınmalı; AMSI script tarama doğrulanmalı."
	case res.TimedOut:
		r.Result = schema.ResultError
		r.SkipReason = schema.SkipTimeout
		r.Evidence = "Kanarya zaman aşımı"
	default:
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = "ASR"
		r.Detected = schema.DetectedYes
		r.Evidence = "Obfuscated script engellendi/çalışmadı — ASR/AMSI tepki verdi (iyi): " + truncate(res.Output, 120)
	}
}

// obfuscatedVBS, verilen marker'i echo eden BENIGN ama Chr()+Execute ile obfuscate
// edilmis bir VBS uretir (zararli is yok; yalniz heuristik tetikleyici desen).
func obfuscatedVBS(marker string) string {
	inner := `WScript.Echo "` + marker + `"`
	parts := make([]string, 0, len(inner))
	for _, c := range inner {
		parts = append(parts, fmt.Sprintf("Chr(%d)", c))
	}
	return "Execute(" + strings.Join(parts, "&") + ")\r\n"
}

// eicarString, standart EICAR test string'ini PARCALARDAN birlestirir (binary'ye butun
// halde gomulmez). Plan: "EICAR string'leri DISKE GOMULMEZ; test aninda uretilir".
func eicarString() string {
	parts := []string{
		`X5O!P%@AP[4\PZX54(P^)7CC)7}`,
		`$EICAR`,
		`-STANDARD-ANTIVIRUS-TEST-FILE!`,
		`$H+H*`,
	}
	s := ""
	for _, p := range parts {
		s += p
	}
	return s
}

// eicarTest, EICAR'i Temp'e yazip AV'nin engelleyip/karantinaya alip almadigini olcer.
func eicarTest(ctx *harness.RunContext, r *schema.Result) {
	path := filepath.Join(os.TempDir(), "cht-eicar.com")
	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(recordFileCreate(path, r.TestID))
	}
	werr := os.WriteFile(path, []byte(eicarString()), 0o600)
	exists := fileExists(path)
	_ = os.Remove(path) // kalan varsa temizle
	if ctx.Manifest != nil {
		ctx.Manifest.MarkActionUndone("file:" + path)
	}

	switch {
	case werr != nil:
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = "Defender"
		r.Detected = schema.DetectedYes
		r.DetectionEvidence = []string{"yazma sırasında engellendi (muhtemel Defender 1116)"}
		r.Evidence = "EICAR yazılamadı — AV on-access engelledi: " + truncate(werr.Error(), 100)
	case !exists:
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = "Defender"
		r.Detected = schema.DetectedYes
		r.DetectionEvidence = []string{"dosya anında karantinaya alındı (Defender 1116)"}
		r.Evidence = "EICAR yazıldı ama anında kaldırıldı/karantina — AV tespit etti (iyi)"
	default:
		r.Result = schema.ResultAllowed
		r.Detected = schema.DetectedNo
		r.RiskWhenOpen = schema.RiskHigh
		r.Evidence = "EICAR Temp'te kaldı, AV tepki vermedi — malware tespiti ZAYIF/kapalı"
		r.Recommendation = "Real-time protection ve on-access tarama doğrulanmalı."
	}
}
