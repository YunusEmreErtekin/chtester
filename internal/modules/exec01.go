package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"chtester/internal/harness"
	"chtester/internal/schema"
)

const cat01 = "01-Execution"

// Module01, kod calistirma yetenegini coklu vektorle test eder (plan: hedef 40-60+ vektor).
// Pasif kisim (binary varligi) her zaman koşar; aktif kisim (gercek launch) gate'lenir.
type Module01 struct{}

func NewModule01() *Module01 { return &Module01{} }

func (Module01) ID() string   { return "01" }
func (Module01) Name() string { return "Kod Çalıştırma Yeteneği" }

// lolbin, imzali MS binary ile proxy-execution yuzeyi (her biri ayri vektor).
type lolbin struct {
	id, name, bin, attack string
}

var lolbins = []lolbin{
	{"CHT-01-011", "rundll32 proxy execution", "rundll32.exe", "T1218.011"},
	{"CHT-01-012", "regsvr32 (scrobj)", "regsvr32.exe", "T1218.010"},
	{"CHT-01-013", "mshta (hta/inline)", "mshta.exe", "T1218.005"},
	{"CHT-01-014", "msbuild inline task", "msbuild.exe", "T1127.001"},
	{"CHT-01-015", "installutil/regasm/regsvcs", "installutil.exe", "T1218.004"},
	{"CHT-01-016", "msiexec paket/uzak", "msiexec.exe", "T1218.007"},
	{"CHT-01-017", "certutil decode/download", "certutil.exe", "T1140"},
	{"CHT-01-018", "bitsadmin download+exec", "bitsadmin.exe", "T1197"},
	{"CHT-01-019", "wmic XSL/process call", "wbem\\wmic.exe", "T1047"},
	{"CHT-01-020", "cmstp INF execution", "cmstp.exe", "T1218.003"},
	{"CHT-01-021", "mavinject DLL injection", "mavinject.exe", "T1055"},
	{"CHT-01-022", "msdt/ieexec/presentationhost", "msdt.exe", "T1218"},
	{"CHT-01-023", "csc/vbc/jsc anlik derleme", "", "T1027.004"}, // .NET SDK yolu degisken
	{"CHT-01-024", "diskshadow/esentutl/makecab/expand/extrac32", "esentutl.exe", "T1218"},
	{"CHT-01-025", "hh/control/verclsid/odbcconf/regini/forfiles/pcalua/ftp", "hh.exe", "T1218"},
	{"CHT-01-026", "scriptrunner/pubprn/syncappvpublishingserver/MpCmdRun/schtasks/winrs", "schtasks.exe", "T1218"},
}

func (m Module01) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat01)
	sr := systemRoot()

	// --- PowerShell vektorleri ---
	psPath := filepath.Join(sr, `System32\WindowsPowerShell\v1.0\powershell.exe`)

	b.add("CHT-01-001", "powershell.exe / pwsh / ISE açma", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.AttemptedMethods = []string{"os.Stat powershell.exe", "launch -Command"}
		if !fileExists(psPath) {
			r.Result = schema.ResultNotApplicable
			r.Evidence = "powershell.exe diskte yok"
			return
		}
		r.Result = schema.ResultPartial
		r.Evidence = "powershell.exe mevcut: " + psPath
		if ctx.ActiveAllowed() {
			res := runCmd(8*time.Second, psPath, "-NoProfile", "-NonInteractive", "-Command", "Write-Output OK")
			classifyExec(r, res, "powershell -Command")
		} else {
			r.Evidence += " (pasif: aktif launch yapilmadi)"
		}
	})

	b.add("CHT-01-002", "PS bayraklari: -ExecutionPolicy Bypass / -EncodedCommand", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.AttemptedMethods = []string{"-ExecutionPolicy Bypass -Command", "-EncodedCommand"}
		// Aktif-guvenli (gurultusuz) vektor, Tier 2 ister; tier+pasif+WhatIf kapilari
		// tek yerden (GateActive) zorlanir — onceden TierRequired atanip zorlanmiyordu.
		if !ctx.GateActive(r, 2, false) {
			return
		}
		if !fileExists(psPath) {
			r.Result = schema.ResultNotApplicable
			r.Evidence = "powershell.exe yok"
			return
		}
		// -ExecutionPolicy Bypass ile benign komut
		res := runCmd(8*time.Second, psPath, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Write-Output BYPASS_OK")
		// -EncodedCommand: 'Write-Output ENC_OK' UTF16LE base64
		enc := "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABFAE4AQwBfAE8ASwA=" // Write-Output ENC_OK
		res2 := runCmd(8*time.Second, psPath, "-NoProfile", "-EncodedCommand", enc)
		ok := strings.Contains(res.Output, "BYPASS_OK")
		ok2 := strings.Contains(res2.Output, "ENC_OK")
		switch {
		case ok && ok2:
			r.Result = schema.ResultAllowed
			r.Evidence = "ExecutionPolicy Bypass VE EncodedCommand calisti — kisitlama yok"
			r.Recommendation = "Constrained Language Mode + ScriptBlock logging + WDAC dusunulmeli."
		case ok || ok2:
			r.Result = schema.ResultPartial
			r.Evidence = fmt.Sprintf("bypass=%v encoded=%v", ok, ok2)
		default:
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = schema.BlockUnknown
			r.Evidence = "Her iki bayrak da sonuc uretmedi (kisitli olabilir)"
		}
	})

	b.add("CHT-01-004", "PS v2 downgrade yüzeyi (-Version 2)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.AttemptedMethods = []string{"registry PS2 engine", "-Version 2 launch"}
		ps2 := exists2Engine()
		if !ps2 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = schema.BlockNone
			r.Evidence = "PS v2 engine mevcut degil (iyi) — downgrade yüzeyi yok"
			return
		}
		r.Result = schema.ResultPartial
		r.Evidence = "PS v2 engine mevcut — AMSI/logging atlatma yüzeyi"
		r.Recommendation = "PowerShell v2 engine kaldirilmali (DISM/Optional Feature)."
		if ctx.ActiveAllowed() && fileExists(psPath) {
			res := runCmd(8*time.Second, psPath, "-NoProfile", "-Version", "2", "-Command", "Write-Output V2_OK")
			if strings.Contains(res.Output, "V2_OK") {
				r.Result = schema.ResultAllowed
				r.Evidence = "PS v2 ile gercekten calisti — atlatma yüzeyi acik"
			}
		}
	})

	// --- Diger yorumlayicilar ---
	addInterp(b, ctx, "CHT-01-007", "cmd.exe erişimi", filepath.Join(sr, `System32\cmd.exe`),
		[]string{"/c", "echo CMD_OK"}, "CMD_OK", schema.RiskMedium)
	addInterp(b, ctx, "CHT-01-008", "wscript/cscript (WSH)", filepath.Join(sr, `System32\cscript.exe`),
		nil, "", schema.RiskHigh)
	addInterp(b, ctx, "CHT-01-009", "mshta (hta/scriptlet)", filepath.Join(sr, `System32\mshta.exe`),
		nil, "", schema.RiskHigh)

	b.add("CHT-01-010", "wsl.exe / bash.exe ile kaçış", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"os.Stat wsl.exe/bash.exe"}
		var found []string
		for _, n := range []string{"wsl.exe", "bash.exe"} {
			p := filepath.Join(sr, "System32", n)
			if fileExists(p) {
				found = append(found, n)
			}
		}
		if len(found) == 0 {
			r.Result = schema.ResultNotApplicable
			r.Evidence = "wsl/bash diskte yok"
			return
		}
		r.Result = schema.ResultPartial
		r.Evidence = "mevcut: " + strings.Join(found, ", ")
		r.Recommendation = "WSL kurumsal cihazda gerekmiyorsa devre disi birakilmali."
	})

	// --- LOLBAS proxy-execution yuzeyi (her biri ayri vektor, pasif varlik) ---
	for _, l := range lolbins {
		l := l
		b.add(l.id, "LOLBAS: "+l.name, func(r *schema.Result) {
			r.RiskWhenOpen = schema.RiskMedium
			r.Mapping.Attack = l.attack
			r.AttemptedMethods = []string{"os.Stat System32/SysWOW64", "aktif: zararsız marker kanaryası (-EnableNoisy)"}
			if l.bin == "" {
				r.Result = schema.ResultPartial
				r.Evidence = ".NET derleyici yolu degisken; varlik manuel dogrulanmali"
				return
			}
			paths := binPaths(l.bin)
			if len(paths) == 0 {
				r.Result = schema.ResultNotApplicable
				r.Evidence = l.bin + " bulunamadi"
				return
			}
			r.Result = schema.ResultPartial
			r.Evidence = "mevcut (proxy-exec yüzeyi): " + strings.Join(paths, "; ")
			r.Recommendation = "AppLocker/WDAC ile bu LOLBin'in script-host davranisi kisitlanmali."
			// Aktif GERCEK engelleme testi — yalniz -EnableNoisy (Tier-agnostik, guvenli kanarya).
			if ctx.NoisyAllowed() {
				runLolbasCanary(ctx, r, l, paths[0])
			} else {
				r.Evidence += " — gerçek proxy-exec testi yapılmadı (yalnızca -EnableNoisy ile; aktif abuse)"
			}
		})
	}

	// --- Kanarya exec matrisi (aktif, gate'li) ---
	b.add("CHT-01-027", "Kanarya .cmd çalıştırma (Temp'ten)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1059.003"
		r.AttemptedMethods = []string{"Temp'e .cmd yaz", "cmd /c calistir"}
		if !ctx.GateActive(r, 2, false) {
			return
		}
		runCanaryCmd(ctx, r)
	})

	// --- Yazilabilir + calistirilabilir dizin avi (pasif ACL tarama) ---
	b.add("CHT-01-031", "Yazılabilir + çalıştırılabilir dizin avı", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1059"
		r.AttemptedMethods = []string{"yazma probe (AppLocker default-rule boşlukları)"}
		writable := huntWritableDirs()
		if len(writable) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Bilinen AppLocker-bypass dizinlerinin hicbirine yazilamiyor"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("%d yazilabilir konum: %s", len(writable), strings.Join(writable, "; "))
		r.Recommendation = "Bu dizinlerden calistirma AppLocker/WDAC path-rule ile engellenmeli; AppLocker default kurallari kullanici profilini (Desktop/Downloads), C:\\Windows\\Tasks, PerfLogs ve ikincil/cikarilabilir surucu koklerini (D:\\, USB) KAPSAMAZ — bu yollar icin explicit deny eklenmeli."
	})

	// --- MOTW etkisi (pasif bilgi) ---
	b.add("CHT-01-032", "Mark-of-the-Web (MOTW) etkisi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskInfo
		r.Result = schema.ResultPartial
		r.AttemptedMethods = []string{"ADS Zone.Identifier prensibi"}
		r.Evidence = "USB/indirilen dosyalarda MOTW SmartScreen tetikler; her aktif exec vektorunde ayri olculur"
		r.Recommendation = "MOTW korunmasi (Attachment Manager) acik tutulmali."
	})

	return b.results()
}

// addInterp, bir yorumlayici icin pasif varlik + (gate'liyse) aktif launch ekler.
func addInterp(b *builder, ctx *harness.RunContext, id, name, path string, runArgs []string, marker string, risk string) {
	b.add(id, name, func(r *schema.Result) {
		r.RiskWhenOpen = risk
		r.AttemptedMethods = []string{"os.Stat", "launch"}
		if !fileExists(path) {
			r.Result = schema.ResultNotApplicable
			r.Evidence = filepath.Base(path) + " diskte yok"
			return
		}
		r.Result = schema.ResultPartial
		r.Evidence = "mevcut: " + path
		if ctx.ActiveAllowed() && runArgs != nil && marker != "" {
			res := runCmd(8*time.Second, path, runArgs...)
			classifyExec(r, res, name)
		} else if runArgs == nil {
			r.Evidence += " (varlik tespiti; güvenli aktif launch tanimlanmadi)"
		} else {
			r.Evidence += " (pasif)"
		}
	})
}

// classifyExec, bir komut sonucunu Allowed/Blocked olarak siniflar.
func classifyExec(r *schema.Result, res runResult, method string) {
	switch {
	case res.TimedOut:
		r.Result = schema.ResultError
		r.SkipReason = schema.SkipTimeout
		r.Evidence = method + ": timeout"
	case res.Err == nil || res.ExitCode == 0:
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("%s calisti (exit=%d): %s", method, res.ExitCode, truncate(res.Output, 120))
	default:
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = schema.BlockUnknown
		r.Evidence = fmt.Sprintf("%s engellendi/hata (exit=%d): %s", method, res.ExitCode, truncate(res.Output, 160))
	}
}

// runCanaryCmd, Temp'e zararsiz bir .cmd yazip calistirir (manifest'e kaydeder), sonra siler.
func runCanaryCmd(ctx *harness.RunContext, r *schema.Result) {
	dir := os.TempDir()
	canary := filepath.Join(dir, "cht-canary.cmd")
	content := "@echo off\r\necho CANARY_OK\r\n"
	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(recordFileCreate(canary, r.TestID))
	}
	if err := os.WriteFile(canary, []byte(content), 0o600); err != nil {
		r.Result = schema.ResultError
		r.Evidence = "kanarya yazilamadi: " + err.Error()
		return
	}
	defer os.Remove(canary)
	res := runCmd(8*time.Second, filepath.Join(systemRoot(), `System32\cmd.exe`), "/c", canary)
	if strings.Contains(res.Output, "CANARY_OK") {
		r.Result = schema.ResultAllowed
		r.Evidence = "Temp'ten .cmd kanarya calisti — script-exec kisitlamasi yok"
		r.Recommendation = "AppLocker Script kuralı Temp'ten çalıştırmayı engellemeli."
	} else if res.TimedOut {
		r.Result = schema.ResultError
		r.SkipReason = schema.SkipTimeout
		r.Evidence = "kanarya timeout"
	} else {
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = schema.BlockUnknown
		r.Evidence = fmt.Sprintf("kanarya engellendi (exit=%d): %s", res.ExitCode, truncate(res.Output, 120))
	}
}

// huntWritableDirs, AppLocker default-rule boşlugu olarak bilinen dizinleri yazma icin yoklar.
func huntWritableDirs() []string {
	sr := systemRoot()
	userProfile := os.Getenv("USERPROFILE")
	candidates := []string{
		expand("%TEMP%"),
		expand("%LOCALAPPDATA%"),
		expand("%APPDATA%"),
		filepath.Join(userProfile, "Desktop"),   // PoC: kullanici profilinden exec (AppLocker default kapsamaz)
		filepath.Join(userProfile, "Downloads"), // indirilen payload'in tipik konumu
		expand("%PUBLIC%"),
		os.Getenv("ProgramData"),
		filepath.Join(sr, "Tasks"),
		filepath.Join(sr, "Temp"),
		filepath.Join(sr, "tracing"),
		filepath.Join(sr, "System32", "spool", "drivers", "color"),
		`C:\PerfLogs`,
	}
	var writable []string
	seen := map[string]bool{}
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if tryWriteProbe(c) {
			writable = append(writable, c)
		}
	}
	// Ikincil sabit disk (D:\) + cikarilabilir USB kokleri — AppLocker default
	// kurallarinin kapsamadigi, sahada dogrulanmis exec-allowed bosluk.
	for _, root := range extraWritableRoots() {
		if !seen[root] {
			seen[root] = true
			writable = append(writable, root)
		}
	}
	return writable
}

func exists2Engine() bool {
	// nativeapi uzerinden registry; basitlik icin context modülü zaten okuyor,
	// burada dosya/registry kontrolu yapariz.
	return fileExists(filepath.Join(systemRoot(), `System32\WindowsPowerShell\v1.0\powershell.exe`)) &&
		regKeyExists(`SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine`)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
