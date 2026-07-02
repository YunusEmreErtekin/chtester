package modules

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat12 = "12-OSHardening"

// Module12, OS sertlestirme / cesitli pasif kontrolleri okur (cogu dusuk risk, yuksek deger).
type Module12 struct{}

func NewModule12() *Module12 { return &Module12{} }

func (Module12) ID() string   { return "12" }
func (Module12) Name() string { return "OS Sertleştirme / Çeşitli" }

// dwLM, HKLM altinda DWORD okur (yoksa 0,false).
func dwLM(path, name string) (uint64, bool) {
	v, err := nativeapi.RegDword(registry.LOCAL_MACHINE, path, name)
	return v, err == nil
}

func (m Module12) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat12)

	// 12.1 Windows Update zorunlu & guncel mi
	b.add("CHT-12-001", "Windows Update yapılandırması", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"registry WindowsUpdate\\AU"}
		noAuto, _ := dwLM(`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoUpdate")
		auOpt, _ := dwLM(`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "AUOptions")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("NoAutoUpdate=%d; AUOptions=%d (4=otomatik indir+kur)", noAuto, auOpt)
		if noAuto == 1 {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskHigh
			r.Recommendation = "Otomatik güncelleme KAPALI — açılmalı."
		}
	})

	// 12.2 SMB / LLMNR / NBT-NS / WPAD poisoning yuzeyi
	b.add("CHT-12-002", "SMBv1 / SMB signing / LLMNR / WPAD", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1557.001"
		r.AttemptedMethods = []string{"registry LanmanServer/DNSClient"}
		smb1, _ := dwLM(`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1")
		sign, _ := dwLM(`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "RequireSecuritySignature")
		llmnr, llmnrOk := dwLM(`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast")
		var issues []string
		if smb1 == 1 {
			issues = append(issues, "SMBv1 AÇIK")
		}
		if sign != 1 {
			issues = append(issues, "SMB signing zorunlu değil")
		}
		if !llmnrOk || llmnr != 0 {
			issues = append(issues, "LLMNR kapatılmamış (poisoning yüzeyi)")
		}
		r.Evidence = fmt.Sprintf("SMB1=%d; RequireSecuritySignature=%d; EnableMulticast(LLMNR)=%d", smb1, sign, llmnr)
		if len(issues) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Düzeltilmeli: " + strings.Join(issues, "; ")
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — temel ayarlar sağlam"
		}
	})

	// 12.3 NTLM kisitlari
	b.add("CHT-12-003", "NTLM kısıtları (LmCompatibility / outbound)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1557"
		r.AttemptedMethods = []string{"registry Lsa"}
		lm, _ := dwLM(`SYSTEM\CurrentControlSet\Control\Lsa`, "LmCompatibilityLevel")
		restrict, _ := dwLM(`SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`, "RestrictSendingNTLMTraffic")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("LmCompatibilityLevel=%d (5=sadece NTLMv2); RestrictSendingNTLMTraffic=%d", lm, restrict)
		if lm < 3 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "LmCompatibilityLevel 5'e alınmalı (NTLMv1/LM engelle)."
		}
	})

	// 12.4 PowerShell logging + 4688 cmdline + Sysmon
	b.add("CHT-12-004", "Logging duruşu (PS / 4688 cmdline / Sysmon)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.AttemptedMethods = []string{"registry PowerShell logging / Audit"}
		sb, _ := dwLM(`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging")
		ml, _ := dwLM(`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`, "EnableModuleLogging")
		tr, _ := dwLM(`SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`, "EnableTranscripting")
		cmd, _ := dwLM(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`, "ProcessCreationIncludeCmdLine_Enabled")
		sysmon := nativeapi.ServiceInstalled("Sysmon") || nativeapi.ServiceInstalled("Sysmon64")
		var missing []string
		if sb != 1 {
			missing = append(missing, "ScriptBlock")
		}
		if ml != 1 {
			missing = append(missing, "ModuleLogging")
		}
		if tr != 1 {
			missing = append(missing, "Transcription")
		}
		if cmd != 1 {
			missing = append(missing, "4688-cmdline")
		}
		r.Evidence = fmt.Sprintf("ScriptBlock=%d Module=%d Transcript=%d 4688cmd=%d Sysmon=%v", sb, ml, tr, cmd, sysmon)
		if len(missing) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Eksik loglama (tespit kör noktası): " + strings.Join(missing, ", ")
		} else {
			r.Result = schema.ResultBlocked
			r.Detected = schema.DetectedYes
			r.Evidence += " — loglama kapsamlı"
		}
	})

	// 12.5 WEF (Event Forwarding)
	b.add("CHT-12-005", "Event Forwarding (WEF) yapılandırması", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"registry EventLog\\EventForwarding\\SubscriptionManager"}
		subs, err := nativeapi.RegValueNames(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager`)
		if err != nil || len(subs) == 0 {
			r.Result = schema.ResultAllowed
			r.Evidence = "WEF aboneliği yok — loglar merkeze forward edilmiyor"
			r.Recommendation = "WEF ile kritik loglar merkezi toplayıcıya forward edilmeli."
		} else {
			r.Result = schema.ResultBlocked
			r.Detected = schema.DetectedYes
			r.Evidence = fmt.Sprintf("%d WEF subscription manager tanımlı", len(subs))
		}
	})

	// 12.6 Event log temizleme YETENEGI — pasif/guvenli: log SILMEDEN, yalniz yetenek olcer.
	// Security event log'unu temizlemek SeSecurityPrivilege + elevation ister; bu sinyal
	// anti-forensics yuzeyini hicbir kalinti birakmadan gosterir.
	b.add("CHT-12-006", "Event log temizleme yeteneği (silmeden)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1070.001"
		r.AttemptedMethods = []string{"token privilege probe (SeSecurityPrivilege) + elevation — TEMIZLEMEDEN"}
		elevated := nativeapi.IsElevated()
		hasSec := nativeapi.HasPrivilege("SeSecurityPrivilege")
		r.Evidence = fmt.Sprintf("elevated=%v; SeSecurityPrivilege=%v", elevated, hasSec)
		if elevated && hasSec {
			r.Result = schema.ResultAllowed
			r.Evidence += " — Security event log temizlenebilir (anti-forensics yüzeyi; log SİLİNMEDİ)"
			r.Recommendation = "Event log temizleme yeteneği izlenmeli (Event 1102) ve WEF ile loglar merkeze forward edilmeli (bkz. CHT-12-005)."
		} else {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "Permission"
			r.Evidence += " — Security log temizleme yetkisi yok (iyi)"
		}
	})

	// 12.15 Gelismis denetim (advanced audit) politikasi — native AuditQuerySystemPolicy
	b.add("CHT-12-015", "Gelişmiş denetim politikası (logon/process/object-access)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"native AuditQuerySystemPolicy (auditpol shell-out yok)"}
		settings, ok := nativeapi.AdvancedAuditPolicy()
		if !ok {
			r.Result = schema.ResultPartial
			r.Evidence = "Denetim politikası okunamadı (SeSecurityPrivilege/admin gerekir)"
			r.Recommendation = "Admin oturumda gelişmiş denetim politikası (logon/process/object-access) doğrulanmalı."
			return
		}
		var missing, parts []string
		for _, s := range settings {
			st := "off"
			switch {
			case s.Success && s.Failure:
				st = "S+F"
			case s.Success:
				st = "S"
			case s.Failure:
				st = "F"
			}
			parts = append(parts, s.Name+"="+st)
			if !s.Success && !s.Failure {
				missing = append(missing, s.Name)
			}
		}
		r.Evidence = strings.Join(parts, "; ")
		if len(missing) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Denetim kapalı alt-kategoriler (tespit kör noktası): " + strings.Join(missing, ", ")
		} else {
			r.Result = schema.ResultBlocked
			r.Detected = schema.DetectedYes
			r.Evidence += " — kritik denetim alt-kategorileri açık"
		}
	})

	// 12.7 Guest/AutoRun/WSH
	b.add("CHT-12-007", "Guest hesap / AutoRun / WSH", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"registry Explorer/WSH"}
		noAutorun, _ := dwLM(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`, "NoDriveTypeAutoRun")
		wsh, wshOk := dwLM(`SOFTWARE\Microsoft\Windows Script Host\Settings`, "Enabled")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("NoDriveTypeAutoRun=0x%X; WSH.Enabled=%d(set=%v)", noAutorun, wsh, wshOk)
		if noAutorun < 0xFF {
			r.Result = schema.ResultAllowed
			r.Recommendation = "AutoRun tüm sürücüler için kapatılmalı (NoDriveTypeAutoRun=0xFF)."
		}
	})

	// 12.8 Office makro policy
	b.add("CHT-12-008", "Office makro politikası + Protected View", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1059.005"
		r.AttemptedMethods = []string{"registry HKCU Office\\*\\Security"}
		// Office surumlerini tara (16.0, 15.0)
		var findings []string
		blocked := false
		for _, ver := range []string{"16.0", "15.0"} {
			for _, app := range []string{"Word", "Excel", "PowerPoint"} {
				base := fmt.Sprintf(`SOFTWARE\Policies\Microsoft\Office\%s\%s\Security`, ver, app)
				blk, blkErr := nativeapi.RegDword(registry.CURRENT_USER, base, "blockcontentexecutionfrominternet")
				vba, vbaErr := nativeapi.RegDword(registry.CURRENT_USER, base, "VBAWarnings")
				if blkErr == nil || vbaErr == nil {
					findings = append(findings, fmt.Sprintf("%s/%s blockNet=%d VBAWarnings=%d", ver, app, blk, vba))
					if blk == 1 {
						blocked = true
					}
				}
			}
		}
		if len(findings) == 0 {
			r.Result = schema.ResultPartial
			r.Evidence = "Office makro politikası registry'de bulunamadı (Office yok veya policy uygulanmamış)"
			r.Recommendation = "İnternetten makro engelleme (blockcontentexecutionfrominternet=1) uygulanmalı."
			return
		}
		r.Evidence = strings.Join(findings, "; ")
		if blocked {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "İnternetten makro çalıştırma engellenmeli."
		}
	})

	// 12.9 WSL / Hyper-V / Sandbox / Dev mode
	b.add("CHT-12-009", "WSL / Hyper-V / Sandbox / Developer mode", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"servis/registry"}
		devmode, _ := dwLM(`SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock`, "AllowDevelopmentWithoutDevLicense")
		wsl := nativeapi.ServiceInstalled("LxssManager")
		hyperv := nativeapi.ServiceInstalled("vmms")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("WSL=%v; Hyper-V=%v; DeveloperMode=%d", wsl, hyperv, devmode)
		if devmode == 1 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Developer mode açık — appx sideloading yüzeyi; kapatılmalı."
		}
	})

	// 12.10 LAPS / Credential Guard / VBS / HVCI
	b.add("CHT-12-010", "LAPS / Credential Guard / VBS / HVCI", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"WMI Win32_DeviceGuard (çalışan)", "registry LAPS/Lsa"}
		lapsNew := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Policies\LAPS`)
		lapsOld := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft Services\AdmPwd`)
		lsaCfg, _ := dwLM(`SYSTEM\CurrentControlSet\Control\Lsa`, "LsaCfgFlags")
		// Win32_DeviceGuard ile CredGuard/VBS'in GERCEKTEN calistigini teyit et.
		dg := deviceGuard()
		var cgDesc string
		cgRunning := dg.OK && dg.CredGuardRunning
		if dg.OK {
			vbsTxt := map[int]string{0: "Off", 1: "Enabled-NotRunning", 2: "Running"}[dg.VBS]
			cgDesc = fmt.Sprintf("CredentialGuard(running)=%v; VBS=%s (WMI)", dg.CredGuardRunning, vbsTxt)
		} else {
			cgDesc = fmt.Sprintf("CredentialGuard(LsaCfgFlags=%d); WMI okunamadı", lsaCfg)
		}
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("LAPS(new=%v old=%v); %s", lapsNew, lapsOld, cgDesc)
		var rec []string
		if !lapsNew && !lapsOld {
			rec = append(rec, "LAPS yok (yerel admin parolası rotasyonu)")
		}
		if !cgRunning {
			rec = append(rec, "Credential Guard çalışmıyor (VBS + CredGuard etkinleştirilmeli)")
		}
		if len(rec) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = strings.Join(rec, "; ")
		} else {
			r.Evidence += " — LAPS + Credential Guard aktif (iyi)"
		}
	})

	// 12.11 Remote registry / WinRM / RDP-NLA / Print Spooler
	b.add("CHT-12-011", "Remote yönetim maruziyeti (WinRM/RDP/Spooler)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1021"
		r.AttemptedMethods = []string{"servis durumu + registry"}
		denyRDP, _ := dwLM(`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections")
		nla, _ := dwLM(`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication")
		spooler := nativeapi.ServiceInstalled("Spooler")
		spoolerStart, _ := dwLM(`SYSTEM\CurrentControlSet\Services\Spooler`, "Start")
		winrm := nativeapi.ServiceInstalled("WinRM")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("RDP-deny=%d NLA=%d; Spooler kayıtlı=%v(Start=%d); WinRM=%v", denyRDP, nla, spooler, spoolerStart, winrm)
		var rec []string
		if denyRDP == 0 && nla != 1 {
			rec = append(rec, "RDP açık ve NLA zorunlu değil")
		}
		if spoolerStart != 4 {
			rec = append(rec, "Print Spooler çalışıyor (PrintNightmare yüzeyi) — gerekmez ise kapatılmalı")
		}
		if len(rec) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = strings.Join(rec, "; ")
		}
	})

	// 12.12 Removable storage policy + rogue root CA
	b.add("CHT-12-012", "Rogue kök CA sayısı (sertifika store)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1553.004"
		r.AttemptedMethods = []string{"registry SystemCertificates\\Root"}
		machineCAs, _ := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\SystemCertificates\Root\Certificates`)
		gpoCAs, _ := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates`)
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("makine kök CA=%d; GPO-dağıtılan kök CA=%d", len(machineCAs), len(gpoCAs))
		r.Recommendation = "Kök CA store beklenmedik (kurumsal TLS-inspection harici) sertifika için incelenmeli (bkz. 07.5)."
	})

	// 12.13 Registry araç kısıtlaması (DisableRegistryTools) — kozmetik mi gerçek mi?
	// Saha bulgusu: regedit GUI gizlense bile reg.exe/regini/.reg ile registry erişimi
	// HÂLÂ açıksa, "düzeltme" kozmetiktir. DisableRegistryTools YALNIZ regedit.exe'yi etkiler.
	b.add("CHT-12-013", "Registry araç kısıtlaması (DisableRegistryTools) — kozmetik mi?", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1112"
		r.AttemptedMethods = []string{`registry Policies\System DisableRegistryTools (HKCU+HKLM)`, "reg.exe/regini varlık"}
		hkcu, _ := nativeapi.RegDword(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DisableRegistryTools")
		hklm, _ := dwLM(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DisableRegistryTools")
		drt := hkcu
		if hklm > drt {
			drt = hklm
		}
		regExe := len(binPaths("reg.exe")) > 0
		reginiExe := len(binPaths("regini.exe")) > 0
		r.Evidence = fmt.Sprintf("DisableRegistryTools HKCU=%d HKLM=%d; reg.exe=%v regini.exe=%v", hkcu, hklm, regExe, reginiExe)
		switch {
		case drt >= 1 && (regExe || reginiExe):
			r.Result = schema.ResultAllowed
			r.Evidence += " — regedit GUI kısıtlı AMA reg.exe/regini ile registry erişimi açık (KOZMETİK düzeltme)"
			r.Recommendation = "DisableRegistryTools yalnız regedit GUI'sini gizler; reg.exe/PowerShell/.reg/regini hâlâ yazar. Gerçek kısıt AppLocker/WDAC ile registry araçlarını engellemeyi + HKCU\\Run izlemeyi gerektirir (bkz. CHT-12-014)."
		case drt >= 1:
			r.Result = schema.ResultPartial
			r.Evidence += " — regedit kısıtlı; alternatif registry araçları diskte yok"
		default:
			r.Result = schema.ResultPartial
			r.Evidence += " — registry araç kısıtlaması yok (regedit açık). Asıl risk yazma/persistence yüzeyi: bkz. CHT-12-014"
		}
	})

	// 12.14 HKCU persistence yazma yüzeyi (Run/RunOnce) — pasif ACL probe (kalıntısız).
	// Saha bulgusunun asıl riski: standart kullanıcı admin OLMADAN açılışta kod
	// çalıştırma (persistence) kurabiliyor mu? (CHT-05-001 aynısını -EnableNoisy ile
	// AKTİF doğrular; bu, varsayılan pasif çalışmada da görünen baseline'dır.)
	b.add("CHT-12-014", "HKCU persistence yazma yüzeyi (Run/RunOnce) — pasif", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1547.001"
		r.AttemptedMethods = []string{"ACL yazma probe (SET_VALUE aç, değer yazma)"}
		runW := canRegWrite(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
		runOnceW := canRegWrite(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`)
		hklmRunW := canRegWrite(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
		r.Evidence = fmt.Sprintf("HKCU\\Run yazılabilir=%v; HKCU\\RunOnce yazılabilir=%v; HKLM\\Run yazılabilir=%v", runW, runOnceW, hklmRunW)
		switch {
		case runW || runOnceW:
			r.Result = schema.ResultAllowed
			r.Evidence += " — standart kullanıcı admin olmadan açılışta kod çalıştırma (persistence) kurabilir"
			r.Recommendation = "HKCU Run/RunOnce yazımı ASR (T1547) + EDR ile izlenmeli; HKCU ACL ile kapatılamaz, tespit/yanıt katmanı şart. Aktif doğrulama: CHT-05-001 (-EnableNoisy)."
			if hklmRunW {
				r.RiskWhenOpen = schema.RiskCritical
				r.Evidence += "; AYRICA HKLM\\Run yazılabilir — sistem geneli persistence (yanlış ACL veya admin token)"
			}
		default:
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "Permission"
			r.Evidence += " — Run anahtarlarına yazma reddedildi"
		}
	})

	return b.results()
}
