package context

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

const cat00 = "00-Context"

// Module00, 00 kesfini Env'den vektor sonuclarina cevirir.
type Module00 struct {
	Env       *Env
	ScopePath string // scope.json yolu (yetki artefakti); bos ise exe yaninda aranir
}

// NewModule00 olusturur.
func NewModule00(env *Env, scopePath string) *Module00 { return &Module00{Env: env, ScopePath: scopePath} }

func (m *Module00) ID() string   { return "00" }
func (m *Module00) Name() string { return "Ortam & Baglam Kesfi" }

func (m *Module00) Run(ctx *harness.RunContext) []schema.Result {
	e := m.Env
	var out []schema.Result

	add := func(id, name string, build func(r *schema.Result)) {
		start := time.Now()
		r := ctx.NewResult(id, cat00, name)
		r.RiskWhenOpen = schema.RiskInfo
		r.TierRequired = 0
		func() {
			defer func() {
				if p := recover(); p != nil {
					r.Result = schema.ResultError
					r.Evidence = fmt.Sprintf("vektor panigi (kurtarildi): %v", p)
				}
			}()
			build(r)
		}()
		ctx.Finalize(r, start)
		out = append(out, *r)
		ctx.Pace()
	}

	// 00.1 OS surum/build/edition/mimari
	add("CHT-00-001", "OS surum/build/edition/mimari", func(r *schema.Result) {
		r.AttemptedMethods = []string{"RtlGetVersion", "registry CurrentVersion"}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("OS %d.%d build %d; edition=%q; arch=%s",
			e.OSMajor, e.OSMinor, e.OSBuild, e.Edition, e.Arch)
		r.Recommendation = "Bilgilendirme: islem sistemi temel bilgisi."
	})

	// 00.2 DeviceId
	add("CHT-00-002", "DeviceId uretimi (filo anahtari)", func(r *schema.Result) {
		r.AttemptedMethods = []string{"sha256(hostname)+assetTag"}
		r.Result = schema.ResultAllowed
		r.Evidence = "deviceId=" + e.DeviceID + " (PII icermez)"
	})

	// 00.3 Domain/AzureAD/Intune
	add("CHT-00-003", "Domain / Azure AD / Intune yonetimi", func(r *schema.Result) {
		r.AttemptedMethods = []string{"registry CloudDomainJoin", "Tcpip Domain", "Enrollments"}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("domainJoin=%s; intuneManaged=%v", e.DomainJoin, e.IntuneManaged)
	})

	// 00.4 Kullanici / admin / integrity / privilege
	add("CHT-00-004", "Kullanici, integrity level, privilege listesi", func(r *schema.Result) {
		r.AttemptedMethods = []string{"OpenProcessToken", "GetTokenInformation"}
		r.Result = schema.ResultAllowed
		notable := notablePrivileges(e.Privileges)
		r.Evidence = fmt.Sprintf("user=%s; admin=%v; integrity=%s; notablePriv=%s",
			e.User, e.IsAdmin, e.IntegrityLevel, strings.Join(notable, ","))
		if len(notable) > 0 && !e.IsAdmin {
			r.RiskWhenOpen = schema.RiskMedium
			r.Result = schema.ResultAllowed
			r.Recommendation = "Privesc yuzeyi olabilecek privilege'ler mevcut (bkz. modul 04)."
		}
	})

	// 00.5 UAC
	add("CHT-00-005", "UAC seviyesi / prompt davranisi", func(r *schema.Result) {
		r.AttemptedMethods = []string{"registry System Policies"}
		el, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA")
		ca, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "ConsentPromptBehaviorAdmin")
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("EnableLUA=%d; ConsentPromptBehaviorAdmin=%d", el, ca)
		if el == 0 {
			r.RiskWhenOpen = schema.RiskHigh
			r.Recommendation = "UAC kapali (EnableLUA=0) — yuksek risk."
		}
	})

	// 00.6 PowerShell + LanguageMode + PS2
	add("CHT-00-006", "PowerShell surum + LanguageMode + PS2", func(r *schema.Result) {
		r.AttemptedMethods = []string{"registry PowerShellEngine surum", "native LanguageMode turetme (PSLockdownPolicy/AppLocker/WDAC)"}
		ps2 := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine`)
		if !e.PSAvailable {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = schema.BlockUnknown
			r.Evidence = "powershell.exe diskte bulunamadi"
		} else {
			r.Result = schema.ResultAllowed
			r.Evidence = fmt.Sprintf("PSVersion=%s; LanguageMode=%s (turetilen, pasif); PS2Engine=%v", e.PSVersion, e.PSLanguageMode, ps2)
		}
		if strings.EqualFold(e.PSLanguageMode, "ConstrainedLanguage") {
			r.Recommendation = "CLM aktif — script-tabanli saldiriya kismi engel (iyi)."
		} else if strings.EqualFold(e.PSLanguageMode, "FullLanguage") {
			r.RiskWhenOpen = schema.RiskMedium
			r.Recommendation = "FullLanguage — CLM/WDAC ile kisitlama dusunulebilir."
		}
		if ps2 {
			r.RiskWhenOpen = schema.RiskHigh
			r.Recommendation = "PS v2 engine mevcut — AMSI/ScriptBlock-logging atlatma yuzeyi; kaldirilmali."
		}
	})

	// 00.7 GPO / yerel guvenlik politikasi (pasif, best-effort)
	add("CHT-00-007", "Uygulanan GPO / yerel guvenlik politikasi", func(r *schema.Result) {
		r.AttemptedMethods = []string{"registry GroupPolicy\\History"}
		subs, err := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History`)
		if err != nil {
			r.Result = schema.ResultPartial
			r.Evidence = "GPO gecmisi okunamadi: " + err.Error()
		} else {
			r.Result = schema.ResultAllowed
			r.Evidence = fmt.Sprintf("%d GPO uzanti gecmisi tespit edildi", len(subs))
		}
	})

	// 00.8 EDR/AV tespiti
	add("CHT-00-008", "EDR/AV tespiti (servis/driver)", func(r *schema.Result) {
		r.AttemptedMethods = []string{"registry Services enum"}
		r.Result = schema.ResultAllowed
		if len(e.EDRDetected) == 0 {
			r.Evidence = "Bilinen EDR/AV servis imzasi tespit edilmedi (Defender dahil kontrol edildi)"
			r.RiskWhenOpen = schema.RiskMedium
			r.Recommendation = "EDR/AV tespit edilemedi — kapsam disinda olabilir veya yok."
		} else {
			r.Evidence = "edrDetected=" + strings.Join(e.EDRDetected, ", ")
		}
	})

	// 00.9 Sysmon / AMSI provider / ETW
	add("CHT-00-009", "Sysmon / AMSI provider / ETW erisilebilirligi", func(r *schema.Result) {
		r.AttemptedMethods = []string{"registry Sysmon", "AMSI providers"}
		amsi, _ := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\AMSI\Providers`)
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("sysmonPresent=%v; amsiProviders=%d", e.SysmonPresent, len(amsi))
	})

	// 00.12 Script host yollari
	add("CHT-00-012", "Script host'larin diskte varligi", func(r *schema.Result) {
		r.AttemptedMethods = []string{"os.Stat host yollari"}
		hosts := scriptHostPaths()
		r.Result = schema.ResultAllowed
		r.Evidence = "mevcut: " + strings.Join(hosts, ", ")
	})

	// 00.13 VM/sandbox self-tespiti
	add("CHT-00-013", "VM / sandbox self-tespiti", func(r *schema.Result) {
		r.AttemptedMethods = []string{"registry BIOS/SystemManufacturer"}
		vm, why := detectVM()
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("vm=%v (%s)", vm, why)
	})

	// 00.14 Scope artefakti + marker (aktif; PassiveOnly/WhatIf'te yazma yok)
	add("CHT-00-014", "Scope artefakti + marker dosyasi kontrolu", func(r *schema.Result) {
		r.TierRequired = 0
		r.AttemptedMethods = []string{"scope.json kontrol", "marker yazimi"}
		scopeFound, scopeInfo := m.checkScope()
		if scopeFound {
			r.Result = schema.ResultAllowed
			r.Evidence = "scope.json bulundu: " + scopeInfo
		} else {
			r.Result = schema.ResultPartial
			r.Evidence = "scope.json bulunamadi — gurultulu [N] testler kilitli kalir"
			r.Recommendation = "Yetkili gurultulu test icin imzali scope.json gerekli."
		}
		// Marker: Stealth'te YAZILMAZ; PassiveOnly/WhatIf'te de yazma yapmiyoruz (Faz 1).
		if ctx.IsStealth() {
			r.EvasionApplied = append(r.EvasionApplied, "no-marker")
			r.Evidence += "; marker yazilmadi (Stealth)"
		} else {
			r.Evidence += "; marker yazimi Faz 1'de devre disi (yalniz kontrol)"
		}
	})

	// 00.15 Capability Tier
	add("CHT-00-015", "Capability Tier belirleme", func(r *schema.Result) {
		r.AttemptedMethods = []string{"00 sinyal sentezi"}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("Tier=%d; gerekce=%s", e.Tier, e.TierReason)
		r.Recommendation = "Bu Tier'e gore vektor seti dallandirilir."
	})

	return out
}

func notablePrivileges(privs []string) []string {
	interesting := map[string]bool{
		"SeImpersonatePrivilege": true, "SeAssignPrimaryTokenPrivilege": true,
		"SeDebugPrivilege": true, "SeBackupPrivilege": true, "SeRestorePrivilege": true,
		"SeLoadDriverPrivilege": true, "SeTakeOwnershipPrivilege": true,
	}
	var out []string
	for _, p := range privs {
		if interesting[p] {
			out = append(out, p)
		}
	}
	return out
}

func scriptHostPaths() []string {
	sr := os.Getenv("SystemRoot")
	if sr == "" {
		sr = `C:\Windows`
	}
	candidates := map[string]string{
		"powershell": sr + `\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"wscript":    sr + `\System32\wscript.exe`,
		"cscript":    sr + `\System32\cscript.exe`,
		"mshta":      sr + `\System32\mshta.exe`,
		"cmd":        sr + `\System32\cmd.exe`,
	}
	var found []string
	for name, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			found = append(found, name)
		}
	}
	return found
}

func detectVM() (bool, string) {
	mfr, _ := nativeapi.RegString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemManufacturer")
	model, _ := nativeapi.RegString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName")
	hay := strings.ToLower(mfr + " " + model)
	for _, sig := range []string{"vmware", "virtualbox", "vbox", "qemu", "kvm", "xen", "hyper-v", "virtual machine", "microsoft corporation"} {
		if strings.Contains(hay, sig) {
			return true, mfr + " " + model
		}
	}
	return false, mfr + " " + model
}

// checkScope, scope.json'u (yetki artefakti) arar ve temel bilgisini doner.
func (m *Module00) checkScope() (bool, string) {
	paths := []string{}
	if m.ScopePath != "" {
		paths = append(paths, m.ScopePath)
	}
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "scope.json"))
	}
	paths = append(paths, "scope.json")
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return true, p
		}
	}
	return false, ""
}
