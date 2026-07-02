package modules

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat02 = "02-AppControl"

// Module02, uygulama kontrolu (AppLocker / WDAC / SRP / Smart App Control) durumunu okur.
type Module02 struct{}

func NewModule02() *Module02 { return &Module02{} }

func (Module02) ID() string   { return "02" }
func (Module02) Name() string { return "Uygulama Kontrolü (AppLocker/WDAC/SAC)" }

var appLockerCollections = []string{"Exe", "Msi", "Script", "Dll", "Appx"}

func (m Module02) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat02)

	// 02.1 AppLocker zorunlu mu (her koleksiyon ayri)
	b.add("CHT-02-001", "AppLocker enforcement (koleksiyon bazlı)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping = schema.Mapping{CIS: "AppLocker", MSBaseline: "App Control", Attack: "T1218"}
		r.AttemptedMethods = []string{`registry SrpV2\*\EnforcementMode`, "AppIDSvc state"}
		var states []string
		anyEnforced := false
		for _, col := range appLockerCollections {
			path := `SOFTWARE\Policies\Microsoft\Windows\SrpV2\` + col
			if !nativeapi.RegKeyExists(registry.LOCAL_MACHINE, path) {
				states = append(states, col+"=yapilandirilmamis")
				continue
			}
			mode, err := nativeapi.RegDword(registry.LOCAL_MACHINE, path, "EnforcementMode")
			if err != nil {
				states = append(states, col+"=kural-var/mode-okunamadi")
				continue
			}
			label := map[uint64]string{0: "AuditOnly", 1: "Enforce"}[mode]
			if label == "" {
				label = fmt.Sprintf("mode=%d", mode)
			}
			if mode == 1 {
				anyEnforced = true
			}
			states = append(states, col+"="+label)
		}
		svc := nativeapi.ServiceInstalled("AppIDSvc")
		r.Evidence = strings.Join(states, ", ") + fmt.Sprintf("; AppIDSvc=%v", svc)
		switch {
		case anyEnforced:
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "AppLocker"
			r.Recommendation = "Dll ve Appx koleksiyonlari da enforce edilmeli (Dll cogu yerde atlanir)."
		case strings.Contains(r.Evidence, "AuditOnly"):
			r.Result = schema.ResultPartial
			r.Recommendation = "AppLocker yalniz Audit modda — enforce'a alinmali."
		default:
			r.Result = schema.ResultAllowed
			r.Evidence += " — AppLocker yok/yapilandirilmamis"
			r.Recommendation = "AppLocker veya WDAC ile uygulama beyaz-listesi uygulanmali."
		}
	})

	// 02.2 WDAC mode + supplemental + ISG
	b.add("CHT-02-002", "WDAC (Code Integrity) durumu", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping = schema.Mapping{MSBaseline: "WDAC", Attack: "T1218"}
		r.AttemptedMethods = []string{"registry DeviceGuard", "CiPolicies\\Active *.cip"}
		// Aktif WDAC politikalari
		activeDir := filepath.Join(systemRoot(), `System32\CodeIntegrity\CiPolicies\Active`)
		var cips []string
		if entries, err := filepath.Glob(filepath.Join(activeDir, "*.cip")); err == nil {
			cips = entries
		}
		// Win32_DeviceGuard ile CALISAN durumu (registry "yapilandirilmis" degil): VBS/HVCI/CI-enforce.
		dg := deviceGuard()
		ciEnforced := dg.OK && dg.CIEnforce == 2
		if dg.OK {
			vbsTxt := map[int]string{0: "Off", 1: "Enabled-NotRunning", 2: "Running"}[dg.VBS]
			ciTxt := map[int]string{0: "Off", 1: "Audit", 2: "Enforced"}[dg.CIEnforce]
			r.Evidence = fmt.Sprintf("aktif .cip politika=%d; VBS=%s; HVCI(running)=%v; CodeIntegrity=%s (WMI Win32_DeviceGuard)",
				len(cips), vbsTxt, dg.HVCIRunning, ciTxt)
		} else {
			dgReg, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\DeviceGuard`, "EnableVirtualizationBasedSecurity")
			hvci, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, "Enabled")
			r.Evidence = fmt.Sprintf("aktif .cip politika=%d; VBS=%d; HVCI=%d (registry; WMI okunamadı)", len(cips), dgReg, hvci)
		}
		if len(cips) > 0 || ciEnforced || dg.HVCIRunning {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "WDAC"
		} else {
			r.Result = schema.ResultAllowed
			r.Evidence += " — dağıtılmış/çalışan WDAC politikası yok"
			r.Recommendation = "Yuksek-deger cihazlarda WDAC (ISG veya imza tabanli) + HVCI dusunulmeli."
		}
	})

	// 02.3 Smart App Control (Win11) + SRP legacy
	b.add("CHT-02-003", "Smart App Control + SRP (legacy)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"registry CI\\Policy", "Safer\\CodeIdentifiers"}
		sac, sacErr := nativeapi.RegDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\CI\Policy`, "VerifiedAndReputablePolicyState")
		sacLabel := "okunamadi"
		if sacErr == nil {
			sacLabel = map[uint64]string{0: "Off", 1: "Enforce", 2: "Evaluation"}[sac]
			if sacLabel == "" {
				sacLabel = fmt.Sprintf("%d", sac)
			}
		}
		srp := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers`)
		r.Evidence = fmt.Sprintf("SmartAppControl=%s; SRP-yapilandirilmis=%v", sacLabel, srp)
		if sac == 1 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "SmartAppControl"
		} else {
			r.Result = schema.ResultPartial
		}
	})

	// 02.4 Bypass: yazilabilir izinli yollar (01-031 ile ortak yüzey)
	b.add("CHT-02-004", "AppLocker bypass: yazılabilir izinli yollar", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1218"
		r.AttemptedMethods = []string{"yazma probe (default-rule boşlukları)", "ADS/UNC prensibi"}
		writable := huntWritableDirs()
		if len(writable) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Bilinen bypass dizinlerine yazilamiyor"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("%d yazilabilir izinli-yol adayi: %s", len(writable), strings.Join(writable, "; "))
		r.Recommendation = "AppLocker default kurallari yalniz %WINDIR%/%PROGRAMFILES%'e güvenir; kullanici profili (Desktop/Downloads), %SYSTEMDRIVE% boşlukları (Tasks, PerfLogs, spool) ve ikincil/cikarilabilir sürücüler (D:\\, USB) kapsam dışı — bu yollar icin explicit deny path-rule eklenmeli."
	})

	// 02.6 Engelleyen mekanizma + Event 8003 vs 8004 ayrimi (pasif: loglama acik mi)
	b.add("CHT-02-006", "AppLocker log kanalı (8003 audit / 8004 block)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskInfo
		r.AttemptedMethods = []string{"EXE/DLL log kanali enabled kontrolu"}
		// AppLocker EXE+DLL operasyonel kanali registry'de enabled mi
		enabled := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppLocker/EXE and DLL`)
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("AppLocker EXE/DLL log kanali kayitli=%v; 8003/8004 ayrimi aktif exec testlerinde olculur", enabled)
		r.Recommendation = "8004 (block) olaylari SIEM'e forward edilmeli."
	})

	return b.results()
}
