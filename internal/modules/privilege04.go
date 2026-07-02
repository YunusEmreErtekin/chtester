package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat04 = "04-Privilege"

// Module04, ayricalik ve UAC yuzeyini pasif okur (privesc firsatlari).
type Module04 struct{}

func NewModule04() *Module04 { return &Module04{} }

func (Module04) ID() string   { return "04" }
func (Module04) Name() string { return "Ayrıcalık & UAC" }

func (m Module04) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat04)

	// 04.1 Local admin + UAC
	b.add("CHT-04-001", "Local admin üyeliği + UAC seviyesi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		admin := nativeapi.IsElevated()
		el, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA")
		ca, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "ConsentPromptBehaviorAdmin")
		r.AttemptedMethods = []string{"token elevation", "registry UAC policy"}
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("elevated=%v; integrity=%s; EnableLUA=%d; ConsentPromptBehaviorAdmin=%d",
			admin, nativeapi.IntegrityLevel(), el, ca)
		if admin {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskCritical
			r.Recommendation = "Kullanici yukseltilmis token tasiyor — standart kullanici prensibi ihlali."
		} else if el == 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "UAC kapali (EnableLUA=0)."
		}
	})

	// 04.3 UAC bypass yuzeyi (auto-elevate binary varligi + ayarlar)
	b.add("CHT-04-003", "UAC bypass yüzeyi (auto-elevate binary'ler)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1548.002"
		r.AttemptedMethods = []string{"auto-elevate binary varligi", "ConsentPromptBehaviorAdmin"}
		var present []string
		sysdir := filepath.Join(systemRoot(), "System32")
		for _, bin := range []string{"fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "eventvwr.exe", "slui.exe"} {
			if fileExists(filepath.Join(sysdir, bin)) {
				present = append(present, bin)
			}
		}
		ca, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "ConsentPromptBehaviorAdmin")
		r.Evidence = fmt.Sprintf("auto-elevate binary mevcut=%s; ConsentPromptBehaviorAdmin=%d", strings.Join(present, ","), ca)
		if ca == 0 || ca == 5 {
			r.Result = schema.ResultPartial
			r.Recommendation = "ConsentPromptBehaviorAdmin=2 (her zaman güvenli masaüstünde sor) onerilir; fodhelper-tarzi bypass yüzeyi mevcut."
		} else {
			r.Result = schema.ResultPartial
		}
	})

	// 04.4 Token privilege privesc yuzeyi
	b.add("CHT-04-004", "Token privilege privesc yüzeyi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1134"
		r.AttemptedMethods = []string{"GetTokenInformation privileges"}
		dangerous := map[string]string{
			"SeImpersonatePrivilege":        "Potato (impersonation)",
			"SeAssignPrimaryTokenPrivilege": "Potato (primary token)",
			"SeDebugPrivilege":              "process bellek/inject",
			"SeBackupPrivilege":             "SAM/SYSTEM okuma",
			"SeRestorePrivilege":            "korumali yazma",
			"SeLoadDriverPrivilege":         "kernel driver yukleme",
			"SeTakeOwnershipPrivilege":      "sahiplik ele gecirme",
		}
		var hits []string
		for _, p := range nativeapi.Privileges() {
			if desc, ok := dangerous[p]; ok {
				hits = append(hits, p+" ("+desc+")")
			}
		}
		if len(hits) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Tehlikeli privesc privilege'i yok"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "Privesc yüzeyi: " + strings.Join(hits, "; ")
		r.Recommendation = "Bu privilege'ler standart kullanici token'inda olmamali."
	})

	// 04.5 AlwaysInstallElevated
	b.add("CHT-04-005", "AlwaysInstallElevated (HKLM + HKCU)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskCritical
		r.Mapping.Attack = "T1548.002"
		r.AttemptedMethods = []string{"registry HKLM+HKCU Installer"}
		hklm, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated")
		hkcu, _ := nativeapi.RegDword(registry.CURRENT_USER, `SOFTWARE\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated")
		r.Evidence = fmt.Sprintf("HKLM=%d; HKCU=%d", hklm, hkcu)
		if hklm == 1 && hkcu == 1 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "AlwaysInstallElevated her iki hive'da AÇIK — doğrudan SYSTEM privesc! Kapatilmali."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — privesc icin ikisi de 1 olmali (degil)"
		}
	})

	// 04.6 Unquoted service path + yazilabilir segment
	b.add("CHT-04-006", "Unquoted service path + yazılabilir segment", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1574.009"
		r.AttemptedMethods = []string{"Services\\*\\ImagePath analizi"}
		vuln := findUnquotedServicePaths()
		if len(vuln) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Sömürülebilir unquoted service path bulunamadi"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("%d aday: %s", len(vuln), truncate(strings.Join(vuln, " | "), 240))
		r.Recommendation = "Service ImagePath'leri tirnak icine alinmali."
	})

	// 04.8 Yazilabilir PATH dizini (DLL hijack yuzeyi)
	b.add("CHT-04-008", "Yazılabilir PATH dizini (DLL hijack)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1574.007"
		r.AttemptedMethods = []string{"%PATH% segment yazma probe"}
		var writable []string
		for _, p := range filepath.SplitList(os.Getenv("PATH")) {
			if p == "" {
				continue
			}
			if tryWriteProbe(p) {
				writable = append(writable, p)
			}
		}
		if len(writable) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "PATH dizinlerinin hicbiri yazilabilir degil"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("%d yazilabilir PATH dizini: %s", len(writable), strings.Join(writable, "; "))
		r.Recommendation = "Yazilabilir PATH dizinleri DLL/exe hijack yüzeyidir; kaldirilmali."
	})

	// 04.9 Gomulu credential (unattend/sysprep/winlogon autologon)
	b.add("CHT-04-009", "Gömülü credential (unattend/sysprep/autologon)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskCritical
		r.Mapping.Attack = "T1552.001"
		r.AttemptedMethods = []string{"unattend/sysprep dosyalari", "Winlogon AutoAdminLogon"}
		var hits []string
		sr := systemRoot()
		for _, f := range []string{
			filepath.Join(sr, `Panther\Unattend.xml`),
			filepath.Join(sr, `Panther\Unattended.xml`),
			filepath.Join(sr, `System32\Sysprep\unattend.xml`),
			`C:\unattend.xml`,
		} {
			if fileExists(f) {
				hits = append(hits, "dosya:"+f)
			}
		}
		auto, _ := nativeapi.RegString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "AutoAdminLogon")
		defPwd, _ := nativeapi.RegString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "DefaultPassword")
		if auto == "1" || defPwd != "" {
			hits = append(hits, fmt.Sprintf("Winlogon AutoAdminLogon=%s DefaultPassword-set=%v", auto, defPwd != ""))
		}
		if len(hits) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Bilinen konumlarda gömülü credential bulunamadi"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = strings.Join(hits, "; ")
		r.Recommendation = "Gömülü/autologon credential temizlenmeli."
	})

	return b.results()
}

// findUnquotedServicePaths, tirnaksiz + boslukli ImagePath'leri (kabaca) tespit eder.
func findUnquotedServicePaths() []string {
	const base = `SYSTEM\CurrentControlSet\Services`
	subs, err := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, base)
	if err != nil {
		return nil
	}
	var vuln []string
	for _, s := range subs {
		img, err := nativeapi.RegString(registry.LOCAL_MACHINE, base+`\`+s, "ImagePath")
		if err != nil || img == "" {
			continue
		}
		t := strings.TrimSpace(img)
		if strings.HasPrefix(t, `"`) {
			continue // tirnakli
		}
		// .exe oncesi bosluk var mi (kabaca)
		low := strings.ToLower(t)
		idx := strings.Index(low, ".exe")
		if idx < 0 {
			continue
		}
		head := t[:idx]
		if strings.Contains(head, " ") && !strings.HasPrefix(low, `\??\`) {
			vuln = append(vuln, s+": "+truncate(t, 80))
		}
	}
	return vuln
}
