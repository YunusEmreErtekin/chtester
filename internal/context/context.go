// Package context, 00 kesfini, Capability Tier belirlemeyi ve EDR/AV tespitini saglar.
// Plan: "Cihaz-Durumu / Capability Tier Matrisi" + modul 00.
package context

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/nativeapi"
)

// Env, 00 kesfinden toplanan ham ortam bilgisidir.
type Env struct {
	Hostname        string
	DeviceID        string
	OSMajor         uint32
	OSMinor         uint32
	OSBuild         uint32
	Edition         string
	Arch            string
	IsAdmin         bool
	IntegrityLevel  string
	User            string
	Privileges      []string
	DomainJoin      string // Workgroup|Domain|AzureAD|Hybrid
	IntuneManaged   bool
	PSAvailable     bool
	PSVersion       string
	PSLanguageMode  string // FullLanguage|ConstrainedLanguage|Unknown
	EDRDetected     []string
	SysmonPresent   bool
	Tier            int
	TierReason      string
}

// edrSignatures, bilinen EDR/AV urunlerinin servis/driver adlari.
var edrSignatures = []struct {
	Name     string
	Services []string
}{
	{"Microsoft Defender", []string{"WinDefend", "WdNisSvc", "Sense"}}, // Sense = MDE
	{"CrowdStrike Falcon", []string{"CSFalconService", "CSAgent"}},
	{"SentinelOne", []string{"SentinelAgent", "SentinelStaticEngine"}},
	{"Palo Alto Cortex XDR", []string{"cyserver", "cyverak", "traps"}},
	{"Carbon Black", []string{"CbDefense", "carbonblack", "cbstream"}},
	{"Cylance", []string{"CylanceSvc", "CyOptics"}},
	{"Sophos", []string{"SophosED", "Sophos Endpoint Defense Service", "hmpalertsvc"}},
	{"Trend Micro", []string{"TmListen", "ntrtscan", "Trend Micro Endpoint Basecamp"}},
	{"ESET", []string{"ekrn", "EraAgentSvc"}},
}

// Discover, ortam bilgisini toplar (00 modulunun ham veri toplama adimi).
func Discover() *Env {
	e := &Env{}
	e.Hostname, _ = os.Hostname()
	e.DeviceID = deviceID(e.Hostname)
	e.OSMajor, e.OSMinor, e.OSBuild = nativeapi.OSVersion()
	e.Edition, _ = nativeapi.RegString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "ProductName")
	e.Arch = nativeapi.NormalizeArch(detectArch())
	e.IsAdmin = nativeapi.IsElevated()
	e.IntegrityLevel = nativeapi.IntegrityLevel()
	e.User = nativeapi.CurrentUser()
	e.Privileges = nativeapi.Privileges()
	e.DomainJoin, e.IntuneManaged = domainState()
	e.PSAvailable, e.PSVersion, e.PSLanguageMode = psState()
	e.EDRDetected = detectEDR()
	e.SysmonPresent = nativeapi.ServiceInstalled("Sysmon") || nativeapi.ServiceInstalled("SysmonDrv") || nativeapi.ServiceInstalled("Sysmon64")
	e.Tier, e.TierReason = determineTier(e)
	return e
}

// deviceID, hash(hostname)+asset tag. KVKK/gizlilik temiz (PII icermez).
func deviceID(hostname string) string {
	asset, _ := nativeapi.RegString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemSerialNumber")
	h := sha256.Sum256([]byte(strings.ToLower(hostname)))
	id := hex.EncodeToString(h[:])[:16]
	if asset != "" {
		ah := sha256.Sum256([]byte(asset))
		return id + "-" + hex.EncodeToString(ah[:])[:8]
	}
	return id
}

func detectArch() string {
	a := os.Getenv("PROCESSOR_ARCHITECTURE")
	if w := os.Getenv("PROCESSOR_ARCHITEW6432"); w != "" {
		a = w // WOW64 altinda gercek mimari
	}
	return a
}

// domainState, domain/AzureAD/Intune durumunu registry'den pasif okur.
func domainState() (string, bool) {
	intune := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments`) &&
		hasMDMEnrollment()
	// Azure AD join: dsregcmd yerine registry.
	aadJoined := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`)
	// Domain join: ComputerName domain bilgisi.
	domain, _ := nativeapi.RegString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, "Domain")
	partOfDomain := domain != ""

	switch {
	case partOfDomain && aadJoined:
		return "Hybrid", intune
	case aadJoined:
		return "AzureAD", intune
	case partOfDomain:
		return "Domain", intune
	default:
		return "Workgroup", intune
	}
}

func hasMDMEnrollment() bool {
	subs, err := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments`)
	if err != nil {
		return false
	}
	for _, s := range subs {
		if v, _ := nativeapi.RegString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments\`+s, "ProviderID"); v != "" {
			return true
		}
	}
	return false
}

// psState, PowerShell varligi + surum + LanguageMode'u TAMAMEN PASIF (native) belirler.
// Plan ilkesi "double-blind / Stealth": arac kesif sirasinda powershell.exe BASLATMAZ —
// aksi halde kendi 4688/ScriptBlock telemetrisini uretip olctugu loglama vektorunu
// (CHT-12-004) ve Stealth profilini kirletirdi. Surum registry'den, LanguageMode ise
// gercek dunyadaki CLM tetikleyicilerinden (PSLockdownPolicy / AppLocker-script-enforce /
// WDAC-enforce) turetilir.
func psState() (available bool, version, langMode string) {
	if findPowerShell() == "" {
		return false, "", "Unknown"
	}
	return true, psVersionFromRegistry(), deriveLanguageMode()
}

// psVersionFromRegistry, PowerShell surumunu registry'den okur (spawn yok).
func psVersionFromRegistry() string {
	for _, key := range []string{
		`SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine`, // PS 5/5.1
		`SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine`, // PS 2
	} {
		if v, err := nativeapi.RegString(registry.LOCAL_MACHINE, key, "PowerShellVersion"); err == nil && v != "" {
			return v
		}
	}
	return ""
}

// deriveLanguageMode, PowerShell LanguageMode'unu spawn ETMEDEN turetir. CLM su
// durumlarda zorlanir: __PSLockdownPolicy=4; AppLocker Script koleksiyonu enforce;
// WDAC (DeviceGuard CI) enforce. Hicbiri yoksa FullLanguage varsayilir (turetilen,
// gozlemlenen degil). FullLanguage'a meyil, degerlendirmeyi daha kapsamli Tier'a iter.
func deriveLanguageMode() string {
	if os.Getenv("__PSLockdownPolicy") == "4" {
		return "ConstrainedLanguage"
	}
	if mode, err := nativeapi.RegDword(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script`, "EnforcementMode"); err == nil && mode == 1 {
		return "ConstrainedLanguage"
	}
	// WDAC UMCI enforce (registry sinyali; COM olmadan best-effort).
	if v, err := nativeapi.RegDword(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\DeviceGuard`, "EnableVirtualizationBasedSecurity"); err == nil && v == 1 {
		if ci, err2 := nativeapi.RegDword(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\DeviceGuard`, "RequirePlatformSecurityFeatures"); err2 == nil && ci > 0 {
			return "ConstrainedLanguage"
		}
	}
	return "FullLanguage"
}

func findPowerShell() string {
	candidates := []string{
		os.Getenv("SystemRoot") + `\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath("powershell.exe"); err == nil {
		return p
	}
	return ""
}

// detectEDR, registry servis anahtarlarindan EDR/AV urunlerini pasif tespit eder.
func detectEDR() []string {
	var found []string
	for _, sig := range edrSignatures {
		for _, svc := range sig.Services {
			if nativeapi.ServiceInstalled(svc) {
				found = append(found, sig.Name)
				break
			}
		}
	}
	return found
}

// determineTier, 00 sinyallerinden Capability Tier belirler.
// chtester.exe calisiyorsa exe en az calisiyor demektir -> taban Tier 1.
func determineTier(e *Env) (int, string) {
	if e.IsAdmin {
		return 3, "Local admin token (yukseltilmis) tespit edildi"
	}
	switch strings.ToLower(e.PSLanguageMode) {
	case "fulllanguage":
		return 2, "Standart kullanici + PS FullLanguage"
	case "constrainedlanguage":
		return 1, "exe calisiyor ama PS ConstrainedLanguage"
	}
	if !e.PSAvailable {
		return 1, "exe calisiyor, PowerShell bulunamadi/bloklu"
	}
	return 1, fmt.Sprintf("exe calisiyor, PS LanguageMode belirsiz (%q)", e.PSLanguageMode)
}
