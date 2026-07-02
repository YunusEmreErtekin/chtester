package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat21 = "21-EvasionPhysical"

// Module21, YURUTME KACISI ve FIZIKSEL/KURTARMA erisimini olcer: calisan, izlemesiz bir
// ortamda (VM/WSL/yorumlayici) kod calistirip EDR/AppLocker'i baypas edebilir mi; ya da
// kurtarma ortami/offline erisimle cihaza fiziksel zarar verebilir mi? Pasif (varlik +
// registry + WMI). Modul 12-009 yalniz Windows OZELLIGI (WSL/Hyper-V feature) bakar; bu
// modul KURULU hypervisor'lari, WSL DISTROLARINI ve yorumlayicilari kapsar.
type Module21 struct{}

func NewModule21() *Module21 { return &Module21{} }

func (Module21) ID() string   { return "21" }
func (Module21) Name() string { return "Yürütme Kaçış & Fiziksel Erişim" }

func (m Module21) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat21)

	// 21.1 Kurulu hypervisor / VM & WSL distro — izlemesiz OS icinde calisma (EDR baypas)
	b.add("CHT-21-001", "İzlemesiz yürütme ortamı (hypervisor / VM / WSL distro)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1564.006"
		r.AttemptedMethods = []string{"hypervisor yol/servis + WSL Lxss distro taraması"}
		pf := os.Getenv("ProgramFiles")
		pf86 := os.Getenv("ProgramFiles(x86)")
		var found []string
		if dirExists(filepath.Join(pf, "VMware", "VMware Workstation")) || fileExists(filepath.Join(pf86, "VMware", "VMware Workstation", "vmware.exe")) {
			found = append(found, "VMware Workstation")
		}
		if fileExists(filepath.Join(pf, "Oracle", "VirtualBox", "VirtualBox.exe")) {
			found = append(found, "VirtualBox")
		}
		if nativeapi.ServiceInstalled("vmms") {
			found = append(found, "Hyper-V (vmms)")
		}
		if d := wslDistros(); len(d) > 0 {
			found = append(found, "WSL distro: "+strings.Join(d, ","))
		}
		if len(found) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Kurulu hypervisor / WSL distro yok — izlemesiz OS yürütme yüzeyi yok"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "İzlemesiz yürütme ortamı: " + strings.Join(found, "; ")
		r.Recommendation = "VM/WSL içinde çalışan kod ana-OS EDR/AppLocker'ını baypas eder; kurumsal cihazda hypervisor/WSL kısıtlanmalı (yalnız onaylı senaryolar)."
	})

	// 21.2 Yorumlayici/runtime yuzeyi — AppLocker EXE kurallarini script ile baypas
	b.add("CHT-21-002", "Yorumlayıcı/runtime yüzeyi (Python/Node/Perl/Git-bash)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1059.006"
		r.AttemptedMethods = []string{"PATH + kurulum yolu taraması"}
		var found []string
		for _, t := range []string{"python", "python3", "node", "perl", "ruby", "php", "pwsh", "tclsh", "lua"} {
			if _, err := exec.LookPath(t); err == nil {
				found = append(found, t)
			}
		}
		// Git-bash (bash.exe WSL DEGIL, MSYS)
		pf := os.Getenv("ProgramFiles")
		if fileExists(filepath.Join(pf, "Git", "bin", "bash.exe")) || fileExists(filepath.Join(pf, "Git", "usr", "bin", "bash.exe")) {
			found = append(found, "git-bash")
		}
		if len(found) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Ek yorumlayıcı/runtime bulunamadı (AppLocker EXE kuralı için daha az baypas)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "Kurulu yorumlayıcı: " + strings.Join(found, ", ") +
			" — bunlar imzalı EXE olduğundan AppLocker EXE kurallarını script ile baypas edebilir"
		r.Recommendation = "Gerekmeyen yorumlayıcılar kaldırılmalı; gerekliyse AppLocker Script + Constrained Language ile sarılmalı."
	})

	// 21.3 Kurtarma ortami (WinRE) & offline tampering yuzeyi
	b.add("CHT-21-003", "Kurtarma ortamı (WinRE) & offline disk tampering", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1542"
		r.AttemptedMethods = []string{"WinRE.wim/ReAgent varlığı + BitLocker(C:) koruma durumu (WMI)"}
		sr := systemRoot()
		winrePresent := fileExists(filepath.Join(`C:\Recovery\WindowsRE`, "Winre.wim")) ||
			fileExists(filepath.Join(sr, "System32", "Recovery", "ReAgent.xml"))
		// BitLocker OS birimi (C:) korumali mi — offline tampering'i BitLocker engeller.
		osProtected, known := osVolumeBitLockerOn()
		switch {
		case known && osProtected:
			r.Result = schema.ResultBlocked
			r.Evidence = fmt.Sprintf("WinRE mevcut=%v; C: BitLocker korumalı=EVET — offline/WinRE disk tampering şifreleme ile engelli", winrePresent)
		case known && !osProtected:
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskCritical
			r.Evidence = fmt.Sprintf("WinRE mevcut=%v; C: BitLocker korumalı=HAYIR — WinRE (Shift+Restart) / USB boot ile diski offline mount edip yerel admin sıfırlama, SAM dökümü, Defender kapatma mümkün", winrePresent)
			r.Recommendation = "ACİL: OS birimi BitLocker ile şifrelenmeli (pre-boot auth); aksi halde fiziksel erişimi olan biri (veya çalışan) offline SYSTEM erişimi alır."
		default:
			r.Result = schema.ResultPartial
			r.Evidence = fmt.Sprintf("WinRE mevcut=%v; C: BitLocker durumu belirlenemedi (WMI erişimi yok olabilir) — fiziksel/offline risk BitLocker'a bağlı", winrePresent)
			r.Recommendation = "BitLocker OS birimi koruma durumu elle doğrulanmalı (manage-bde -status); şifreli değilse offline tampering açıktır."
		}
	})

	return b.results()
}

// --- yardimcilar ---

// wslDistros, kurulu WSL dagitimlarini (HKCU Lxss) doner.
func wslDistros() []string {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Lxss`, registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()
	subs, _ := k.ReadSubKeyNames(-1)
	var out []string
	for _, s := range subs {
		name, _ := nativeapi.RegString(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Lxss\`+s, "DistributionName")
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// osVolumeBitLockerOn, C: biriminin BitLocker koruma durumunu WMI ile okur.
// (protected, known). WMI erisilemezse known=false.
func osVolumeBitLockerOn() (protected, known bool) {
	rows, err := nativeapi.WMIQuery(`root\cimv2\Security\MicrosoftVolumeEncryption`,
		`SELECT DriveLetter,ProtectionStatus FROM Win32_EncryptableVolume`,
		[]string{"DriveLetter", "ProtectionStatus"})
	if err != nil || len(rows) == 0 {
		return false, false
	}
	sysDrive := strings.ToUpper(os.Getenv("SystemDrive")) // "C:"
	if sysDrive == "" {
		sysDrive = "C:"
	}
	for _, v := range rows {
		if strings.EqualFold(v["DriveLetter"], sysDrive) {
			return v["ProtectionStatus"] == "1", true
		}
	}
	return false, true // C: listede yoksa korumasiz kabul (bilgi mevcut)
}
