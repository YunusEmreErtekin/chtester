package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/schema"
)

const cat19 = "19-DataExfil"

// Module19, VERI SIZINTISI derinligini olcer: kisitli calisan cihazdan sirket verisini
// disari cikarma kanallari. Modul 06 (USB/pano/tethering) uzerine ekler; hepsi PASIF
// (dosya varligi + registry). Soru: calisan bu cihazdan veriyi nasil sizdirabilir?
type Module19 struct{}

func NewModule19() *Module19 { return &Module19{} }

func (Module19) ID() string   { return "19" }
func (Module19) Name() string { return "Veri Sızıntısı Derinliği" }

func (m Module19) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat19)
	sys := filepath.Join(systemRoot(), "System32")

	// 19.1 Yerlesik + ucuncu-parti exfil CLI araclari (curl/ftp/scp/certutil/bitsadmin + rclone/aws)
	b.add("CHT-19-001", "Yerleşik/harici exfil araçları (curl/ftp/scp/certutil/rclone)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1048"
		r.AttemptedMethods = []string{"System32 + OpenSSH + PATH taraması"}
		builtin := presentBase([]string{
			filepath.Join(sys, "curl.exe"), filepath.Join(sys, "ftp.exe"), filepath.Join(sys, "tftp.exe"),
			filepath.Join(sys, "certutil.exe"), filepath.Join(sys, "bitsadmin.exe"),
			filepath.Join(sys, "OpenSSH", "ssh.exe"), filepath.Join(sys, "OpenSSH", "scp.exe"),
		})
		var third []string
		for _, t := range []string{"rclone", "aws", "wget", "ncat", "megatools", "gdrive", "rsync"} {
			if _, err := exec.LookPath(t); err == nil {
				third = append(third, t)
			}
		}
		all := append(append([]string{}, builtin...), third...)
		r.Evidence = fmt.Sprintf("yerleşik=%s; harici=%s", orNone(builtin), orNone(third))
		if len(all) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Bu araçlar tek-komut veri sızıntısı sağlar; standart kullanıcı için AppLocker/WDAC ile kısıtlanmalı (curl/ftp/certutil/bitsadmin dahil)."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — bilinen exfil aracı bulunamadı"
		}
	})

	// 19.2 Kisisel bulut depolama istemcileri (Dropbox/Google Drive/MEGA/Box)
	b.add("CHT-19-002", "Kişisel bulut depolama istemcisi (Dropbox/Drive/MEGA)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1567.002"
		r.AttemptedMethods = []string{"kurulu istemci yol taraması"}
		pf := os.Getenv("ProgramFiles")
		pf86 := os.Getenv("ProgramFiles(x86)")
		lad := os.Getenv("LOCALAPPDATA")
		ad := os.Getenv("APPDATA")
		cand := map[string][]string{
			"Dropbox":       {filepath.Join(pf, "Dropbox"), filepath.Join(ad, "Dropbox"), filepath.Join(lad, "Dropbox")},
			"Google Drive":  {filepath.Join(pf, "Google", "Drive File Stream"), filepath.Join(pf, "Google", "DriveFS")},
			"MEGAsync":      {filepath.Join(lad, "MEGAsync"), filepath.Join(pf, "MEGAsync")},
			"Box":           {filepath.Join(pf, "Box", "Box"), filepath.Join(lad, "Box")},
			"pCloud":        {filepath.Join(pf86, "pCloud Drive"), filepath.Join(lad, "pCloud")},
			"iCloud":        {filepath.Join(pf, "Common Files", "Apple", "Internet Services")},
		}
		var found []string
		for name, paths := range cand {
			for _, p := range paths {
				if p != "" && dirExists(p) {
					found = append(found, name)
					break
				}
			}
		}
		if len(found) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Kişisel bulut depolama istemcisi bulunamadı"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "Kurulu kişisel bulut istemcisi: " + strings.Join(found, ", ")
		r.Recommendation = "Kişisel bulut istemcileri kurumsal veri için onaylı olmayan senkron kanalıdır; kaldırılmalı/engellenmeli (AppLocker + ağ)."
	})

	// 19.3 Arsivleyiciler — sifreli arsiv ile icerik-DLP baypas
	b.add("CHT-19-003", "Arşivleyici (şifreli arşivle content-DLP baypas)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1560.001"
		r.AttemptedMethods = []string{"7-Zip/WinRAR/WinZip yol taraması"}
		pf := os.Getenv("ProgramFiles")
		pf86 := os.Getenv("ProgramFiles(x86)")
		found := presentBase([]string{
			filepath.Join(pf, "7-Zip", "7z.exe"), filepath.Join(pf86, "7-Zip", "7z.exe"),
			filepath.Join(pf, "WinRAR", "Rar.exe"), filepath.Join(pf86, "WinRAR", "Rar.exe"),
			filepath.Join(pf, "WinRAR", "WinRAR.exe"), filepath.Join(pf86, "WinRAR", "WinRAR.exe"),
			filepath.Join(pf, "WinZip", "winzip64.exe"), filepath.Join(pf86, "WinZip", "winzip32.exe"),
		})
		if len(found) == 0 {
			r.Result = schema.ResultPartial
			r.RiskWhenOpen = schema.RiskLow
			r.Evidence = "Harici arşivleyici yok (yerleşik ZIP şifreleme desteklemez — kısmi koruma)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "Parola-korumalı arşiv yapabilen araç: " + strings.Join(found, ", ")
		r.Recommendation = "Şifreli arşiv içerik-tabanlı DLP'yi baypas eder; arşivleyiciler kısıtlanmalı veya DLP arşiv-içi inceleme yapmalı."
	})

	// 19.4 Tasinabilir medya cikisi: CD/DVD yazma + WPD/MTP (telefon)
	b.add("CHT-19-004", "Taşınabilir medya çıkışı (CD/DVD yazma + WPD/MTP)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1052.001"
		r.AttemptedMethods = []string{"registry NoCDBurning + RemovableStorageDevices WPD Deny_Write"}
		noCD, hasNoCD := duHKCU(`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`, "NoCDBurning")
		// WPD (telefon/kamera/MTP) yazma reddi — GPO sinifi GUID'i
		const wpdClass = `SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}`
		wpdDeny, hasWpd := dwLM(wpdClass, "Deny_Write")
		cdOpen := !hasNoCD || noCD == 0
		wpdOpen := !hasWpd || wpdDeny == 0
		r.Evidence = fmt.Sprintf("NoCDBurning=%s; WPD.Deny_Write=%s", dwState(hasNoCD, noCD), dwState(hasWpd, wpdDeny))
		var open []string
		if cdOpen {
			open = append(open, "CD/DVD yazma açık")
		}
		if wpdOpen {
			open = append(open, "WPD/MTP (telefon) yazma açık")
		}
		if len(open) > 0 {
			r.Result = schema.ResultAllowed
			r.Evidence += " → " + strings.Join(open, ", ")
			r.Recommendation = "Taşınabilir medyaya yazma kısıtlanmalı: NoCDBurning=1 + RemovableStorageDevices WPD/MTP Deny_Write=1 (telefon üzerinden exfil dahil)."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — CD ve WPD yazma politikayla kapalı"
		}
	})

	// 19.5 Yerel posta verisi — mevcut .pst/.ost (exfile-hazir) + cross-account kopya
	b.add("CHT-19-005", "Yerel posta verisi (.pst/.ost dışa aktarma)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1114.001"
		r.AttemptedMethods = []string{"Outlook veri dosyası taraması"}
		lad := os.Getenv("LOCALAPPDATA")
		up := os.Getenv("USERPROFILE")
		dirs := []string{
			filepath.Join(lad, "Microsoft", "Outlook"),
			filepath.Join(up, "Documents", "Outlook Files"),
		}
		var files []string
		for _, d := range dirs {
			files = append(files, scanExt(d, []string{".pst"})...)
		}
		if len(files) == 0 {
			r.Result = schema.ResultPartial
			r.RiskWhenOpen = schema.RiskLow
			r.Evidence = "Yerel .pst (dışa aktarılmış posta) bulunamadı"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("%d yerel .pst dosyası (dışa aktarılabilir posta arşivi): %s",
			len(files), truncate(strings.Join(files, "; "), 200))
		r.Recommendation = "PST dışa aktarma kısıtlanmalı (PstDisableGrow/DisablePst); mevcut PST'ler taşınabilir kurumsal veri arşividir."
	})

	return b.results()
}

// --- yardimcilar ---

// presentBase, verilen mutlak yollardan var olanlarin taban adini doner.
func presentBase(paths []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || !fileExists(p) {
			continue
		}
		base := filepath.Base(p)
		if !seen[base] {
			seen[base] = true
			out = append(out, base)
		}
	}
	return out
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// duHKCU, HKCU altindan DWORD okur.
func duHKCU(path, name string) (uint64, bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return v, true
}

// scanExt, bir dizinde (recursive DEGIL) verilen uzantilardaki dosyalari doner.
func scanExt(dir string, exts []string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		low := strings.ToLower(e.Name())
		for _, x := range exts {
			if strings.HasSuffix(low, x) {
				out = append(out, filepath.Join(dir, e.Name()))
				break
			}
		}
		if len(out) >= 15 {
			break
		}
	}
	return out
}
