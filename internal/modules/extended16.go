package modules

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat16 = "16-Extended"

// Module16, ilk katalogda atlanan ama yuksek-deger pasif kontrolleri ekler: firmware
// (Secure Boot), yerel hesap hijyeni, anonim enum, Windows Recall, pano gecmisi,
// anti-ransomware (VSS), yama guncelligi, Windows Hello, PrintNightmare, NetBIOS/mDNS,
// bulut senkron, kamera/mikrofon + cihaz kontrolu. Hepsi pasif registry/native.
type Module16 struct{}

func NewModule16() *Module16 { return &Module16{} }

func (Module16) ID() string   { return "16" }
func (Module16) Name() string { return "Genişletilmiş Sertleştirme" }

func (m Module16) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat16)

	// 16.1 Secure Boot (UEFI)
	b.add("CHT-16-001", "Secure Boot (UEFI) durumu", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1542.003"
		r.AttemptedMethods = []string{`registry SecureBoot\State\UEFISecureBootEnabled`}
		v, ok := dwLM(`SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled")
		if !ok {
			r.Result = schema.ResultPartial
			r.Evidence = "Secure Boot durumu okunamadı (Legacy/BIOS boot olabilir)"
			r.Recommendation = "UEFI + Secure Boot etkinleştirilmeli (bootkit/rootkit koruması)."
			return
		}
		r.Evidence = fmt.Sprintf("UEFISecureBootEnabled=%d", v)
		if v == 1 {
			r.Result = schema.ResultBlocked
			r.Evidence += " — Secure Boot AÇIK"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Secure Boot KAPALI — bootkit/imzasız boot bileşeni riski; UEFI'de açılmalı."
		}
	})

	// 16.2 Yerel admin hesap envanteri
	b.add("CHT-16-002", "Yerel admin / built-in hesap hijyeni", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1078.003"
		r.AttemptedMethods = []string{"native NetUserEnum + SID/RID (built-in 500/501)"}
		la := nativeapi.LocalAccounts()
		if !la.OK {
			r.Result = schema.ResultPartial
			r.Evidence = "Yerel hesaplar listelenemedi"
			return
		}
		r.Evidence = fmt.Sprintf("yerel hesap=%d; etkin admin=%d; built-in Administrator(RID500) etkin=%v (ad=%q); Guest etkin=%v",
			la.Total, la.EnabledAdmins, la.BuiltinAdminEnabled, la.BuiltinAdminName, la.GuestEnabled)
		var issues []string
		// Yerel Administrators grubunun TAM uyeligi (ic ice AD gruplari dahil) — yetki sisme
		// ve lateral hareket yuzeyi. NetLocalGroupGetMembers, sadece NetUserEnum sayiminin
		// goremedigi domain gruplarini/kullanicilarini da yakalar.
		if am := nativeapi.LocalAdminMembers(); am.OK && len(am.Members) > 0 {
			host := os.Getenv("COMPUTERNAME")
			var names []string
			adGroups, localUsers := 0, 0
			for _, mb := range am.Members {
				names = append(names, fmt.Sprintf("%s(%s)", mb.Name, mb.Type))
				dom, acct := mb.Name, mb.Name
				if i := strings.IndexByte(mb.Name, '\\'); i >= 0 {
					dom, acct = mb.Name[:i], mb.Name[i+1:]
				}
				isLocal := strings.EqualFold(dom, host)
				switch {
				case !isLocal && mb.Type == "Grup":
					adGroups++
				case isLocal && mb.Type == "Kullanıcı" && !strings.EqualFold(acct, la.BuiltinAdminName):
					localUsers++ // built-in Administrator disindaki standing yerel admin'ler
				}
			}
			r.Evidence += fmt.Sprintf(" | Administrators üyeleri (%d): %s", len(am.Members), strings.Join(names, ", "))
			if localUsers > 0 {
				issues = append(issues, fmt.Sprintf("%d yerel admin kullanıcı (built-in dışı standing admin)", localUsers))
			}
			if adGroups > 2 {
				issues = append(issues, fmt.Sprintf("%d AD grubu doğrudan yerel admin (yetki şişkinliği; üyelik dolaylı büyür)", adGroups))
			}
		}
		if la.BuiltinAdminEnabled {
			issues = append(issues, "built-in Administrator etkin (LAPS+devre dışı önerilir)")
		}
		if la.GuestEnabled {
			issues = append(issues, "Guest hesabı etkin")
		}
		if la.EnabledAdmins > 2 {
			issues = append(issues, fmt.Sprintf("%d etkin yerel admin (fazla)", la.EnabledAdmins))
		}
		if strings.EqualFold(la.BuiltinAdminName, "Administrator") {
			issues = append(issues, "built-in admin yeniden adlandırılmamış")
		}
		if len(issues) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Düzeltilmeli: " + strings.Join(issues, "; ") + "."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — yerel hesap hijyeni makul"
		}
	})

	// 16.3 Anonim enumerasyon / null-session
	b.add("CHT-16-003", "Anonim enumerasyon / null-session kısıtı", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1087"
		r.AttemptedMethods = []string{"registry Lsa RestrictAnonymous*/LocalAccountTokenFilterPolicy"}
		ra, _ := dwLM(`SYSTEM\CurrentControlSet\Control\Lsa`, "RestrictAnonymous")
		rasam, _ := dwLM(`SYSTEM\CurrentControlSet\Control\Lsa`, "RestrictAnonymousSAM")
		everyone, _ := dwLM(`SYSTEM\CurrentControlSet\Control\Lsa`, "EveryoneIncludesAnonymous")
		latfp, _ := dwLM(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "LocalAccountTokenFilterPolicy")
		r.Evidence = fmt.Sprintf("RestrictAnonymous=%d; RestrictAnonymousSAM=%d; EveryoneIncludesAnonymous=%d; LocalAccountTokenFilterPolicy=%d", ra, rasam, everyone, latfp)
		var issues []string
		if rasam != 1 {
			issues = append(issues, "RestrictAnonymousSAM!=1 (SAM anonim enum)")
		}
		if everyone == 1 {
			issues = append(issues, "EveryoneIncludesAnonymous=1")
		}
		if latfp == 1 {
			issues = append(issues, "LocalAccountTokenFilterPolicy=1 (uzak yerel-admin tam token — lateral)")
		}
		if len(issues) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Düzeltilmeli: " + strings.Join(issues, "; ") + "."
		} else {
			r.Result = schema.ResultBlocked
		}
	})

	// 16.4 Windows Recall (Win11 AI snapshot)
	b.add("CHT-16-004", "Windows Recall (AI ekran anlık görüntüsü)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1113"
		r.AttemptedMethods = []string{`registry WindowsAI DisableAIDataAnalysis (HKLM+HKCU)`}
		dis, ok := polDword(`SOFTWARE\Policies\Microsoft\Windows\WindowsAI`, "DisableAIDataAnalysis")
		r.Evidence = fmt.Sprintf("DisableAIDataAnalysis=%d (set=%v) — 1=Recall kapalı", dis, ok)
		if ok && dis == 1 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Recall kapatılmamış — ekran anlık görüntüleri hassas veri/parola yakalayabilir. Kurumsal cihazda DisableAIDataAnalysis=1 önerilir."
		}
	})

	// 16.5 Pano geçmişi / bulut panosu
	b.add("CHT-16-005", "Pano geçmişi / bulut panosu (DLP kanalı)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.Mapping.Attack = "T1115"
		r.AttemptedMethods = []string{`registry System AllowClipboardHistory/AllowCrossDeviceClipboard`}
		hist, histOk := polDword(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "AllowClipboardHistory")
		cross, crossOk := polDword(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "AllowCrossDeviceClipboard")
		r.Evidence = fmt.Sprintf("AllowClipboardHistory=%d(set=%v); AllowCrossDeviceClipboard=%d(set=%v) — 0=kapalı", hist, histOk, cross, crossOk)
		if histOk && hist == 0 && crossOk && cross == 0 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultPartial
			r.Recommendation = "Bulut panosu (cross-device) kurumsal veriyi buluta taşıyabilir; gerekmez ise kapatılmalı."
		}
	})

	// 16.6 VSS / geri yükleme (anti-ransomware kurtarma)
	b.add("CHT-16-006", "Shadow Copy / sistem geri yükleme (ransomware kurtarma)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1490"
		r.AttemptedMethods = []string{"servis VSS + registry SystemRestore"}
		vssStart, _ := dwLM(`SYSTEM\CurrentControlSet\Services\VSS`, "Start")
		disableSR, _ := dwLM(`SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore`, "DisableSR")
		r.Evidence = fmt.Sprintf("VSS.Start=%d (4=disabled); SystemRestore DisableSR=%d", vssStart, disableSR)
		if vssStart == 4 || disableSR == 1 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "VSS/sistem geri yükleme devre dışı — ransomware sonrası yerel kurtarma yok. Kurumsal yedek + shadow copy değerlendirilmeli."
		} else {
			r.Result = schema.ResultPartial
			r.Evidence += " — VSS kullanılabilir (shadow copy temelli kurtarma mümkün; merkezi yedek yine de şart)"
		}
	})

	// 16.7 Yama guncelligi (gercek durum, politika degil)
	b.add("CHT-16-007", "Yama güncelliği (son başarılı güncelleme)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1190"
		r.AttemptedMethods = []string{`registry WindowsUpdate ...Results\Install LastSuccessTime`, "UBR"}
		ubr, _ := dwLM(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "UBR")
		last, _ := nativeapi.RegString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install`, "LastSuccessTime")
		r.Evidence = fmt.Sprintf("UBR(build revizyon)=%d; SonBaşarılıGüncelleme=%q", ubr, last)
		if last == "" {
			r.Result = schema.ResultPartial
			r.Evidence += " — son güncelleme zamanı okunamadı"
			return
		}
		// Format: "2024-01-15 03:20:00" (yerel saat).
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(last), time.Local); err == nil {
			days := int(time.Since(t).Hours() / 24)
			r.Evidence += fmt.Sprintf(" (%d gün önce)", days)
			if days > 35 {
				r.Result = schema.ResultAllowed
				r.RiskWhenOpen = schema.RiskHigh
				r.Recommendation = fmt.Sprintf("Cihaz %d gündür güncelleme almamış (>35) — kritik yamalar eksik olabilir; WSUS/Intune güncelleme halkası kontrol edilmeli.", days)
			} else {
				r.Result = schema.ResultBlocked
				r.Evidence += " — güncel"
			}
		} else {
			r.Result = schema.ResultPartial
		}
	})

	// 16.8 Windows Hello for Business
	b.add("CHT-16-008", "Windows Hello for Business / PIN politikası", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskInfo
		r.AttemptedMethods = []string{`registry PassportForWork`}
		en, ok := polDword(`SOFTWARE\Policies\Microsoft\PassportForWork`, "Enabled")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("PassportForWork.Enabled=%d (set=%v)", en, ok)
		if ok && en == 1 {
			r.Evidence += " — WHfB etkin (phishing-dayanıklı kimlik)"
			r.Result = schema.ResultBlocked
		} else {
			r.Recommendation = "Windows Hello for Business değerlendirilmeli (parola yerine phishing-dayanıklı kimlik)."
		}
	})

	// 16.9 Point-and-Print / PrintNightmare
	b.add("CHT-16-009", "Point-and-Print sürücü kurulumu (PrintNightmare)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1068"
		r.AttemptedMethods = []string{`registry PointAndPrint RestrictDriverInstallationToAdministrators`}
		const pp = `SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`
		restrict, restrictOk := dwLM(pp, "RestrictDriverInstallationToAdministrators")
		noWarn, _ := dwLM(pp, "NoWarningNoElevationOnInstall")
		r.Evidence = fmt.Sprintf("RestrictDriverInstallationToAdministrators=%d(set=%v); NoWarningNoElevationOnInstall=%d", restrict, restrictOk, noWarn)
		if restrictOk && restrict == 1 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Standart kullanıcı yazıcı sürücüsü kurabiliyor (PrintNightmare/T1068 privesc) — RestrictDriverInstallationToAdministrators=1 yapılmalı."
		}
	})

	// 16.10 NetBIOS / mDNS multicast ad çözümleme
	b.add("CHT-16-010", "Multicast ad çözümleme (mDNS / NetBIOS)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1557.001"
		r.AttemptedMethods = []string{`registry Dnscache EnableMDNS`, "LLMNR (bkz. 12-002)"}
		mdns, mdnsOk := dwLM(`SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`, "EnableMDNS")
		r.Evidence = fmt.Sprintf("EnableMDNS=%d(set=%v) — 0=kapalı", mdns, mdnsOk)
		if mdnsOk && mdns == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence += " — mDNS kapalı"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "mDNS açık (poisoning/spoofing yüzeyi); LLMNR (CHT-12-002) ile birlikte kapatılmalı (EnableMDNS=0)."
		}
	})

	// 16.11 OneDrive / bulut senkron
	b.add("CHT-16-011", "OneDrive / bulut senkron (kurumsal veri)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.Mapping.Attack = "T1567.002"
		r.AttemptedMethods = []string{"servis/registry OneDrive + policy"}
		const od = `SOFTWARE\Policies\Microsoft\OneDrive`
		blockPersonal, _ := dwLM(od, "DisablePersonalSync")
		odsvc := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\OneDrive`)
		r.Evidence = fmt.Sprintf("OneDrive kurulu=%v; DisablePersonalSync=%d (1=kişisel hesap engelli)", odsvc, blockPersonal)
		if !odsvc {
			r.Result = schema.ResultNotApplicable
			r.Evidence = "OneDrive kurulu değil"
			return
		}
		if blockPersonal == 1 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Kişisel OneDrive senkronu engellenmemiş — kurumsal veri kişisel buluta sızabilir (DisablePersonalSync=1)."
		}
	})

	// 16.12 Kamera / mikrofon + cihaz kurulum kontrolu
	b.add("CHT-16-012", "Kamera / mikrofon + cihaz kurulum kontrolü", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.AttemptedMethods = []string{`registry AppPrivacy LetAppsAccessCamera/Microphone`, "DeviceInstall Restrictions"}
		const ap = `SOFTWARE\Policies\Microsoft\Windows\AppPrivacy`
		cam, _ := dwLM(ap, "LetAppsAccessCamera")
		mic, _ := dwLM(ap, "LetAppsAccessMicrophone")
		devRestrict := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`)
		r.Evidence = fmt.Sprintf("LetAppsAccessCamera=%d; LetAppsAccessMicrophone=%d (2=engelli); cihaz-kurulum kısıtı=%v", cam, mic, devRestrict)
		if devRestrict {
			r.Result = schema.ResultPartial
			r.Evidence += " — cihaz kurulum kısıtı tanımlı (BadUSB/HID için sınıf-bazlı deny doğrulanmalı)"
		} else {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskLow
			r.Recommendation = "Cihaz kurulum kısıtı (DeviceInstall Restrictions) yok — BadUSB/HID enjeksiyon yüzeyi; kamera/mikrofon erişimi gözden geçirilmeli."
		}
	})

	return b.results()
}
