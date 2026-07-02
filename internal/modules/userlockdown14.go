package modules

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat14 = "14-UserLockdown"

// Module14, kullanici kilitleme / kisitlama / kisisellestirme durusunu PASIF okur.
// Bunlar kurumsal "calisanin cihazinda neye dokunabilecegi" kontrolleridir (Denetim
// Masasi/Ayarlar erisimi, Gorev Yoneticisi, CMD, surucu gizleme, duvar kagidi kilidi,
// ekran kilidi, parola/kilitleme politikasi, RDP yonlendirme). Hicbiri degisiklik yapmaz.
// Mantik: kisitlanmamis => Allowed (zayif), kisitli => Blocked (kontrol calisiyor).
type Module14 struct{}

func NewModule14() *Module14 { return &Module14{} }

func (Module14) ID() string   { return "14" }
func (Module14) Name() string { return "Kullanıcı Kısıtlama / Kilitleme" }

const (
	polExplorer = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`
	polSystem   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
)

// polDword, bir policy DWORD'unu HKCU ve HKLM'den okuyup en kisitlayici (en buyuk)
// degeri doner (makine genelinde set edilmis olabilir).
func polDword(subkey, name string) (uint64, bool) {
	v, ok := uint64(0), false
	if cu, err := nativeapi.RegDword(registry.CURRENT_USER, subkey, name); err == nil {
		v, ok = cu, true
	}
	if lm, err := nativeapi.RegDword(registry.LOCAL_MACHINE, subkey, name); err == nil {
		if !ok || lm > v {
			v, ok = lm, true
		}
	}
	return v, ok
}

func (m Module14) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat14)

	// 14.1 Denetim Masasi & Ayarlar erisimi
	b.add("CHT-14-001", "Denetim Masası / Ayarlar erişimi kısıtlaması", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"registry Policies\\Explorer NoControlPanel / SettingsPageVisibility"}
		ncp, _ := polDword(polExplorer, "NoControlPanel")
		spvCU, _ := nativeapi.RegString(registry.CURRENT_USER, polExplorer, "SettingsPageVisibility")
		spvLM, _ := nativeapi.RegString(registry.LOCAL_MACHINE, polExplorer, "SettingsPageVisibility")
		spv := spvCU
		if spv == "" {
			spv = spvLM
		}
		r.Evidence = fmt.Sprintf("NoControlPanel=%d; SettingsPageVisibility=%q", ncp, spv)
		if ncp == 1 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Standart kullanıcı Denetim Masası/Ayarlar'a tam erişebiliyor; gerekmeyen sayfalar SettingsPageVisibility ile kısıtlanmalı."
		}
	})

	// 14.2 Gorev Yoneticisi
	b.add("CHT-14-002", "Görev Yöneticisi kısıtlaması (DisableTaskMgr)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.AttemptedMethods = []string{"registry Policies\\System DisableTaskMgr"}
		v, _ := polDword(polSystem, "DisableTaskMgr")
		r.Evidence = fmt.Sprintf("DisableTaskMgr=%d", v)
		if v == 1 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Görev Yöneticisi açık (kiosk/kısıtlı profillerde kapatılması değerlendirilebilir)."
		}
	})

	// 14.3 Komut istemi (cmd)
	b.add("CHT-14-003", "Komut İstemi kısıtlaması (DisableCMD)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1059.003"
		r.AttemptedMethods = []string{"registry Policies\\System DisableCMD"}
		v, ok := polDword(polSystem, "DisableCMD")
		r.Evidence = fmt.Sprintf("DisableCMD=%d (1=cmd+script kapalı, 2=cmd kapalı/script açık)", v)
		switch {
		case ok && (v == 1 || v == 2):
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
			if v == 2 {
				r.Result = schema.ResultPartial
				r.Evidence += " — interaktif cmd kapalı ama .bat/.cmd script çalışması açık"
			}
		default:
			r.Result = schema.ResultAllowed
			r.Recommendation = "cmd.exe kısıtlanmamış; AppLocker/WDAC ile birlikte değerlendirin (DisableCMD tek başına zayıf engeldir)."
		}
	})

	// 14.4 Calistir / DisallowRun beyaz-kara liste
	b.add("CHT-14-004", "Çalıştır menüsü / DisallowRun kısıtı", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.AttemptedMethods = []string{"registry Policies\\Explorer NoRun/RestrictRun/DisallowRun"}
		noRun, _ := polDword(polExplorer, "NoRun")
		restrictRun, _ := polDword(polExplorer, "RestrictRun")
		disallowCU, _ := nativeapi.RegValueNames(registry.CURRENT_USER, polExplorer+`\DisallowRun`)
		disallowLM, _ := nativeapi.RegValueNames(registry.LOCAL_MACHINE, polExplorer+`\DisallowRun`)
		n := len(disallowCU) + len(disallowLM)
		r.Evidence = fmt.Sprintf("NoRun=%d; RestrictRun=%d; DisallowRun girdisi=%d", noRun, restrictRun, n)
		if noRun == 1 || restrictRun == 1 || n > 0 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultPartial
			r.RiskWhenOpen = schema.RiskInfo
			r.Evidence += " — kısıt yok (çoğu ortamda normal; asıl engel AppLocker/WDAC)"
		}
	})

	// 14.5 Surucu gorunurlugu/erisimi
	b.add("CHT-14-005", "Sürücü gizleme / erişim kısıtı (NoDrives/NoViewOnDrive)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.AttemptedMethods = []string{"registry Policies\\Explorer NoDrives/NoViewOnDrive"}
		noDrives, _ := polDword(polExplorer, "NoDrives")
		noView, _ := polDword(polExplorer, "NoViewOnDrive")
		r.Evidence = fmt.Sprintf("NoDrives=0x%X; NoViewOnDrive=0x%X (bit maskesi: A=1,B=2,C=4...)", noDrives, noView)
		if noDrives != 0 || noView != 0 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultPartial
			r.RiskWhenOpen = schema.RiskInfo
			r.Evidence += " — sürücü gizleme yok (kozmetik kontrol; veri erişimi için ACL/DLP esastır)"
		}
	})

	// 14.6 Kisisellestirme / duvar kagidi kilidi
	b.add("CHT-14-006", "Kişiselleştirme / duvar kağıdı kilidi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskInfo
		r.AttemptedMethods = []string{"registry ActiveDesktop NoChangingWallPaper", "System Wallpaper"}
		const polAD = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop`
		noChange, _ := polDword(polAD, "NoChangingWallPaper")
		wpCU, _ := nativeapi.RegString(registry.CURRENT_USER, polSystem, "Wallpaper")
		wpLM, _ := nativeapi.RegString(registry.LOCAL_MACHINE, polSystem, "Wallpaper")
		forced := wpCU != "" || wpLM != ""
		r.Evidence = fmt.Sprintf("NoChangingWallPaper=%d; zorunlu Wallpaper ayarlı=%v", noChange, forced)
		if noChange == 1 || forced {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskInfo
			r.Recommendation = "Kişiselleştirme kilidi yok (düşük güvenlik etkisi; kurumsal kimlik/kiosk için değerlendirilebilir)."
		}
	})

	// 14.7 Otomatik ekran kilidi / hareketsizlik zaman asimi
	b.add("CHT-14-007", "Otomatik ekran kilidi (inactivity / screensaver-secure)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1078"
		r.AttemptedMethods = []string{"registry Policies\\System InactivityTimeoutSecs", "Control Panel\\Desktop ScreenSaverIsSecure"}
		inact, _ := polDword(polSystem, "InactivityTimeoutSecs")
		const polDesk = `SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`
		secCU, _ := nativeapi.RegString(registry.CURRENT_USER, polDesk, "ScreenSaverIsSecure")
		secLM, _ := nativeapi.RegString(registry.LOCAL_MACHINE, polDesk, "ScreenSaverIsSecure")
		toCU, _ := nativeapi.RegString(registry.CURRENT_USER, polDesk, "ScreenSaveTimeOut")
		toLM, _ := nativeapi.RegString(registry.LOCAL_MACHINE, polDesk, "ScreenSaveTimeOut")
		secure := secCU == "1" || secLM == "1"
		ssTimeout := toCU
		if ssTimeout == "" {
			ssTimeout = toLM
		}
		r.Evidence = fmt.Sprintf("InactivityTimeoutSecs=%d; ScreenSaverIsSecure=%v; ScreenSaveTimeOut=%q", inact, secure, ssTimeout)
		if inact > 0 || (secure && ssTimeout != "" && ssTimeout != "0") {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Otomatik ekran kilidi zorlanmamış — kilitlenmemiş bırakılan cihaz fiziksel erişim riski. InactivityTimeoutSecs (örn. 900) veya güvenli ekran koruyucu zorunlu kılınmalı."
		}
	})

	// 14.8 Kilit ekrani kamera / bildirim maruziyeti
	b.add("CHT-14-008", "Kilit ekranı kamera / bildirim maruziyeti", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.AttemptedMethods = []string{"registry Personalization NoLockScreenCamera", "System DisableLockScreenAppNotifications"}
		const polPers = `SOFTWARE\Policies\Microsoft\Windows\Personalization`
		const polSys2 = `SOFTWARE\Policies\Microsoft\Windows\System`
		noCam, _ := polDword(polPers, "NoLockScreenCamera")
		noNotif, _ := polDword(polSys2, "DisableLockScreenAppNotifications")
		r.Evidence = fmt.Sprintf("NoLockScreenCamera=%d; DisableLockScreenAppNotifications=%d", noCam, noNotif)
		if noCam == 1 && noNotif == 1 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultPartial
			r.Recommendation = "Kilit ekranında kamera ve uygulama bildirimleri kısıtlanmamış (bildirimler kilitli ekranda hassas veri sızdırabilir)."
		}
	})

	// 14.9 Parola politikasi (native NetUserModalsGet)
	b.add("CHT-14-009", "Parola politikası (uzunluk / yaş / geçmiş)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping = schema.Mapping{CIS: "Password Policy", Attack: "T1110"}
		r.AttemptedMethods = []string{"NetUserModalsGet level 0 (native)"}
		pp := nativeapi.PasswordPolicyInfo()
		if !pp.OK {
			r.Result = schema.ResultPartial
			r.Evidence = "Yerel parola politikası okunamadı (NetUserModalsGet)"
			return
		}
		ageTxt := fmt.Sprintf("%d gün", pp.MaxAgeDays)
		if pp.NeverExpires {
			ageTxt = "hiç (süresiz)"
		}
		r.Evidence = fmt.Sprintf("MinUzunluk=%d; MaxYaş=%s; Geçmiş=%d (yerel SAM)", pp.MinLength, ageTxt, pp.HistoryLength)
		var weak []string
		if pp.MinLength < 14 {
			weak = append(weak, fmt.Sprintf("min uzunluk %d (<14 önerilmez)", pp.MinLength))
		}
		if pp.HistoryLength < 24 {
			weak = append(weak, fmt.Sprintf("geçmiş %d (<24)", pp.HistoryLength))
		}
		if len(weak) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Yerel parola politikası zayıf: " + strings.Join(weak, "; ") + ". Domain üyesinde etkin politika DC'den gelebilir; yine de yerel SAM sıkılaştırılmalı (CIS: min 14, geçmiş 24)."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — temel eşikler makul"
		}
	})

	// 14.10 Hesap kilitleme politikasi (native)
	b.add("CHT-14-010", "Hesap kilitleme politikası (brute-force)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping = schema.Mapping{CIS: "Account Lockout", Attack: "T1110"}
		r.AttemptedMethods = []string{"NetUserModalsGet level 3 (native)"}
		lp := nativeapi.LockoutPolicyInfo()
		if !lp.OK {
			r.Result = schema.ResultPartial
			r.Evidence = "Yerel kilitleme politikası okunamadı"
			return
		}
		r.Evidence = fmt.Sprintf("Eşik=%d deneme; Süre=%ds; Pencere=%ds", lp.Threshold, lp.DurationSec, lp.WindowSec)
		if lp.Threshold == 0 {
			r.Result = schema.ResultAllowed
			r.Evidence += " — kilitleme YOK (sınırsız parola denemesi / brute-force açık)"
			r.Recommendation = "Hesap kilitleme eşiği ayarlanmalı (CIS: ≤5 başarısız deneme, ≥15 dk kilit). Domain üyesinde etkin politika DC'den gelebilir."
		} else if lp.Threshold > 10 {
			r.Result = schema.ResultPartial
			r.Recommendation = "Kilitleme eşiği yüksek (>10); 5'e düşürülmesi önerilir."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — kilitleme aktif"
		}
	})

	// 14.11 RDP oturum yonlendirme kisitlari
	b.add("CHT-14-011", "RDP oturum yönlendirme kısıtları (sürücü/pano/yazıcı)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1021.001"
		r.AttemptedMethods = []string{`registry Policies\...\Terminal Services fDisable*`}
		const ts = `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
		cdm, _ := polDword(ts, "fDisableCdm")   // sürücü yönlendirme
		clip, _ := polDword(ts, "fDisableClip") // pano
		lpt, _ := polDword(ts, "fDisableLPT")   // yazıcı portu
		pnp, _ := polDword(ts, "fDisablePNPRedir")
		r.Evidence = fmt.Sprintf("fDisableCdm(sürücü)=%d; fDisableClip(pano)=%d; fDisableLPT=%d; fDisablePNPRedir=%d (1=engelli)", cdm, clip, lpt, pnp)
		if cdm == 1 && clip == 1 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		} else {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskMedium
			r.Recommendation = "RDP sürücü/pano yönlendirme kısıtlanmamış — RDP üzerinden veri çıkışı/giriş kanalı. fDisableCdm=1 ve fDisableClip=1 önerilir."
		}
	})

	return b.results()
}
