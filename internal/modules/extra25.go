package modules

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat25 = "25-AuthSession"

// Module25, KIMLIK DOGRULAMA & OTURUM sertlestirme derinligini olcer: convenience PIN /
// picture password ile parola zayiflatma, akilli-kart cikarma & hizli-kullanici-degistirme
// oturum-kilit bosluklari, EFS ile kullanicinin veriyi DLP/admin/adli'den gizleme yuzeyi.
// Modul 16-008 yalniz WHfB, 14-007 yalniz inactivity-timeout bakar. Hepsi PASIF registry.
type Module25 struct{}

func NewModule25() *Module25 { return &Module25{} }

func (Module25) ID() string   { return "25" }
func (Module25) Name() string { return "Kimlik Doğrulama & Oturum Sertleştirme Derinliği" }

func (m Module25) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat25)

	// 25.1 Convenience PIN / picture password — parola yerine zayif kimlik
	b.add("CHT-25-001", "Zayıf kimlik doğrulama (convenience PIN / picture password)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1078"
		r.AttemptedMethods = []string{"registry System AllowDomainPINLogon / BlockDomainPicturePassword"}
		const sys = `SOFTWARE\Policies\Microsoft\Windows\System`
		pin, _ := dwLM(sys, "AllowDomainPINLogon")            // 1 = convenience PIN acik (zayif)
		picBlock, hasPic := dwLM(sys, "BlockDomainPicturePassword") // 1 = engelli (iyi)
		var issues []string
		if pin == 1 {
			issues = append(issues, "convenience PIN açık (basit PIN domain parolasının yerine geçer)")
		}
		if !hasPic || picBlock != 1 {
			issues = append(issues, "picture password engellenmemiş")
		}
		r.Evidence = fmt.Sprintf("AllowDomainPINLogon=%d; BlockDomainPicturePassword=%s", pin, dwState(hasPic, picBlock))
		if len(issues) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Domain cihazında convenience PIN kapatılmalı (WHfB PIN'i farklıdır), picture password engellenmeli: " + strings.Join(issues, "; ") + "."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — zayıf oturum-açma yöntemleri kapalı"
		}
	})

	// 25.2 Oturum kilidi derinligi — akilli-kart cikarma + hizli-kullanici-degistirme + son-kullanici
	b.add("CHT-25-002", "Oturum kilidi derinliği (smartcard çıkarma / fast user switching)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1078"
		r.AttemptedMethods = []string{"registry Winlogon ScRemoveOption + Policies\\System"}
		scRemove, _ := nativeapi.RegString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "ScRemoveOption")
		const polSys = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
		hideFUS, hasFUS := dwLM(polSys, "HideFastUserSwitching")   // 1 = gizli (iyi)
		noLastUser, hasNLU := dwLM(polSys, "DontDisplayLastUserName") // 1 = gizli (iyi)
		var issues []string
		if scRemove == "" || scRemove == "0" {
			issues = append(issues, "akıllı-kart çıkarınca kilitleme yok (ScRemoveOption=0)")
		}
		if !hasFUS || hideFUS != 1 {
			issues = append(issues, "hızlı kullanıcı değiştirme açık")
		}
		if !hasNLU || noLastUser != 1 {
			issues = append(issues, "son oturum kullanıcı adı gösteriliyor")
		}
		r.Evidence = fmt.Sprintf("ScRemoveOption=%q; HideFastUserSwitching=%s; DontDisplayLastUserName=%s",
			scRemove, dwState(hasFUS, hideFUS), dwState(hasNLU, noLastUser))
		if len(issues) > 0 {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskLow
			r.Recommendation = "Sertleştirilmeli: " + strings.Join(issues, "; ") + " (akıllı-kart kilit, fast-user-switching kapalı, son kullanıcı gizli)."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — oturum kilidi sağlam"
		}
	})

	// 25.3 EFS — kullanici veriyi DLP/admin/adli'den gizleyebilir / sifreleyebilir
	b.add("CHT-25-003", "EFS ile veri gizleme/şifreleme yüzeyi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1027"
		r.AttemptedMethods = []string{"registry FileSystem NtfsDisableEncryption"}
		dis, hasDis := dwLM(`SYSTEM\CurrentControlSet\Control\FileSystem`, "NtfsDisableEncryption")
		efsOn := !hasDis || dis != 1 // 1 = EFS kapali; 0/ayarsiz = acik
		r.Evidence = fmt.Sprintf("NtfsDisableEncryption=%s → EFS %s", dwState(hasDis, dis), onOff(efsOn))
		if !efsOn {
			r.Result = schema.ResultBlocked
			r.Evidence += " — EFS devre dışı (kullanıcı EFS ile veri gizleyemez)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Recommendation = "EFS açık — kullanıcı dosyaları EFS ile şifreleyip DLP/adli incelemeden gizleyebilir (kurtarma ajanı yoksa veri kaybı da riski). Gerekmiyorsa NtfsDisableEncryption=1; gerekiyorsa merkezi DRA + anahtar yedekleme zorunlu."
	})

	return b.results()
}
