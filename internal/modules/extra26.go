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

const cat26 = "26-Browser"

// Module26, TARAYICI saldiri yuzey derinligini olcer: kurumsal (Edge/Chrome) politikalari
// baypas eden alternatif/yonetilmeyen tarayicilar (Firefox/Brave/Tor/Opera — URL-filter/DLP
// baypasi, Tor=anonim exfil), tarayici SmartScreen/indirme korumasi (11-004 iskeletti), ve
// kisisel-hesaba sign-in/sync (Edge+Chrome — veri exfil). Pasif (dosya + registry).
type Module26 struct{}

func NewModule26() *Module26 { return &Module26{} }

func (Module26) ID() string   { return "26" }
func (Module26) Name() string { return "Tarayıcı Saldırı Yüzeyi Derinliği" }

func (m Module26) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat26)
	pf := os.Getenv("ProgramFiles")
	pf86 := os.Getenv("ProgramFiles(x86)")
	lad := os.Getenv("LOCALAPPDATA")
	up := os.Getenv("USERPROFILE")

	// 26.1 Alternatif/yonetilmeyen tarayici — kurumsal politika/URL-filter/DLP baypasi
	b.add("CHT-26-001", "Alternatif/yönetilmeyen tarayıcı (Firefox/Brave/Tor/Opera)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1105"
		r.AttemptedMethods = []string{"kurulu tarayıcı yol taraması"}
		type br struct {
			name string
			tor  bool
			path []string
		}
		cands := []br{
			{"Firefox", false, []string{filepath.Join(pf, "Mozilla Firefox", "firefox.exe"), filepath.Join(pf86, "Mozilla Firefox", "firefox.exe")}},
			{"Brave", false, []string{filepath.Join(lad, "BraveSoftware", "Brave-Browser", "Application", "brave.exe")}},
			{"Opera", false, []string{filepath.Join(lad, "Programs", "Opera", "opera.exe"), filepath.Join(pf, "Opera")}},
			{"Vivaldi", false, []string{filepath.Join(lad, "Vivaldi", "Application", "vivaldi.exe")}},
			{"Chrome", false, []string{filepath.Join(pf, "Google", "Chrome", "Application", "chrome.exe"), filepath.Join(pf86, "Google", "Chrome", "Application", "chrome.exe")}},
			{"Tor Browser", true, []string{filepath.Join(up, "Desktop", "Tor Browser"), filepath.Join(lad, "Tor Browser"), filepath.Join(up, "Downloads", "Tor Browser")}},
		}
		var found []string
		torFound := false
		for _, c := range cands {
			for _, p := range c.path {
				if fileExists(p) || dirExists(p) {
					found = append(found, c.name)
					if c.tor {
						torFound = true
					}
					break
				}
			}
		}
		if len(found) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Alternatif tarayıcı yok (yalnız kurumsal Edge/Chrome varsayımı)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "Kurulu alternatif tarayıcı: " + strings.Join(found, ", ")
		if torFound {
			r.RiskWhenOpen = schema.RiskHigh
			r.Evidence += " — TOR: anonim exfil/C2 kanalı"
			r.Recommendation = "ACİL: Tor Browser anonim veri sızıntısı/C2 sağlar. Alternatif tarayıcılar kurumsal politika/URL-filter/DLP'yi baypas eder; AppLocker/WDAC ile engellenmeli."
		} else {
			r.Recommendation = "Alternatif tarayıcılar kurumsal politika/URL-filter/DLP'yi baypas eder; yalnız yönetilen tarayıcıya izin verilmeli (AppLocker/WDAC)."
		}
	})

	// 26.2 Tarayici SmartScreen / indirme korumasi (Edge policy)
	b.add("CHT-26-002", "Tarayıcı SmartScreen / indirme koruması (Edge)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1189"
		r.AttemptedMethods = []string{"registry Edge SmartScreenEnabled/PuaEnabled/PreventOverride"}
		const edge = `SOFTWARE\Policies\Microsoft\Edge`
		ss, errSS := nativeapi.RegDword(registry.LOCAL_MACHINE, edge, "SmartScreenEnabled")
		hasSS := errSS == nil
		pua, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, edge, "SmartScreenPuaEnabled")
		override, errOv := nativeapi.RegDword(registry.LOCAL_MACHINE, edge, "PreventSmartScreenPromptOverride")
		hasOv := errOv == nil
		r.Evidence = fmt.Sprintf("SmartScreenEnabled=%s; PuaEnabled=%d; PreventOverride=%s",
			dwState(hasSS, ss), pua, dwState(hasOv, override))
		var issues []string
		if !hasSS || ss != 1 {
			issues = append(issues, "SmartScreen zorunlu değil")
		}
		if !hasOv || override != 1 {
			issues = append(issues, "kullanıcı SmartScreen uyarısını atlayabilir")
		}
		if pua != 1 {
			issues = append(issues, "PUA koruması kapalı")
		}
		if len(issues) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Edge politikasıyla zorlanmalı: SmartScreenEnabled=1, SmartScreenPuaEnabled=1, PreventSmartScreenPromptOverride=1 — " + strings.Join(issues, ", ") + "."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — SmartScreen zorunlu ve atlanamaz"
		}
	})

	// 26.3 Kisisel-hesaba sign-in/sync (Edge + Chrome) — tarayici uzerinden veri exfil
	b.add("CHT-26-003", "Tarayıcı kişisel-hesap sign-in/sync (Edge + Chrome)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1567.002"
		r.AttemptedMethods = []string{"registry Edge/Chrome BrowserSignin/SyncDisabled/RestrictSigninToPattern"}
		var open []string
		for _, br := range []struct{ name, key string }{
			{"Edge", `SOFTWARE\Policies\Microsoft\Edge`},
			{"Chrome", `SOFTWARE\Policies\Google\Chrome`},
		} {
			signin, errSignin := nativeapi.RegDword(registry.LOCAL_MACHINE, br.key, "BrowserSignin")
			hasSignin := errSignin == nil
			sync, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, br.key, "SyncDisabled")
			restrict, _ := nativeapi.RegString(registry.LOCAL_MACHINE, br.key, "RestrictSigninToPattern")
			// sign-in kapali degil (0!=BrowserSignin) VE domain kisiti yok VE sync engelli degil
			signinOpen := !hasSignin || signin != 0
			if signinOpen && restrict == "" && sync != 1 {
				open = append(open, br.name)
			}
		}
		if len(open) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Tarayıcı kişisel-hesap sign-in/sync kısıtlı (kurumsal domain'e kilitli veya sync kapalı)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "Kişisel hesapla sign-in + sync açık: " + strings.Join(open, ", ") +
			" — çalışan kurumsal veriyi (yer imi/parola/geçmiş) kişisel hesaba senkronlayabilir"
		r.Recommendation = "RestrictSigninToPattern ile kurumsal domain'e kilitlenmeli veya SyncDisabled=1 / BrowserSignin=0 yapılmalı."
	})

	return b.results()
}
