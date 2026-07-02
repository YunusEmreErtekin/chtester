package modules

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat11 = "11-Browser"

// Module11, tarayici & web kisitlamalarini pasif okur (eklenti/indirme gibi aktifler gate'li).
type Module11 struct{}

func NewModule11() *Module11 { return &Module11{} }

func (Module11) ID() string   { return "11" }
func (Module11) Name() string { return "Tarayıcı & Web Kısıtlamaları" }

func (m Module11) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat11)

	// 11.1 Edge/Chrome yonetilen politikalar
	b.add("CHT-11-001", "Edge/Chrome yönetilen politikalar", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"registry Policies\\Microsoft\\Edge + Google\\Chrome"}
		edge, _ := nativeapi.RegValueNames(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Edge`)
		chrome, _ := nativeapi.RegValueNames(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Google\Chrome`)
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("Edge policy değeri=%d; Chrome policy değeri=%d", len(edge), len(chrome))
		if len(edge) == 0 && len(chrome) == 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Tarayıcı yönetim politikası yok — kurumsal tarayıcı sertleştirmesi uygulanmalı."
		}
	})

	// 11.3 Incognito + DevTools (politika okuma)
	b.add("CHT-11-003", "Gizli mod / DevTools politikası", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.AttemptedMethods = []string{"registry InPrivate/Incognito/DeveloperTools"}
		edgeInPriv, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Edge`, "InPrivateModeAvailability")
		chromeIncog, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Google\Chrome`, "IncognitoModeAvailability")
		edgeDev, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Edge`, "DeveloperToolsAvailability")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("Edge InPrivate=%d; Chrome Incognito=%d; Edge DevTools=%d (1=disabled)", edgeInPriv, chromeIncog, edgeDev)
		if edgeInPriv == 0 && chromeIncog == 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Gizli mod kısıtlanmamış (DLP/izleme kaçışı yüzeyi)."
		}
	})

	// 11.2 Eklenti kurma (aktif) — gate
	b.add("CHT-11-002", "Tarayıcı eklentisi kurma yeteneği", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"ExtensionInstallBlocklist politikası + sideload denemesi"}
		// Pasif: blocklist/allowlist politikasi var mi
		blockAll := false
		if vals, _ := nativeapi.RegStringValues(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist`); vals["1"] == "*" {
			blockAll = true
		}
		if !ctx.ActiveAllowed() {
			r.Result = schema.ResultPartial
			r.Evidence = fmt.Sprintf("Eklenti blocklist '*'=%v (aktif sideload denemesi -PassiveOnly=false ister)", blockAll)
			return
		}
		// Aktif sideload denemesi gercek tarayici otomasyonu ister; iskelet.
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("blocklist '*'=%v; gerçek sideload denemesi tarayıcı otomasyonu gerektirir", blockAll)
	})

	// 11.4 Tehlikeli dosya indirme (aktif) — gate
	b.add("CHT-11-004", "Exe/tehlikeli dosya indirme (SmartScreen)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1105"
		r.AttemptedMethods = []string{"AMTSO/EICAR test URL indirme"}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		markNotImplemented(r, "tehlikeli dosya indirme / SmartScreen testi (AMTSO/EICAR URL)")
	})

	// 11.5 URL kategori filtre testi (aktif) — gate
	b.add("CHT-11-005", "URL kategori filtre testi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"kategori test sayfaları (anonymizer/webmail/file-sharing)"}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		markNotImplemented(r, "URL kategori filtre testi (anonymizer/webmail/file-sharing)")
	})

	// 11.6 Kayitli parola / sync politikasi (pasif)
	b.add("CHT-11-006", "Tarayıcı parola yöneticisi / sync politikası", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1555.003"
		r.AttemptedMethods = []string{"registry PasswordManagerEnabled/SyncDisabled/BrowserSignin"}
		edgePM, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Edge`, "PasswordManagerEnabled")
		edgeSync, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Edge`, "SyncDisabled")
		edgeSignin, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Edge`, "BrowserSignin")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("Edge PasswordManagerEnabled=%d; SyncDisabled=%d; BrowserSignin=%d", edgePM, edgeSync, edgeSignin)
		var rec []string
		if edgeSync != 1 {
			rec = append(rec, "Sync kapatılmamış (kişisel hesaba veri sızması)")
		}
		if len(rec) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = strings.Join(rec, "; ")
		}
	})

	return b.results()
}
