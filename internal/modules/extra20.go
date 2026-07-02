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

const cat20 = "20-CredPersist"

// Module20, KIMLIK & KALICILIK yuzey derinligini olcer: standart kullanici, zayif registry
// ACL'leri, IFEO hijack, DPAPI/kayitli kimlik depolari veya kayitli RDP kimlikleri uzerinden
// yetki yukseltebilir / kalicilik kurabilir / kimlik calabilir mi? Hepsi PASIF: anahtari
// YAZMADAN yalniz "yazma erisimiyle acilabiliyor mu" test edilir + dosya/registry envanteri.
type Module20 struct{}

func NewModule20() *Module20 { return &Module20{} }

func (Module20) ID() string   { return "20" }
func (Module20) Name() string { return "Kimlik & Kalıcılık Yüzeyi Derinliği" }

// sensitiveHKLMKeys, standart kullanici tarafindan yazilabilir OLMAMASI gereken, yazilabilirse
// dogrudan privesc/persistence saglayan anahtarlar.
var sensitiveHKLMKeys = []struct{ path, risk string }{
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM Run (tüm-kullanıcı açılış kalıcılığı)"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM RunOnce"},
	{`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Winlogon (Shell/Userinit hijack)"},
	{`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, "IFEO (debugger hijack)"},
	{`SYSTEM\CurrentControlSet\Services`, "Services (yeni servis / ImagePath)"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "Policies Explorer Run"},
}

func (m Module20) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat20)

	// 20.1 Hassas HKLM registry ACL zayifligi (yazma erisimiyle acilabiliyor mu — YAZMADAN)
	b.add("CHT-20-001", "Hassas registry ACL zayıflığı (HKLM Run/Services/IFEO)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1112"
		r.AttemptedMethods = []string{"RegOpenKey SET_VALUE (yazmadan yalnız erişim testi)"}
		var writable []string
		for _, k := range sensitiveHKLMKeys {
			if hklmKeyWritable(k.path) {
				writable = append(writable, k.risk)
			}
		}
		if len(writable) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Hassas HKLM anahtarlarının hiçbiri mevcut kullanıcıya yazılabilir değil (iyi)"
			return
		}
		r.Result = schema.ResultAllowed
		r.RiskWhenOpen = schema.RiskCritical
		r.Evidence = fmt.Sprintf("%d hassas HKLM anahtarı mevcut kullanıcıya YAZILABİLİR: %s",
			len(writable), strings.Join(writable, "; "))
		r.Recommendation = "ACİL: bu anahtarların ACL'leri düzeltilmeli; standart kullanıcı buralara yazarak SYSTEM'e yükselir / kalıcılık kurar."
	})

	// 20.2 IFEO debugger hijack + erisilebilirlik arka kapisi (sethc/utilman)
	b.add("CHT-20-002", "IFEO debugger hijack + erişilebilirlik arka kapısı", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1546.008"
		r.AttemptedMethods = []string{"IFEO Debugger değerleri + sethc/utilman kontrolü"}
		hijacks := findIFEOHijacks()
		if len(hijacks) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "IFEO'da Debugger hijack / erişilebilirlik arka kapısı yok (temiz)"
			return
		}
		r.Result = schema.ResultAllowed
		r.RiskWhenOpen = schema.RiskCritical
		r.Evidence = fmt.Sprintf("%d IFEO hijack: %s", len(hijacks), truncate(strings.Join(hijacks, "; "), 220))
		r.Recommendation = "ACİL: IFEO Debugger girişleri (özellikle sethc/utilman/osk) kilit-ekranı SYSTEM arka kapısıdır — incelenip kaldırılmalı."
	})

	// 20.3 DPAPI & kayitli kimlik depolari (kullanici baglaminda cozulebilir sirlar)
	b.add("CHT-20-003", "DPAPI & kayıtlı kimlik depoları erişimi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1555.004"
		r.AttemptedMethods = []string{"Protect/Credentials/Vault dizin okunabilirliği"}
		ad := os.Getenv("APPDATA")
		lad := os.Getenv("LOCALAPPDATA")
		stores := map[string]string{
			"DPAPI master key (Protect)": filepath.Join(ad, "Microsoft", "Protect"),
			"Credentials":                filepath.Join(ad, "Microsoft", "Credentials"),
			"Vault":                      filepath.Join(lad, "Microsoft", "Vault"),
			"Local Credentials":          filepath.Join(lad, "Microsoft", "Credentials"),
		}
		var present []string
		for name, dir := range stores {
			if c := countArtifacts(dir); c > 0 {
				present = append(present, fmt.Sprintf("%s(%d)", name, c))
			}
		}
		if len(present) == 0 {
			r.Result = schema.ResultPartial
			r.RiskWhenOpen = schema.RiskLow
			r.Evidence = "Okunabilir DPAPI/kimlik deposu artefaktı bulunamadı"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "Kullanıcı bağlamında okunabilir kimlik deposu: " + strings.Join(present, ", ") +
			" — kullanıcı olarak çalışan herhangi bir kod (malware) bu DPAPI sırlarını çözebilir"
		r.Recommendation = "Bu depolar DPAPI ile korunur ama kullanıcı bağlamında çözülür; Credential Guard + EDR ile kimlik-erişim davranışı izlenmeli."
	})

	// 20.4 Kayitli RDP kimlik/baglantilari (lateral hareket haritasi)
	b.add("CHT-20-004", "Kayıtlı RDP kimlik/bağlantıları", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.Mapping.Attack = "T1021.001"
		r.AttemptedMethods = []string{"Terminal Server Client\\Servers + .rdp dosyaları"}
		var found []string
		if servers, err := nativeapi.RegSubKeys(registry.CURRENT_USER, `Software\Microsoft\Terminal Server Client\Servers`); err == nil {
			for _, s := range servers {
				hint, _ := nativeapi.RegString(registry.CURRENT_USER, `Software\Microsoft\Terminal Server Client\Servers\`+s, "UsernameHint")
				if hint != "" {
					found = append(found, s+" (kullanıcı: "+hint+")")
				} else {
					found = append(found, s)
				}
			}
		}
		up := os.Getenv("USERPROFILE")
		found = append(found, scanExt(filepath.Join(up, "Documents"), []string{".rdp"})...)
		if len(found) == 0 {
			r.Result = schema.ResultPartial
			r.Evidence = "Kayıtlı RDP bağlantısı / .rdp dosyası yok"
			return
		}
		r.Result = schema.ResultAllowed
		r.RiskWhenOpen = schema.RiskInfo
		r.Evidence = fmt.Sprintf("%d kayıtlı RDP hedefi/dosyası: %s", len(found), truncate(strings.Join(found, "; "), 200))
		r.Recommendation = "Bilgilendirme: kayıtlı RDP hedefleri erişilebilir sunucuları (yatay hareket haritası) ve kayıtlı kullanıcı ipuçlarını gösterir."
	})

	return b.results()
}

// --- yardimcilar ---

// hklmKeyWritable, bir HKLM anahtarinin MEVCUT kullanici token'iyla YAZILABILIR olup
// olmadigini test eder — anahtari yalniz SET_VALUE erisimiyle acmayi dener, HICBIR SEY
// YAZMAZ. Basari = yazma yetkisi var. (Elevated calisirsa dogal olarak yazilabilir gorunur;
// arac calisan baglaminda/standart kullanici olarak calistirilmalidir.)
func hklmKeyWritable(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

// findIFEOHijacks, IFEO altinda Debugger degeri olan girisleri doner; erisilebilirlik
// ikililerini (sethc/utilman/osk...) ayrica isaretler.
func findIFEOHijacks() []string {
	const base = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	subs, err := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, base)
	if err != nil {
		return nil
	}
	access := map[string]bool{
		"sethc.exe": true, "utilman.exe": true, "osk.exe": true, "magnify.exe": true,
		"narrator.exe": true, "displayswitch.exe": true, "atbroker.exe": true,
	}
	var out []string
	for _, s := range subs {
		dbg, err := nativeapi.RegString(registry.LOCAL_MACHINE, base+`\`+s, "Debugger")
		if err != nil || dbg == "" {
			continue
		}
		tag := s + " → Debugger=" + truncate(dbg, 60)
		if access[strings.ToLower(s)] {
			tag = "[ERİŞİLEBİLİRLİK ARKA KAPISI] " + tag
		}
		out = append(out, tag)
		if len(out) >= 15 {
			break
		}
	}
	return out
}

// countArtifacts, dir + bir alt-seviye dizinlerindeki dosya sayisini doner (DPAPI Protect\<SID>).
func countArtifacts(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
			if err == nil {
				for _, se := range sub {
					if !se.IsDir() {
						n++
					}
				}
			}
			continue
		}
		n++
	}
	return n
}
