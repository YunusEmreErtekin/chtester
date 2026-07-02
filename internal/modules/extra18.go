package modules

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat18 = "18-Lockdown"

// Module18, "kisitli calisan cihazi" vizyonuna dogrudan hizmet eden ayricalik-yukseltme,
// yetkisiz yazilim kurulumu, rogue ag ve yetkisiz uzak erisim yuzeylerini olcer. Hepsi
// PASIF (registry/servis-enum + yazma probu). Soru: calisan bu cihazdan sirkete/veriye/
// cihaza zarar verebilir mi?
type Module18 struct{}

func NewModule18() *Module18 { return &Module18{} }

func (Module18) ID() string   { return "18" }
func (Module18) Name() string { return "Çalışan Cihazı Sıkılaştırma Derinliği" }

func (m Module18) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat18)

	// 18.1 Yazilabilir servis ikili dizini — herhangi bir servisin EXE'si kullanici-yazilabilir
	// dizindeyse, standart kullanici ikiliyi degistirip SYSTEM'e yukselir.
	b.add("CHT-18-001", "Yazılabilir servis ikili dizini (binary replacement privesc)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1543.003"
		r.AttemptedMethods = []string{"Services ImagePath enum + dizin yazma probu"}
		vuln := serviceWritableBins()
		if len(vuln) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Yazılabilir dizinde servis ikili bulunamadı (System32/Program Files dışı yazılabilir yok)"
			return
		}
		r.Result = schema.ResultAllowed
		r.RiskWhenOpen = schema.RiskCritical
		r.Evidence = fmt.Sprintf("%d servis ikilisi kullanıcı-yazılabilir dizinde: %s", len(vuln), truncate(strings.Join(vuln, "; "), 220))
		r.Recommendation = "ACİL: bu servislerin ikili dizin ACL'leri düzeltilmeli; standart kullanıcı ikiliyi değiştirip SYSTEM'e yükselebilir."
	})

	// 18.2 Yetkisiz yazilim kurulum yetenegi (Store / sideload / MSI)
	b.add("CHT-18-002", "Yetkisiz yazılım kurulum yeteneği (MSI/sideload/Store)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1072"
		r.AttemptedMethods = []string{"registry Installer/Appx/WindowsStore politikaları"}
		disableMSI, _ := dwLM(`SOFTWARE\Policies\Microsoft\Windows\Installer`, "DisableMSI")
		sideload, hasSide := dwLM(`SOFTWARE\Policies\Microsoft\Windows\Appx`, "AllowAllTrustedApps")
		storeRemoved, _ := dwLM(`SOFTWARE\Policies\Microsoft\WindowsStore`, "RemoveWindowsStore")
		msiOpen := disableMSI == 0                 // 0/absent = MSI kurulum acik
		sideOpen := !hasSide || sideload == 1      // sideload izinli (imzasiz/kurumsal appx)
		storeOpen := storeRemoved != 1             // Store erisilebilir
		var open []string
		if msiOpen {
			open = append(open, "MSI kurulum açık")
		}
		if sideOpen {
			open = append(open, "sideload izinli")
		}
		if storeOpen {
			open = append(open, "Store erişilebilir")
		}
		r.Evidence = fmt.Sprintf("DisableMSI=%d; AllowAllTrustedApps=%s; RemoveWindowsStore=%d → %s",
			disableMSI, dwState(hasSide, sideload), storeRemoved, orNone(open))
		switch {
		case msiOpen && sideOpen:
			r.Result = schema.ResultAllowed
			r.Recommendation = "Çalışan yetkisiz yazılım kurabilir; MSI kurulumu (DisableMSI) ve sideload (AllowAllTrustedApps=0) kısıtlanmalı, AppLocker/WDAC ile birlikte."
		case msiOpen || sideOpen || storeOpen:
			r.Result = schema.ResultPartial
			r.Recommendation = "Kısmi kısıt; kalan kurulum kanalları (" + orNone(open) + ") kapatılmalı."
		default:
			r.Result = schema.ResultBlocked
			r.Evidence += " — kurulum kanalları kapalı"
		}
	})

	// 18.3 Rogue ag: ICS / ag koprusu (kurumsal↔kisisel ag koprulenmesi, egress baypas)
	b.add("CHT-18-003", "Rogue ağ: Internet paylaşımı (ICS) / ağ köprüsü", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1090"
		r.AttemptedMethods = []string{"registry Network Connections politikaları"}
		const nc = `SOFTWARE\Policies\Microsoft\Windows\Network Connections`
		icsUI, hasICS := dwLM(nc, "NC_ShowSharedAccessUI")       // 0 = ICS UI kapali
		bridge, hasBridge := dwLM(nc, "NC_AllowNetBridge_NLA")   // 0 = koprü kapali
		icsOpen := !hasICS || icsUI != 0
		bridgeOpen := !hasBridge || bridge != 0
		r.Evidence = fmt.Sprintf("NC_ShowSharedAccessUI=%s; NC_AllowNetBridge_NLA=%s",
			dwState(hasICS, icsUI), dwState(hasBridge, bridge))
		switch {
		case icsOpen || bridgeOpen:
			var s []string
			if icsOpen {
				s = append(s, "ICS/hotspot açık")
			}
			if bridgeOpen {
				s = append(s, "ağ köprüsü açık")
			}
			r.Result = schema.ResultAllowed
			r.Evidence += " → " + strings.Join(s, ", ")
			r.Recommendation = "Çalışan kurumsal ağı kişisel ağa köprüleyip/paylaşıp egress kontrollerini baypas edebilir; ICS ve ağ köprüsü GPO ile kapatılmalı."
		default:
			r.Result = schema.ResultBlocked
			r.Evidence += " — ICS ve köprü politikayla kapalı"
		}
	})

	// 18.4 Yetkisiz uzak erisim: Uzak Yardim + Remote Registry
	b.add("CHT-18-004", "Yetkisiz uzak erişim (Uzak Yardım / Remote Registry)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1219"
		r.AttemptedMethods = []string{"registry Remote Assistance + RemoteRegistry servis durumu"}
		ra, _ := dwLM(`SYSTEM\CurrentControlSet\Control\Remote Assistance`, "fAllowToGetHelp")
		rrStart, hasRR := dwLM(`SYSTEM\CurrentControlSet\Services\RemoteRegistry`, "Start")
		raOpen := ra == 1
		rrOpen := hasRR && rrStart != 4 // 4 = disabled
		var open []string
		if raOpen {
			open = append(open, "Uzak Yardım etkin")
		}
		if rrOpen {
			open = append(open, "Remote Registry etkin")
		}
		r.Evidence = fmt.Sprintf("fAllowToGetHelp=%d; RemoteRegistry.Start=%s → %s",
			ra, dwState(hasRR, rrStart), orNone(open))
		if len(open) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Uzak Yardım (fAllowToGetHelp=0) ve Remote Registry (Start=4/devre dışı) kapatılmalı — yetkisiz uzak erişim/registry okuma yüzeyi."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — uzak erişim yüzeyleri kapalı"
		}
	})

	return b.results()
}

// --- yardimcilar ---

func dwState(has bool, v uint64) string {
	if !has {
		return "ayarsız"
	}
	return fmt.Sprintf("%d", v)
}

// serviceExePath, ImagePath'ten calistirilabilir EXE yolunu cikarir (tirnakli/tirnaksiz,
// \??\ onekli, argumanli). .exe degilse (driver .sys) bos doner.
func serviceExePath(img string) string {
	t := strings.TrimSpace(img)
	t = strings.TrimPrefix(t, `\??\`)
	if strings.HasPrefix(t, `"`) {
		if end := strings.Index(t[1:], `"`); end >= 0 {
			return t[1 : end+1]
		}
		return strings.Trim(t, `"`)
	}
	low := strings.ToLower(t)
	if idx := strings.Index(low, ".exe"); idx >= 0 {
		return t[:idx+4]
	}
	return ""
}

// serviceWritableBins, EXE'si kullanici-yazilabilir dizinde olan servisleri doner
// (binary replacement privesc). System32/Program Files dizinleri atlanir.
func serviceWritableBins() []string {
	const base = `SYSTEM\CurrentControlSet\Services`
	subs, err := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, base)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var vuln []string
	for _, s := range subs {
		img, err := nativeapi.RegString(registry.LOCAL_MACHINE, base+`\`+s, "ImagePath")
		if err != nil || img == "" {
			continue
		}
		exe := serviceExePath(img)
		if exe == "" {
			continue
		}
		exe = expand(exe) // %SystemRoot% vb. genislet — aksi halde sistem yollari atlanmaz
		dir := filepath.Dir(exe)
		low := strings.ToLower(dir)
		if low == "" || seen[low] || strings.Contains(low, "%") {
			continue // genisletilemeyen degisken kalintisi — atla (yanlis prob onle)
		}
		seen[low] = true
		if strings.Contains(low, `\windows\`) || strings.Contains(low, `\program files`) ||
			strings.Contains(low, `\winsxs\`) {
			continue // sistem dizini — yazilamaz, prob gereksiz
		}
		if tryWriteProbe(dir) {
			vuln = append(vuln, s+"→"+truncate(exe, 70))
			if len(vuln) >= 15 {
				break
			}
		}
	}
	return vuln
}
