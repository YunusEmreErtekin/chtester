package modules

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat23 = "23-UpdateWireless"

// Module23, GUNCELLEME BUTUNLUGU + KABLOSUZ/CEVRE BIRIMI saldiri yuzeyini olcer: WSUS-over-HTTP
// ile guncelleme MITM (zararli yama enjeksiyonu), kayitli acik/otomatik-baglanan WLAN profilleri
// (evil-twin/karma), ve cihaz-kurulum kontrolu derinligi (BadUSB/HID enjeksiyon). Pasif.
type Module23 struct{}

func NewModule23() *Module23 { return &Module23{} }

func (Module23) ID() string   { return "23" }
func (Module23) Name() string { return "Güncelleme & Kablosuz/Çevre Birimi Bütünlüğü" }

func (m Module23) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat23)

	// 23.1 WSUS/guncelleme MITM — HTTP WSUS zararli yama enjeksiyonu saglar
	b.add("CHT-23-001", "Güncelleme bütünlüğü (WSUS-over-HTTP MITM)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1195.002"
		r.AttemptedMethods = []string{"registry WindowsUpdate WUServer/WUStatusServer"}
		const wu = `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
		server, _ := nativeapi.RegString(registry.LOCAL_MACHINE, wu, "WUServer")
		if server == "" {
			r.Result = schema.ResultPartial
			r.RiskWhenOpen = schema.RiskLow
			r.Evidence = "WSUS ayarlı değil — güncellemeler Microsoft Update (HTTPS) üzerinden; MITM yüzeyi düşük"
			return
		}
		low := strings.ToLower(strings.TrimSpace(server))
		r.Evidence = "WUServer=" + server
		if strings.HasPrefix(low, "http://") {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskCritical
			r.Recommendation = "ACİL: WSUS HTTP üzerinden — ağdaki saldırgan sahte/zararlı güncelleme (imzasız driver dahil) enjekte edebilir. HTTPS WSUS'a geçilmeli + TLS zorunlu."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — HTTPS WSUS (MITM'e dirençli)"
		}
	})

	// 23.2 Kablosuz saldiri yuzeyi — acik ag + otomatik-baglanma (evil-twin/karma)
	b.add("CHT-23-002", "Kablosuz saldırı yüzeyi (açık ağ / otomatik-bağlanma)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1557"
		r.AttemptedMethods = []string{"WlanGetProfile authentication + connectionMode"}
		profs, ok := nativeapi.WiFiProfiles()
		if !ok {
			r.Result = schema.ResultNotApplicable
			r.Evidence = "WLAN servisi/arabirimi yok"
			return
		}
		if len(profs) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Kayıtlı WLAN profili yok"
			return
		}
		var open, autoOpen []string
		for _, p := range profs {
			if strings.EqualFold(p.Auth, "open") {
				open = append(open, p.SSID)
				if p.AutoConnect {
					autoOpen = append(autoOpen, p.SSID)
				}
			}
		}
		r.Evidence = fmt.Sprintf("%d profil; açık ağ=%s; açık+otomatik-bağlanan=%s",
			len(profs), orNone(open), orNone(autoOpen))
		switch {
		case len(autoOpen) > 0:
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskHigh
			r.Recommendation = "ACİL: açık ağa OTOMATİK bağlanan profil(ler) — saldırgan aynı SSID'yi yayınlayıp cihazı sahte AP'ye çeker (karma/evil-twin). Bu profiller silinmeli, otomatik-bağlanma kapatılmalı."
		case len(open) > 0:
			r.Result = schema.ResultAllowed
			r.Recommendation = "Kayıtlı açık ağ profilleri şifresiz/kimliksizdir (evil-twin); kaldırılmalı."
		default:
			r.Result = schema.ResultBlocked
			r.Evidence += " — açık ağ profili yok"
		}
	})

	// 23.3 Cihaz kurulum kontrolu derinligi — BadUSB/HID enjeksiyon yuzeyi
	b.add("CHT-23-003", "Cihaz kurulum kontrolü (BadUSB/HID sınıf-deny)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1200"
		r.AttemptedMethods = []string{"registry DeviceInstall\\Restrictions (DenyUnspecified + sınıf listeleri)"}
		const dir = `SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`
		denyUnspec, _ := dwLM(dir, "DenyUnspecified")
		denyClasses := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, dir+`\DenyDeviceClasses`)
		allowClasses := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, dir+`\AllowDeviceClasses`)
		r.Evidence = fmt.Sprintf("DenyUnspecified=%d; DenyDeviceClasses=%v; AllowDeviceClasses=%v",
			denyUnspec, denyClasses, allowClasses)
		switch {
		case denyUnspec == 1 || allowClasses:
			r.Result = schema.ResultBlocked
			r.Evidence += " — varsayılan-reddet / izin-listesi tanımlı (BadUSB/HID kısıtlı)"
		case denyClasses:
			r.Result = schema.ResultPartial
			r.Evidence += " — sınıf-bazlı reddet var ama varsayılan-reddet yok; HID izinliyse BadUSB açık"
			r.Recommendation = "DenyUnspecified=1 (varsayılan-reddet) + HID sınıfı için deny; aksi halde Rubber Ducky/BadUSB tuş enjeksiyonu mümkün."
		default:
			r.Result = schema.ResultAllowed
			r.Recommendation = "Cihaz kurulum kısıtı yok — herhangi bir USB (HID klavye taklidi/BadUSB dahil) sürücüsüz kurulur. DeviceInstall Restrictions ile sınıf-bazlı allow-list uygulanmalı."
		}
	})

	return b.results()
}
