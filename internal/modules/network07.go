package modules

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat07 = "07-Network"

// Module07, ag kontrollerini pasif/guvenli okur (egress sweep gibi gurultululer gate'li).
type Module07 struct{}

func NewModule07() *Module07 { return &Module07{} }

func (Module07) ID() string   { return "07" }
func (Module07) Name() string { return "Ağ Kontrolleri" }

func (m Module07) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat07)
	const fwBase = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`

	// 07.1 Firewall profil-bazli
	b.add("CHT-07-001", "Firewall profil-bazlı (Domain/Private/Public)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.AttemptedMethods = []string{"registry FirewallPolicy\\*Profile"}
		profiles := map[string]string{
			"DomainProfile":   "Domain",
			"StandardProfile": "Private",
			"PublicProfile":   "Public",
		}
		var states []string
		allOn := true
		for key, label := range profiles {
			en, err := nativeapi.RegDword(registry.LOCAL_MACHINE, fwBase+`\`+key, "EnableFirewall")
			outAction, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, fwBase+`\`+key, "DefaultOutboundAction")
			if err != nil || en != 1 {
				allOn = false
			}
			states = append(states, fmt.Sprintf("%s:on=%d,out=%d", label, en, outAction))
		}
		r.Evidence = strings.Join(states, " ")
		if allOn {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
			r.Evidence += " (tüm profiller açık)"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Tüm profillerde firewall etkin olmalı; default outbound 'block' değerlendirilmeli."
		}
	})

	// 07.2 Firewall kapatma denemesi (aktif) → engellenmeli
	b.add("CHT-07-002", "Firewall kapatma denemesi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1562.004"
		r.AttemptedMethods = []string{"netsh advfirewall set / registry (+ geri al)"}
		if !ctx.GateActive(r, 2, false) {
			return
		}
		// Registry yazma denemesi standart kullanicida zaten reddedilir; güvenli probe.
		err := tryRegWriteProbe(fwBase + `\StandardProfile`)
		if err == nil {
			r.Result = schema.ResultAllowed
			r.Evidence = "Firewall profil anahtarına yazılabildi (geri alındı) — kullanıcı firewall değiştirebiliyor"
			r.Recommendation = "Firewall ayar değişikliği standart kullanıcıya kapatılmalı."
		} else {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "Permission"
			r.Evidence = "Firewall ayarı değiştirilemedi: " + truncate(err.Error(), 100)
		}
	})

	// 07.4 Proxy ayari (pasif okuma + degistirilebilirlik)
	b.add("CHT-07-004", "Proxy ayarı / bypass yüzeyi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1090"
		r.AttemptedMethods = []string{"registry Internet Settings"}
		enable, _ := nativeapi.RegDword(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable")
		server, _ := nativeapi.RegString(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyServer")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("ProxyEnable=%d; ProxyServer=%q (kullanıcı hive'da değiştirilebilir)", enable, server)
		r.Recommendation = "Proxy ayarları GPO ile kilitlenmeli (kullanıcı bypass edememeli)."
	})

	// 07.13 DoH / DNS filtreleme baypas yüzeyi (pasif) — saha bulgusu: URL/içerik
	// filtrelemesi DNS tabanlıysa, cihaz DoH (443) ile çözümleyip filtreyi atlar.
	// Sertleştirilmiş cihazda tarayıcı DoH'u "off"a zorlanmalı (DnsOverHttpsMode=off).
	b.add("CHT-07-013", "DoH / DNS filtreleme baypas yüzeyi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1572"
		r.AttemptedMethods = []string{"registry Edge/Chrome DnsOverHttpsMode", "Windows EnableAutoDoh/DoHPolicy"}
		edge, edgeErr := nativeapi.RegString(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Edge`, "DnsOverHttpsMode")
		chrome, chromeErr := nativeapi.RegString(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Google\Chrome`, "DnsOverHttpsMode")
		winDoH, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`, "EnableAutoDoh")
		dohPolicy, dohPolErr := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "DoHPolicy")
		edgeOk, chromeOk, dohPolOk := edgeErr == nil, chromeErr == nil, dohPolErr == nil
		edgeOff := edgeOk && strings.EqualFold(edge, "off")
		chromeOff := chromeOk && strings.EqualFold(chrome, "off")
		// Windows resolver DoH GPO ile "off" (3) zorlanmış mı?
		winForcedOff := dohPolOk && dohPolicy == 3
		r.Evidence = fmt.Sprintf("Edge DnsOverHttpsMode=%q(set=%v) Chrome=%q(set=%v); Windows EnableAutoDoh=%d DoHPolicy=%d(set=%v)",
			edge, edgeOk, chrome, chromeOk, winDoH, dohPolicy, dohPolOk)
		// Tarayıcı DoH'u açıkça "off"a zorlanmamışsa, kullanıcı DoH ile DNS filtresini atlatabilir.
		if edgeOff && chromeOff {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
			r.Evidence += " — tarayıcı DoH politika ile kapatılmış (DNS filtre baypası engelli)"
			if !winForcedOff {
				r.Evidence += "; Windows resolver DoH ayrıca GPO ile kilitlenmeli (DoHPolicy=3)"
			}
		} else {
			r.Result = schema.ResultAllowed
			r.Evidence += " — tarayıcı DoH 'off'a zorlanmamış; cihaz DoH (443) ile DNS tabanlı URL/içerik filtresini atlatabilir"
			r.Recommendation = "Edge/Chrome DnsOverHttpsMode=off ile zorlanmalı; bilinen DoH uç noktaları firewall'da engellenmeli; port 53 yalnız kurum DNS'ine kısıtlanmalı."
		}
	})

	// 07.5 TLS inspection / kurumsal kök CA tespiti
	b.add("CHT-07-005", "TLS inspection / kurumsal kök CA tespiti", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskInfo
		r.AttemptedMethods = []string{"registry SystemCertificates\\Root sayımı"}
		machineCAs, _ := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\SystemCertificates\Root\Certificates`)
		gpoCAs, _ := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates`)
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("makine kök CA=%d; GPO kök CA=%d — fazlalık SSL-interception işareti olabilir", len(machineCAs), len(gpoCAs))
		if len(gpoCAs) > 0 {
			r.Evidence += " (GPO ile dağıtılan kök CA mevcut → muhtemel TLS inspection)"
		}
	})

	// 07.6 Captive portal / 802.1x NAC tespiti
	b.add("CHT-07-006", "802.1x NAC / captive portal tespiti", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskInfo
		r.AttemptedMethods = []string{"servis dot3svc/wlansvc"}
		wired := nativeapi.ServiceInstalled("dot3svc")
		wifi := nativeapi.ServiceInstalled("WlanSvc")
		eap := nativeapi.ServiceInstalled("EapHost")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("dot3svc(kablolu 802.1x)=%v; WlanSvc=%v; EapHost=%v", wired, wifi, eap)
	})

	// 07.7 Egress cok-portlu sweep (gurultulu [N]) — gercek TCP-erisim testi, gate'li
	b.add("CHT-07-007", "Egress çok-portlu sweep", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1048"
		r.AttemptedMethods = []string{"yaygın portlara giden TCP bağlantı denemesi (kısa timeout)"}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		egressSweep(r)
	})

	// 07.12 VPN zorunlu mu / split-tunnel
	b.add("CHT-07-012", "VPN zorunluluğu / split-tunnel", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskInfo
		r.Mapping.Attack = "T1090"
		r.AttemptedMethods = []string{"rasphone.pbk (IpPrioritizeRemote) native parse", "servis RasMan"}
		ras := nativeapi.ServiceInstalled("RasMan")
		// rasphone.pbk INI-benzeri; her [Profil] icin IpPrioritizeRemote: 1=force-tunnel,
		// 0=split-tunnel (tunel disi trafik kurumsal inspection'i atlar). Native dosya okuma.
		pbks := []string{
			filepath.Join(os.Getenv("APPDATA"), `Microsoft\Network\Connections\Pbk\rasphone.pbk`),
			filepath.Join(os.Getenv("ProgramData"), `Microsoft\Network\Connections\Pbk\rasphone.pbk`),
		}
		type prof struct {
			name  string
			split bool
		}
		var profs []prof
		for _, p := range pbks {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				t := strings.TrimSpace(strings.TrimRight(line, "\r"))
				if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
					profs = append(profs, prof{name: strings.Trim(t, "[]")})
				} else if strings.HasPrefix(t, "IpPrioritizeRemote=") && len(profs) > 0 {
					if strings.TrimSpace(strings.SplitN(t, "=", 2)[1]) == "0" {
						profs[len(profs)-1].split = true
					}
				}
			}
		}
		if len(profs) == 0 {
			r.Result = schema.ResultPartial
			r.Evidence = fmt.Sprintf("RasMan=%v; tanımlı VPN profili yok (rasphone.pbk). İstemci-VPN varsa always-on/force-tunnel doğrulanmalı", ras)
			return
		}
		var splitNames []string
		for _, p := range profs {
			if p.split {
				splitNames = append(splitNames, p.name)
			}
		}
		if len(splitNames) > 0 {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskMedium
			r.Evidence = fmt.Sprintf("%d VPN profili; split-tunnel AÇIK: %s (IpPrioritizeRemote=0)", len(profs), strings.Join(splitNames, ", "))
			r.Recommendation = "Tünel dışı trafik kurumsal filtre/inspection'ı atlar — force-tunnel'a alınmalı (IpPrioritizeRemote=1)."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence = fmt.Sprintf("%d VPN profili; tümü force-tunnel (split kapalı) — iyi", len(profs))
		}
	})

	return b.results()
}

// egressSweep, yaygin egress portlarina kisa-timeout'lu TCP baglanti dener.
// Kontrollu listener olmadigindan veri-sizdirma teyit edilemez; yalniz "ag katmaninda
// bu porta cikis acik mi" sinyali uretir (asili kalmaz: her port 2sn timeout).
func egressSweep(r *schema.Result) {
	// Genel erisilen ve genis cozunurluklu hedefler (port-bazli farkli host).
	targets := []struct {
		label string
		addr  string
	}{
		{"443/HTTPS", "1.1.1.1:443"},
		{"80/HTTP", "1.1.1.1:80"},
		{"53/DNS-TCP", "1.1.1.1:53"},
		{"22/SSH", "github.com:22"},
		{"3389/RDP", "1.1.1.1:3389"},
		{"445/SMB", "1.1.1.1:445"},
		{"21/FTP", "1.1.1.1:21"},
		{"8443/alt", "1.1.1.1:8443"},
	}
	var open, blocked []string
	for _, t := range targets {
		conn, err := net.DialTimeout("tcp", t.addr, 2*time.Second)
		if err == nil {
			conn.Close()
			open = append(open, t.label)
		} else {
			blocked = append(blocked, t.label)
		}
	}
	r.Evidence = fmt.Sprintf("açık çıkış: [%s]; engelli/erişilemez: [%s] (kontrollü listener olmadan veri-egress teyit edilemez)",
		strings.Join(open, " "), strings.Join(blocked, " "))
	switch {
	case len(open) == 0:
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = "GPO"
		r.Recommendation = "Egress sıkı görünüyor; yine de kontrollü listener ile derinlemesine test önerilir."
	case len(open) <= 2:
		r.Result = schema.ResultPartial
		r.Recommendation = "Yalnız standart portlar açık; yüksek/atipik portlar engelli (makul)."
	default:
		r.Result = schema.ResultAllowed
		r.RiskWhenOpen = schema.RiskHigh
		r.Recommendation = "Çok sayıda çıkış portu açık — egress filtreleme/proxy zorunluluğu değerlendirilmeli."
	}
}
