package modules

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat22 = "22-Network"

// Module22, AG SALDIRI yuzey derinligini olcer: calisan/saldirgan bu cihazdan agi zehirleyip
// (Responder/mitm6) veya pivot/MITM yapip sirkete/kimliklere zarar verebilir mi? LLMNR (12-002)
// ve mDNS (16-010) zaten var; bu modul NBT-NS (per-adapter), IPv6/mitm6 ve ag-katmani
// sertlestirmesini (ICMP redirect / source routing / IP forwarding) ekler. Hepsi pasif registry.
type Module22 struct{}

func NewModule22() *Module22 { return &Module22{} }

func (Module22) ID() string   { return "22" }
func (Module22) Name() string { return "Ağ Saldırı Yüzeyi Derinliği" }

func (m Module22) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat22)
	const tcpip = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

	// 22.1 NBT-NS (NetBIOS ad servisi) poisoning — per-adapter NetbiosOptions
	b.add("CHT-22-001", "NBT-NS (NetBIOS) poisoning yüzeyi (per-adapter)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1557.001"
		r.AttemptedMethods = []string{"registry NetBT Interfaces NetbiosOptions"}
		const base = `SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`
		subs, err := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, base)
		if err != nil {
			r.Result = schema.ResultPartial
			r.Evidence = "NetBT arayüzleri okunamadı"
			return
		}
		var enabled int
		total := 0
		for _, s := range subs {
			if !strings.HasPrefix(strings.ToLower(s), "tcpip_") {
				continue
			}
			total++
			opt, ok := dwLM(base+`\`+s, "NetbiosOptions")
			if !ok || opt != 2 { // 2 = NetBIOS-over-TCP KAPALI; 0(DHCP)/1 = acik → poisoning
				enabled++
			}
		}
		r.Evidence = fmt.Sprintf("%d/%d adaptörde NBT-NS açık (NetbiosOptions≠2)", enabled, total)
		if enabled == 0 && total > 0 {
			r.Result = schema.ResultBlocked
			r.Evidence += " — tüm adaptörlerde NetBIOS-over-TCP kapalı (iyi)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Recommendation = "NBT-NS Responder ile kimlik toplama/relay yüzeyidir; tüm adaptörlerde NetbiosOptions=2 (devre dışı) yapılmalı."
	})

	// 22.2 IPv6 / mitm6 yuzeyi — rogue DHCPv6 → DNS ele gecirme → NTLM relay (LDAP/ADCS)
	b.add("CHT-22-002", "IPv6 / mitm6 yüzeyi (rogue DHCPv6 → NTLM relay)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1557"
		r.AttemptedMethods = []string{"registry Tcpip6 DisabledComponents"}
		dc, ok := dwLM(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`, "DisabledComponents")
		// 0xFF = IPv6 bilesenleri kapali. 0/ayarsiz = IPv6 tam acik → mitm6 hedefi.
		ipv6On := !ok || dc != 0xFF
		r.Evidence = fmt.Sprintf("DisabledComponents=%s → IPv6 %s", dwState(ok, dc), onOff(ipv6On))
		if !ipv6On {
			r.Result = schema.ResultBlocked
			r.Evidence += " — IPv6 devre dışı (mitm6 yüzeyi yok)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Recommendation = "IPv6 kullanılmıyorsa mitm6'ya karşı ağda DHCPv6/RA-Guard yoksa risklidir; kullanılmıyorsa devre dışı (DisabledComponents=0xFF) veya ağda RA Guard + DHCPv6 snooping uygulanmalı."
	})

	// 22.3 Ag-katmani sertlestirme — ICMP redirect / source routing / IP forwarding (pivot/MITM)
	b.add("CHT-22-003", "Ağ katmanı sertleştirme (ICMP redirect / source routing / forwarding)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1090"
		r.AttemptedMethods = []string{"registry Tcpip EnableICMPRedirect/DisableIPSourceRouting/IPEnableRouter"}
		icmp, hasICMP := dwLM(tcpip, "EnableICMPRedirect")     // 1/ayarsiz = acik (kotu)
		srcRoute, hasSR := dwLM(tcpip, "DisableIPSourceRouting") // 2 = tam kapali (iyi)
		router, _ := dwLM(tcpip, "IPEnableRouter")             // 1 = cihaz yonlendiriyor (kotu)
		var issues []string
		if !hasICMP || icmp != 0 {
			issues = append(issues, "ICMP redirect açık (MITM yeniden yönlendirme)")
		}
		if !hasSR || srcRoute != 2 {
			issues = append(issues, "IP source routing tam kapalı değil")
		}
		if router == 1 {
			issues = append(issues, "IP forwarding açık (cihaz router/pivot)")
		}
		r.Evidence = fmt.Sprintf("EnableICMPRedirect=%s; DisableIPSourceRouting=%s; IPEnableRouter=%d",
			dwState(hasICMP, icmp), dwState(hasSR, srcRoute), router)
		if len(issues) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence += " — ağ katmanı sağlam"
			return
		}
		r.Result = schema.ResultAllowed
		r.Recommendation = "Sertleştirilmeli: EnableICMPRedirect=0, DisableIPSourceRouting=2, IPEnableRouter=0 — " + strings.Join(issues, ", ") + "."
	})

	return b.results()
}
