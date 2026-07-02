package modules

import (
	"fmt"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/context"
	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat13 = "13-Lateral"

// Module13, yanal hareket / ic ag enum yuzeyini test eder. AD enum gurultulu [N] + scope
// + SOC ister ve YALNIZ domain'e bagliysa anlamlidir. Gercek saldiri YOK; salt-okunur
// LDAP sayimi (kullanici adi/secret toplanmaz). Yapilan sorgular DC tarafinda gorunur.
type Module13 struct {
	Env *context.Env
}

func NewModule13(env *context.Env) *Module13 { return &Module13{Env: env} }

func (Module13) ID() string   { return "13" }
func (Module13) Name() string { return "Yanal Hareket / İç Ağ" }

func (m Module13) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat13)
	domain := m.Env != nil && m.Env.DomainJoin != "Workgroup"

	// Pahali LDAP enumerasyonunu yetkili (noisy) ve domain ise BIR KEZ yap, vektorler paylassin.
	var ad nativeapi.ADStats
	if domain && ctx.NoisyAllowed() {
		ad = nativeapi.ADEnumerate()
	}

	// 13.1 AD enumeration yuzeyi (gercek native LDAP sayimi)
	b.add("CHT-13-001", "AD enumeration yüzeyi (user/group/SPN/delegation)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1087.002"
		r.AttemptedMethods = []string{"native LDAP (wldap32) salt-okunur sayım", "entegre kimlik bind"}
		if !domain {
			r.Result = schema.ResultNotApplicable
			r.SkipReason = schema.SkipNotApplicableOS
			r.Evidence = "Cihaz domain'e bağlı değil — AD enum uygulanamaz"
			return
		}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		if !ad.OK {
			r.Result = schema.ResultError
			r.Evidence = "AD LDAP sorgusu başarısız (DC erişimi yok / bind reddedildi)"
			return
		}
		r.Result = schema.ResultAllowed // standart kullanici AD'yi enum edebildi = yuzey acik
		r.Evidence = fmt.Sprintf("LDAP enum BAŞARILI (base=%s): Users=%d Computers=%d Groups=%d | Kerberoastable=%d AS-REP=%d UnconstrainedDeleg=%d",
			truncate(ad.BaseDN, 60), ad.Users, ad.Computers, ad.Groups, ad.Kerberoastable, ad.ASREPRoastable, ad.UnconstrainedDelegation)
		switch {
		case ad.Kerberoastable > 0 || ad.ASREPRoastable > 0 || ad.UnconstrainedDelegation > 0:
			r.RiskWhenOpen = schema.RiskCritical
			r.Recommendation = "Saldırı yüzeyi var — Kerberoastable hesaplara gMSA+AES; AS-REP için preauth zorunlu; unconstrained delegation kaldırılmalı. Ayrıca standart kullanıcı tüm dizini enum edebiliyor (LDAP imzalama + Defender for Identity ile izlenmeli)."
		default:
			r.Recommendation = "Belirgin roast/delegation yüzeyi yok; ancak standart kullanıcı tüm AD'yi enum edebiliyor — LDAP imzalama + ATA/Defender for Identity ile izlenmeli."
		}
	})

	// 13.3 SMB sweep / share enum — guvenli genel sweep hedef listesi ister (scope'tan).
	b.add("CHT-13-003", "SMB sweep / erişilebilir host haritası", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1135"
		if !ctx.GateActive(r, 2, true) {
			return
		}
		markNotImplemented(r, "SMB sweep / erisilebilir host haritasi (hedef listesi scope'tan gelmeli)")
	})

	// 13.5 PtH / Kerberoast / AS-REP yuzeyi (pasif registry + enum sayilari)
	b.add("CHT-13-005", "PtH / Kerberoast / AS-REP roast yüzeyi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1558.003"
		if !domain {
			r.Result = schema.ResultNotApplicable
			r.SkipReason = schema.SkipNotApplicableOS
			r.Evidence = "Domain'e bağlı değil"
			return
		}
		ntlmMin, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`, "NtlmMinClientSec")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("NtlmMinClientSec=0x%X", ntlmMin)
		if ad.OK {
			r.Evidence += fmt.Sprintf("; Kerberoastable=%d AS-REP=%d (LDAP enum)", ad.Kerberoastable, ad.ASREPRoastable)
			if ad.Kerberoastable > 0 || ad.ASREPRoastable > 0 {
				r.Result = schema.ResultAllowed
				r.RiskWhenOpen = schema.RiskHigh
			}
		}
		r.Recommendation = "Servis hesapları için gMSA + AES-only; AS-REP için preauth zorunlu."
	})

	// 13.7 ADCS misconfig yuzeyi (gercek sablon sayimi)
	b.add("CHT-13-007", "ADCS misconfig (ESC1) yüzeyi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1649"
		if !domain {
			r.Result = schema.ResultNotApplicable
			r.SkipReason = schema.SkipNotApplicableOS
			r.Evidence = "Domain'e bağlı değil"
			return
		}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		if !ad.OK {
			r.Result = schema.ResultError
			r.Evidence = "ADCS sorgusu için LDAP bind başarısız"
			return
		}
		r.Evidence = fmt.Sprintf("Sertifika şablonu=%d; ENROLLEE_SUPPLIES_SUBJECT (ESC1 yüzeyi)=%d", ad.ADCSTemplates, ad.ADCSEnrolleeSuppliesSubject)
		switch {
		case ad.ADCSEnrolleeSuppliesSubject > 0:
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskHigh
			r.Recommendation = "ESC1 yüzeyi: ENROLLEE_SUPPLIES_SUBJECT izinli şablon(lar) var — düşük-yetki enrollment + SAN ile privesc riski. Şablon ACL'leri ve 'Supply in request' kısıtlanmalı."
		case ad.ADCSTemplates > 0:
			r.Result = schema.ResultPartial
			r.Evidence += " — belirgin ESC1 yüzeyi yok (diğer ESC'ler için derin inceleme önerilir)"
		default:
			r.Result = schema.ResultNotApplicable
			r.Evidence = "ADCS sertifika şablonu bulunamadı (CA yok veya erişilemiyor)"
		}
	})

	// 13.9 Domain trust yuzeyi (native netapi32; hafif)
	b.add("CHT-13-009", "Domain trust yüzeyi (forest/external)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1482"
		r.AttemptedMethods = []string{"native DsEnumerateDomainTrusts"}
		if !domain {
			r.Result = schema.ResultNotApplicable
			r.SkipReason = schema.SkipNotApplicableOS
			r.Evidence = "Domain'e bağlı değil"
			return
		}
		cnt, ok := nativeapi.DomainTrustCount()
		if !ok {
			r.Result = schema.ResultPartial
			r.Evidence = "Domain trust listesi sorgulanamadı"
			return
		}
		r.Evidence = fmt.Sprintf("%d domain trust (outbound+inbound)", cnt)
		if cnt > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Trust ilişkileri yanal hareket yüzeyidir; external/forest trust'larda SID filtering + selective authentication doğrulanmalı."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — ek trust yok"
		}
	})

	return b.results()
}
