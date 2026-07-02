package modules

import (
	"fmt"
	"strings"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat24 = "24-Visibility"

// Module24, GORUNURLUK & YEREL POLITIKA derinligini olcer: tehlikeli kullanici haklari genis
// gruplara mi atanmis (privesc), adli izler yeterince tutuluyor mu (event log retention),
// ve ETW autologger'lari kapatilarak izleme korlestirilmis mi? Hepsi PASIF (native LSA + registry).
type Module24 struct{}

func NewModule24() *Module24 { return &Module24{} }

func (Module24) ID() string   { return "24" }
func (Module24) Name() string { return "Görünürlük & Yerel Politika Derinliği" }

// dangerousRights, standart/genis gruplara ATANMASI privesc saglayan kullanici haklari.
var dangerousRights = []struct{ right, desc string }{
	{"SeDebugPrivilege", "process belleği/inject"},
	{"SeImpersonatePrivilege", "Potato privesc"},
	{"SeAssignPrimaryTokenPrivilege", "Potato (primary token)"},
	{"SeBackupPrivilege", "SAM/SYSTEM okuma"},
	{"SeRestorePrivilege", "korumalı yazma"},
	{"SeLoadDriverPrivilege", "kernel driver yükleme"},
	{"SeTakeOwnershipPrivilege", "sahiplik ele geçirme"},
	{"SeTcbPrivilege", "SYSTEM olarak davranma"},
}

func (m Module24) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat24)

	// 24.1 Tehlikeli kullanici-haklari genis gruplara mi atanmis (privilege assignment)
	b.add("CHT-24-001", "Tehlikeli kullanıcı hakları ataması (privilege assignment)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1078"
		r.AttemptedMethods = []string{"native LsaEnumerateAccountsWithUserRight"}
		var findings []string
		any := false
		for _, dr := range dangerousRights {
			accts := nativeapi.AccountsWithRight(dr.right)
			if len(accts) > 0 {
				any = true
			}
			for _, a := range accts {
				if isBroadPrincipal(a) {
					findings = append(findings, fmt.Sprintf("%s [%s] → %s", dr.right, dr.desc, a))
				}
			}
		}
		if !any {
			r.Result = schema.ResultPartial
			r.Evidence = "Kullanıcı-hakları ataması okunamadı (LSA erişimi yok olabilir)"
			return
		}
		if len(findings) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Tehlikeli haklar yalnızca yönetici/SYSTEM'de (geniş gruplara atanmamış)"
			return
		}
		r.Result = schema.ResultAllowed
		r.RiskWhenOpen = schema.RiskCritical
		r.Evidence = fmt.Sprintf("%d tehlikeli hak GENİŞ gruba atanmış: %s", len(findings), truncate(strings.Join(findings, "; "), 240))
		r.Recommendation = "ACİL: bu haklar Users/Authenticated Users/Everyone gibi geniş gruplardan alınmalı — standart kullanıcı doğrudan SYSTEM'e yükselir."
	})

	// 24.2 Event log retention/boyut — adli gorunurluk (saldirgan loglari devirir)
	b.add("CHT-24-002", "Event log retention/boyut (adli görünürlük)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.Mapping.Attack = "T1070.001"
		r.AttemptedMethods = []string{"registry EventLog\\Security MaxSize/Retention/AutoBackup"}
		const base = `SYSTEM\CurrentControlSet\Services\EventLog\Security`
		maxSize, hasMax := dwLM(base, "MaxSize")
		autoBackup, _ := dwLM(base, "AutoBackupLogFiles")
		const minRecommended = 196608 * 1024 // ~192 MB (CIS önerisi)
		mb := maxSize / (1024 * 1024)
		r.Evidence = fmt.Sprintf("Security MaxSize=%d MB; AutoBackupLogFiles=%d", mb, autoBackup)
		switch {
		case !hasMax:
			r.Result = schema.ResultPartial
			r.Evidence = "Security MaxSize ayarlı değil (varsayılan ~20MB olabilir — kısa retention)"
			r.Recommendation = "Security log ≥192MB + arşivleme yapılandırılmalı."
		case maxSize < minRecommended && autoBackup != 1:
			r.Result = schema.ResultAllowed
			r.Recommendation = "Security log küçük ve arşivleme kapalı — saldırgan olayları log'u devirerek gizleyebilir. ≥192MB + AutoBackupLogFiles=1 önerilir."
		default:
			r.Result = schema.ResultBlocked
			r.Evidence += " — yeterli retention/arşivleme"
		}
	})

	// 24.3 ETW autologger butunlugu — izleme korlestirme (EDR/denetim ETW kapatilmis mi)
	b.add("CHT-24-003", "ETW autologger bütünlüğü (izleme körleştirme)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1562.006"
		r.AttemptedMethods = []string{"registry WMI\\Autologger Start değerleri"}
		const base = `SYSTEM\CurrentControlSet\Control\WMI\Autologger`
		critical := []string{"EventLog-Security", "EventLog-System", "DefenderApiLogger", "DefenderAuditLogger"}
		var disabled []string
		checked := 0
		for _, name := range critical {
			start, ok := dwLM(base+`\`+name, "Start")
			if !ok {
				continue // bu autologger yok
			}
			checked++
			if start == 0 {
				disabled = append(disabled, name)
			}
		}
		if checked == 0 {
			r.Result = schema.ResultPartial
			r.Evidence = "ETW autologger durumu okunamadı"
			return
		}
		r.Evidence = fmt.Sprintf("%d kritik autologger'dan devre dışı: %s", checked, orNone(disabled))
		if len(disabled) > 0 {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskHigh
			r.Recommendation = "ACİL: kritik ETW autologger'ları devre dışı (Start=0) — birileri EDR/denetim izlemesini körleştirmiş; incelenip Start=1 yapılmalı."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — kritik autologger'lar etkin"
		}
	})

	return b.results()
}

// isBroadPrincipal, bir hesap adinin GENIS/dusuk-guven bir grup olup olmadigini belirler
// (Users / Authenticated Users / Everyone / INTERACTIVE / Domain Users).
func isBroadPrincipal(name string) bool {
	low := strings.ToLower(name)
	for _, p := range []string{"everyone", "authenticated users", "interactive", `\users`, "domain users", "domänen-benutzer"} {
		if strings.Contains(low, p) {
			return true
		}
	}
	return low == "users"
}
