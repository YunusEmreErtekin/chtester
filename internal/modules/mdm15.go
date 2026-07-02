package modules

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat15 = "15-MDM"

// Module15, MDM (Intune vb.) kaydini ve GERCEKTEN UYGULANAN CSP politikalarini PASIF okur.
// Onceden arac yalniz "yonetiliyor mu" tespiti yapiyordu; bu modul uygulanan politika
// alanlarini (PolicyManager) envanterler. Native registry, shell-out yok.
type Module15 struct{}

func NewModule15() *Module15 { return &Module15{} }

func (Module15) ID() string   { return "15" }
func (Module15) Name() string { return "MDM / Yönetim Politikaları" }

const polManagerDevice = `SOFTWARE\Microsoft\PolicyManager\current\device`

// mdmEnrollment, cihazin GERCEKTEN bir MDM'e kayitli olup olmadigini doner. Enrollments
// altinda varsayilan/yerel placeholder anahtarlar (Local/Cloud/Deploy Authority) MDM
// degildir; gercek kayit DiscoveryServiceFullURL + EnrollmentState=1 ile ayirt edilir.
func mdmEnrollment() (bool, string) {
	subs, _ := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments`)
	for _, s := range subs {
		base := `SOFTWARE\Microsoft\Enrollments\` + s
		disco, _ := nativeapi.RegString(registry.LOCAL_MACHINE, base, "DiscoveryServiceFullURL")
		state, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, base, "EnrollmentState")
		if disco != "" && state == 1 {
			pid, _ := nativeapi.RegString(registry.LOCAL_MACHINE, base, "ProviderID")
			upn, _ := nativeapi.RegString(registry.LOCAL_MACHINE, base, "UPN")
			return true, fmt.Sprintf("provider=%q; upn=%q; url=%s", pid, upn, truncate(disco, 60))
		}
	}
	return false, ""
}

func (m Module15) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat15)
	enrolled, enrollInfo := mdmEnrollment()

	// 15.1 MDM kayit / saglayici
	b.add("CHT-15-001", "MDM kayıt durumu / sağlayıcı", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskInfo
		r.AttemptedMethods = []string{`registry Enrollments\*\DiscoveryServiceFullURL+EnrollmentState`}
		if !enrolled {
			r.Result = schema.ResultNotApplicable
			r.SkipReason = schema.SkipNotApplicableOS
			r.Evidence = "Gerçek MDM kaydı yok (cihaz Intune/MDM ile yönetilmiyor; yerel PolicyManager varsayılanları sayılmadı)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = "MDM kayıtlı: " + enrollInfo + " (provider 'MS DM Server' = Intune)"
		r.Recommendation = "Bilgilendirme: cihaz MDM ile yönetiliyor; uygulanan politikalar CHT-15-002'de."
	})

	// 15.2 Uygulanan CSP politika envanteri
	b.add("CHT-15-002", "Uygulanan MDM/CSP politika envanteri", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{`registry PolicyManager\current\device\* sayım`}
		if !enrolled {
			r.Result = schema.ResultNotApplicable
			r.SkipReason = schema.SkipNotApplicableOS
			r.Evidence = "Cihaz MDM yönetiminde değil — uygulanan CSP politikası kıyası anlamsız"
			return
		}
		areas, err := nativeapi.RegSubKeys(registry.LOCAL_MACHINE, polManagerDevice)
		if err != nil || len(areas) == 0 {
			r.Result = schema.ResultAllowed
			r.Evidence = "PolicyManager altında uygulanan CSP politikası yok — MDM cihaz sertleştirmesi uygulamıyor"
			r.Recommendation = "Cihaz MDM yönetiliyorsa güvenlik temel çizgisi (DeviceLock/BitLocker/Defender/Firewall CSP) atanmalı."
			return
		}
		total := 0
		for _, a := range areas {
			if vals, e := nativeapi.RegValueNames(registry.LOCAL_MACHINE, polManagerDevice+`\`+a); e == nil {
				total += len(vals)
			}
		}
		// Guvenlik-kritik alanlar uygulanmis mi
		want := []string{"DeviceLock", "BitLocker", "DeviceGuard", "Defender", "Firewall", "ApplicationManagement", "Update", "DataProtection"}
		present := map[string]bool{}
		for _, a := range areas {
			present[a] = true
		}
		var missing []string
		for _, w := range want {
			if !present[w] {
				missing = append(missing, w)
			}
		}
		r.Evidence = fmt.Sprintf("%d CSP alanı, ~%d politika uygulanmış; alanlar: %s", len(areas), total, truncate(strings.Join(areas, ","), 200))
		if len(missing) > 0 {
			r.Result = schema.ResultPartial
			r.Recommendation = "Eksik güvenlik CSP alanları: " + strings.Join(missing, ", ") + " — temel çizgiye eklenmeli."
		} else {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "MDM"
			r.Evidence += " — tüm kritik güvenlik alanları uygulanmış"
		}
	})

	// 15.3 DeviceLock CSP (MDM ile parola/PIN + ekran kilidi)
	b.add("CHT-15-003", "DeviceLock CSP (MDM parola / ekran kilidi)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1078"
		r.AttemptedMethods = []string{`registry PolicyManager\current\device\DeviceLock`}
		if !enrolled {
			r.Result = schema.ResultNotApplicable
			r.SkipReason = schema.SkipNotApplicableOS
			r.Evidence = "Cihaz MDM yönetiminde değil — DeviceLock CSP kıyası anlamsız"
			return
		}
		const dl = polManagerDevice + `\DeviceLock`
		if !nativeapi.RegKeyExists(registry.LOCAL_MACHINE, dl) {
			r.Result = schema.ResultNotApplicable
			r.SkipReason = schema.SkipNotApplicableOS
			r.Evidence = "DeviceLock CSP uygulanmamış (MDM parola/kilit politikası yok)"
			return
		}
		pwdEnabled, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, dl, "DevicePasswordEnabled")
		minLen, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, dl, "MinDevicePasswordLength")
		maxInact, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, dl, "MaxInactivityTimeDeviceLock")
		// DevicePasswordEnabled: 0 = parola zorunlu (CSP tersine semantik), 1 = zorunlu degil.
		r.Evidence = fmt.Sprintf("DevicePasswordEnabled=%d (0=zorunlu); MinUzunluk=%d; MaxInactivityLock=%d dk", pwdEnabled, minLen, maxInact)
		if pwdEnabled == 0 && maxInact > 0 {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "MDM"
		} else {
			r.Result = schema.ResultAllowed
			r.Recommendation = "MDM DeviceLock ile parola zorunlu + otomatik kilit (MaxInactivityTimeDeviceLock) ayarlanmalı."
		}
	})

	return b.results()
}
