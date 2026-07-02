package modules

import (
	"fmt"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat08 = "08-Encryption"

// Module08, BitLocker / sifreleme durusunu pasif okur.
// Not: tam birim-bazli durum WMI (Win32_EncryptableVolume) ister; burada registry/policy
// best-effort okunur, eksik kalan WMI alanlari durust sekilde Partial isaretlenir.
type Module08 struct{}

func NewModule08() *Module08 { return &Module08{} }

func (Module08) ID() string   { return "08" }
func (Module08) Name() string { return "Şifreleme / BitLocker" }

func (m Module08) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat08)
	const fve = `SOFTWARE\Policies\Microsoft\FVE`

	// 08.1 TPM varlik/surum — native TBS (Tbsi_GetDeviceInfo); WMI/admin gerekmez.
	b.add("CHT-08-001", "TPM varlık / durum", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"TBS Tbsi_GetDeviceInfo (native)", "registry TPM service (yedek)"}
		tpm := nativeapi.TPMVersion()
		if tpm.Present {
			if tpm.Version == "2.0" {
				r.Result = schema.ResultBlocked
				r.Evidence = "TPM mevcut, sürüm=2.0 (donanım güven kökü) — TBS ile teyit edildi"
				r.Recommendation = "TPM 2.0 mevcut; BitLocker TPM-protector ve Credential Guard için uygun."
			} else {
				v := tpm.Version
				if v == "" {
					v = "bilinmiyor"
				}
				r.Result = schema.ResultPartial
				r.Evidence = "TPM mevcut ama sürüm=" + v + " (1.2/bilinmiyor) — modern korumalar için sınırlı"
				r.Recommendation = "TPM 2.0'a yükseltme değerlendirilmeli (Credential Guard / modern BitLocker)."
			}
			return
		}
		tpmSvc := nativeapi.ServiceInstalled("TPM")
		tpmKey := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\TPM`)
		if !tpmSvc && !tpmKey {
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskHigh
			r.Evidence = "TPM TBS ile bulunamadı; registry servisi/anahtarı da yok"
			r.Recommendation = "TPM tespit edilemedi — BitLocker TPM-koruması ve Credential Guard mümkün olmayabilir."
		} else {
			r.Result = schema.ResultPartial
			r.Evidence = fmt.Sprintf("TBS TPM döndürmedi ama registry servisi=%v anahtar=%v (firmware'de kapalı olabilir)", tpmSvc, tpmKey)
			r.Recommendation = "TPM firmware'de etkinleştirilmeli."
		}
	})

	// 08.2 BitLocker durumu + protector tipleri — WMI Win32_EncryptableVolume (yetkili),
	// erisemezse (standart kullanici → access denied) registry yedek.
	b.add("CHT-08-002", "BitLocker birim durumu + protector tipleri", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.CIS = "BitLocker"
		r.AttemptedMethods = []string{"WMI Win32_EncryptableVolume", "registry FVE (yedek)"}
		rows, err := nativeapi.WMIQuery(`root\cimv2\Security\MicrosoftVolumeEncryption`,
			"SELECT * FROM Win32_EncryptableVolume",
			[]string{"DriveLetter", "ProtectionStatus", "ConversionStatus", "VolumeType"})
		if err == nil && len(rows) > 0 {
			anyUnprotected := false
			var parts []string
			for _, v := range rows {
				vt := v["VolumeType"] // 0 OS, 1 fixed data, 2 removable
				on := v["ProtectionStatus"] == "1"
				enc := v["ConversionStatus"] == "1"
				if (vt == "0" || vt == "1") && !(on && enc) {
					anyUnprotected = true
				}
				parts = append(parts, fmt.Sprintf("%s:prot=%s conv=%s type=%s", v["DriveLetter"], v["ProtectionStatus"], v["ConversionStatus"], vt))
			}
			if anyUnprotected {
				r.Result = schema.ResultAllowed
				r.Evidence = "WMI: korumasız/şifresiz sabit birim var — " + joinSemi(parts)
				r.Recommendation = "Tüm sabit/OS birimler BitLocker On + FullyEncrypted olmalı."
			} else {
				r.Result = schema.ResultBlocked
				r.Evidence = "WMI: tüm sabit/OS birimler korumalı ve tam şifreli (iyi) — " + joinSemi(parts)
			}
			return
		}
		// WMI erisilemedi → registry yedek
		blKey := nativeapi.RegKeyExists(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\BitLocker`)
		useTPM, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, fve, "UseTPM")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("WMI birim durumu okunamadı (admin gerekir); registry BitLocker control key=%v UseTPM=%d", blKey, useTPM)
		r.Recommendation = "Admin oturumda birim şifreleme durumu (Win32_EncryptableVolume) teyit edilmeli."
		if !blKey {
			r.Result = schema.ResultAllowed
			r.Evidence += " — kontrol anahtarı yok, OS diski şifresiz olabilir"
		}
	})

	// 08.3 BitLocker suspend/disable denemesi (aktif) → engellenmeli
	b.add("CHT-08-003", "BitLocker suspend/disable denemesi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1562"
		r.AttemptedMethods = []string{"manage-bde/Disable-BitLocker (gate'li)"}
		if !ctx.GateActive(r, 3, false) {
			return
		}
		markNotImplemented(r, "BitLocker suspend/disable denemesi (manage-bde/Disable-BitLocker, admin)")
	})

	// 08.5 BitLocker To Go zorlamasi
	b.add("CHT-08-005", "BitLocker To Go zorlaması (USB)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"registry FVE RDV*"}
		rdvDeny, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, fve, "RDVDenyWriteAccess")
		rdvConfig, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, fve, "RDVConfigureBDE")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("RDVDenyWriteAccess=%d (1=şifresiz USB'ye yazma engelli); RDVConfigureBDE=%d", rdvDeny, rdvConfig)
		if rdvDeny != 1 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Şifrelenmemiş USB'ye yazma engellenmeli (RDVDenyWriteAccess=1)."
		} else {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
		}
	})

	// 08.6 Kernel DMA / hibernation / device encryption
	b.add("CHT-08-006", "Kernel DMA Protection / hibernation / device encryption", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"registry DmaGuard/Power"}
		dma, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection`, "DeviceEnumerationPolicy")
		hib, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Power`, "HibernateEnabled")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("DMA DeviceEnumerationPolicy=%d; HibernateEnabled=%d (hibernation RAM'de cred sızdırabilir)", dma, hib)
		if hib == 1 {
			r.Recommendation = "Hassas cihazlarda hibernation/uyku + DMA korumaları gözden geçirilmeli."
		}
	})

	return b.results()
}
