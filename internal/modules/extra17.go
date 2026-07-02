package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat17 = "17-Config"

// Module17, ilk 16 modulde kapsanmayan yaygin YANLIS YAPILANDIRMA / EKSIK SERTLESTIRME
// kontrollerini ekler. Hepsi PASIF (registry/native/dosya okuma): yerel SMB paylasimlari,
// onbellek kimlik, Kerberos zayif sifreleme, exploit korumasi, hosts, artik kimlik-dokum
// artefaktlari, eslenmis suruculer, COM hijack yuzeyi.
type Module17 struct{}

func NewModule17() *Module17 { return &Module17{} }

func (Module17) ID() string   { return "17" }
func (Module17) Name() string { return "Ek Konfigürasyon Denetimleri" }

func (m Module17) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat17)

	// 17.1 Yerel SMB paylasimlari + AutoShareWks
	b.add("CHT-17-001", "Yerel SMB paylaşımları + admin share (AutoShareWks)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1135"
		r.AttemptedMethods = []string{"native NetShareEnum (level 2)", "registry AutoShareWks"}
		sh := nativeapi.LocalShares()
		if !sh.OK {
			r.Result = schema.ResultPartial
			r.Evidence = "Paylaşımlar listelenemedi"
			return
		}
		var custom, admin []string
		for _, s := range sh.Shares {
			if s.IsAdmin || strings.EqualFold(s.Name, "IPC$") {
				admin = append(admin, s.Name)
			} else {
				custom = append(custom, fmt.Sprintf("%s→%s", s.Name, s.Path))
			}
		}
		autoshare, hasAS := dwLM(`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "AutoShareWks")
		adminDisabled := hasAS && autoshare == 0
		r.Evidence = fmt.Sprintf("admin/gizli=%s; özel paylaşım=%s; AutoShareWks=%s",
			orNone(admin), orNone(custom), asState(hasAS, autoshare))
		switch {
		case len(custom) > 0:
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskHigh
			r.Recommendation = "Özel SMB paylaşımları veri sızıntısı yüzeyidir; ACL'leri gözden geçirin, gereksizse kaldırın."
		case len(admin) > 0 && !adminDisabled:
			r.Result = schema.ResultAllowed
			r.Recommendation = "Varsayılan admin paylaşımları (C$/ADMIN$) yatay hareket yüzeyi; AutoShareWks=0 ile kapatılabilir."
		default:
			r.Result = schema.ResultBlocked
			r.Evidence += " — özel paylaşım yok / admin paylaşımları kapalı"
		}
	})

	// 17.2 Onbellege alinmis oturum kimligi (offline cracking)
	b.add("CHT-17-002", "Önbelleğe alınmış oturum kimliği sayısı (CachedLogonsCount)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1003.005"
		r.AttemptedMethods = []string{"registry Winlogon\\CachedLogonsCount"}
		s, err := nativeapi.RegString(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "CachedLogonsCount")
		if err != nil {
			r.Result = schema.ResultPartial
			r.Evidence = "CachedLogonsCount okunamadı (varsayılan 10 olabilir)"
			r.RiskWhenOpen = schema.RiskLow
			return
		}
		n, _ := strconv.Atoi(strings.TrimSpace(s))
		r.Evidence = fmt.Sprintf("CachedLogonsCount=%s", s)
		switch {
		case n == 0:
			r.Result = schema.ResultBlocked
			r.Evidence += " — önbelleğe alınmış kimlik yok (iyi)"
		case n <= 4:
			r.Result = schema.ResultPartial
			r.RiskWhenOpen = schema.RiskLow
			r.Recommendation = "Domain-joined cihazlarda 0-1 önerilir (çevrimdışı MSCACHE kırma yüzeyi)."
		default:
			r.Result = schema.ResultAllowed
			r.Recommendation = "CachedLogonsCount düşürülmeli (0-1); yüksek değer çevrimdışı MSCACHEv2 hash kırma yüzeyini büyütür."
		}
	})

	// 17.3 Kerberos zayif sifreleme (RC4/DES)
	b.add("CHT-17-003", "Kerberos zayıf şifreleme (RC4/DES izinli)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1558"
		r.AttemptedMethods = []string{"registry Kerberos SupportedEncryptionTypes"}
		v, ok := dwLM(`SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`, "SupportedEncryptionTypes")
		if !ok {
			r.Result = schema.ResultPartial
			r.Evidence = "SupportedEncryptionTypes ayarlı değil — Windows varsayılanı RC4'ü içerir (zayıf)"
			r.Recommendation = "SupportedEncryptionTypes=0x18 (yalnız AES128+AES256) ile RC4/DES kapatılmalı."
			return
		}
		weak := v&0x1 != 0 || v&0x2 != 0 || v&0x4 != 0 // DES-CRC/DES-MD5/RC4
		r.Evidence = fmt.Sprintf("SupportedEncryptionTypes=0x%X (DES=%v RC4=%v AES128=%v AES256=%v)",
			v, v&0x3 != 0, v&0x4 != 0, v&0x8 != 0, v&0x10 != 0)
		if weak {
			r.Result = schema.ResultAllowed
			r.Recommendation = "RC4/DES kapatılmalı: SupportedEncryptionTypes=0x18 (yalnız AES)."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — yalnız AES (iyi)"
		}
	})

	// 17.4 Exploit korumasi / sistem geneli azaltmalar (SEHOP/ASLR)
	b.add("CHT-17-004", "Exploit koruması / sistem azaltmaları (SEHOP/ASLR)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1211"
		r.AttemptedMethods = []string{"registry kernel\\DisableExceptionChainValidation", "MoveImages"}
		sehopOff, _ := dwLM(`SYSTEM\CurrentControlSet\Control\Session Manager\kernel`, "DisableExceptionChainValidation")
		aslr, hasAslr := dwLM(`SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`, "MoveImages")
		var issues []string
		if sehopOff == 1 {
			issues = append(issues, "SEHOP devre dışı")
		}
		if hasAslr && aslr == 0 {
			issues = append(issues, "ASLR (MoveImages) devre dışı")
		}
		r.Evidence = fmt.Sprintf("SEHOP=%s; ASLR/MoveImages=%s",
			onOff(sehopOff != 1), aslrState(hasAslr, aslr))
		if len(issues) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Sistem azaltmaları açılmalı: " + strings.Join(issues, ", ") + " (Exploit Protection / GPO)."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — temel azaltmalar etkin"
		}
	})

	// 17.5 Hosts dosyasi degisikligi (statik DNS override)
	b.add("CHT-17-005", "Hosts dosyası değişikliği (statik DNS override)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.Mapping.Attack = "T1565.001"
		r.AttemptedMethods = []string{"hosts dosyası okuma + aktif giriş sayımı"}
		hosts := filepath.Join(systemRoot(), `System32\drivers\etc\hosts`)
		data, err := os.ReadFile(hosts)
		if err != nil {
			r.Result = schema.ResultPartial
			r.Evidence = "hosts okunamadı: " + truncate(err.Error(), 80)
			return
		}
		var entries []string
		for _, ln := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(ln)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			// varsayilan localhost satirlari onemsiz
			if strings.Contains(t, "127.0.0.1") && strings.Contains(strings.ToLower(t), "localhost") {
				continue
			}
			if strings.HasPrefix(t, "::1") {
				continue
			}
			entries = append(entries, t)
			if len(entries) >= 20 {
				break
			}
		}
		if len(entries) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "hosts dosyasında aktif özel giriş yok (temiz)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("%d aktif hosts girişi: %s", len(entries), truncate(strings.Join(entries, " | "), 200))
		r.Recommendation = "hosts girişleri incelenmeli — statik DNS override phishing/C2 yönlendirmesi olabilir."
	})

	// 17.6 Artik kimlik-dokum / hassas artefakt (sam.bak, *.dmp)
	b.add("CHT-17-006", "Artık kimlik-döküm / hassas artefakt (sam.bak, *.dmp)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1003"
		r.AttemptedMethods = []string{"bilinen dünya-okunur konumlarda desen taraması"}
		sr := systemRoot()
		dirs := []string{
			filepath.Join(sr, "Tasks"), filepath.Join(sr, "Temp"), sr,
			os.TempDir(), `C:\`, os.Getenv("PUBLIC"), os.Getenv("ProgramData"),
		}
		var hits []string
		for _, d := range dirs {
			if d == "" {
				continue
			}
			hits = append(hits, scanSensitiveArtifacts(d)...)
			if len(hits) >= 25 {
				break
			}
		}
		if len(hits) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Bilinen konumlarda artık kimlik-döküm/hassas artefakt bulunamadı"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("%d şüpheli artefakt: %s", len(hits), truncate(strings.Join(hits, "; "), 220))
		r.Recommendation = "ACİL: bu dosyalar (SAM/SYSTEM kopyası, LSASS/proc dump) kimlik hırsızlığı kalıntısıdır — incelenip silinmeli, olay müdahalesi değerlendirilmeli."
	})

	// 17.7 Eslenmis ag surucileri / erisilebilir dosya sunuculari
	b.add("CHT-17-007", "Eşlenmiş ağ sürücüleri / erişilebilir dosya sunucuları", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskLow
		r.Mapping.Attack = "T1135"
		r.AttemptedMethods = []string{"registry HKCU\\Network alt anahtarları"}
		mapped := enumMappedDrives()
		if len(mapped) == 0 {
			r.Result = schema.ResultPartial
			r.Evidence = "Eşlenmiş ağ sürücüsü yok (kalıcı)"
			return
		}
		r.Result = schema.ResultAllowed
		r.RiskWhenOpen = schema.RiskInfo
		r.Evidence = fmt.Sprintf("%d eşlenmiş sürücü: %s", len(mapped), strings.Join(mapped, "; "))
		r.Recommendation = "Bilgilendirme: eşlenmiş paylaşımlar erişilebilir veri sunucularını gösterir (yatay hareket/veri erişim haritası)."
	})

	// 17.8 COM hijack yuzeyi (HKCU InprocServer32 kullanici-yazilabilir yol)
	b.add("CHT-17-008", "COM hijack yüzeyi (HKCU InprocServer32)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1546.015"
		r.AttemptedMethods = []string{"registry HKCU\\Software\\Classes\\CLSID\\*\\InprocServer32"}
		sus, other := enumComHijack()
		switch {
		case len(sus) > 0:
			// Temp/Downloads/Public'te COM sunucusu = gercek hijack gostergesi.
			r.Result = schema.ResultAllowed
			r.RiskWhenOpen = schema.RiskHigh
			r.Evidence = fmt.Sprintf("%d ŞÜPHELİ konumda COM sunucusu (Temp/Downloads/Public): %s",
				len(sus), truncate(strings.Join(sus, "; "), 220))
			r.Recommendation = "ACİL: bu COM InprocServer32 kayıtları hijack/persistence göstergesidir; DLL'ler incelenmeli."
		case other > 0:
			// AppData\Local\<uygulama> COM'lari mesru yazilimda (Teams/OneDrive) yaygin — envanter.
			r.Result = schema.ResultPartial
			r.RiskWhenOpen = schema.RiskLow
			r.Evidence = fmt.Sprintf("%d per-user COM sunucusu (AppData; meşru yazılımda tipik) — Temp/Downloads/Public'te şüpheli kayıt yok", other)
			r.Recommendation = "Bilgilendirme: per-user COM inventarı; anormal/imzasız DLL'ler için periyodik gözden geçirme."
		default:
			r.Result = schema.ResultBlocked
			r.Evidence = "HKCU CLSID InprocServer32'de kullanıcı-yol COM sunucusu yok (temiz)"
		}
	})

	return b.results()
}

// --- yardimcilar ---

func orNone(s []string) string {
	if len(s) == 0 {
		return "(yok)"
	}
	return strings.Join(s, ", ")
}

func asState(has bool, v uint64) string {
	if !has {
		return "ayarsız (varsayılan: admin share açık)"
	}
	if v == 0 {
		return "0 (admin share kapalı)"
	}
	return fmt.Sprintf("%d (açık)", v)
}

func onOff(on bool) string {
	if on {
		return "etkin"
	}
	return "devre dışı"
}

func aslrState(has bool, v uint64) string {
	if !has {
		return "varsayılan (etkin)"
	}
	if v == 0 {
		return "devre dışı"
	}
	return "etkin"
}

// scanSensitiveArtifacts, bir dizinde (recursive DEGIL) kimlik-dokum/hive desenlerini arar.
func scanSensitiveArtifacts(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		low := strings.ToLower(e.Name())
		match := strings.HasSuffix(low, ".dmp") ||
			strings.Contains(low, "lsass") ||
			strings.Contains(low, "sam.bak") || strings.Contains(low, "sam.save") ||
			strings.HasSuffix(low, ".dit") || strings.Contains(low, "ntds") ||
			(strings.Contains(low, "sam") && strings.HasSuffix(low, ".hive"))
		if match {
			out = append(out, filepath.Join(dir, e.Name()))
			if len(out) >= 25 {
				break
			}
		}
	}
	return out
}

// enumMappedDrives, HKCU\Network altindaki kalici eslenmis suruculeri doner.
func enumMappedDrives() []string {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Network`, registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()
	letters, _ := k.ReadSubKeyNames(-1)
	var out []string
	for _, l := range letters {
		remote, _ := nativeapi.RegString(registry.CURRENT_USER, `Network\`+l, "RemotePath")
		if remote != "" {
			out = append(out, strings.ToUpper(l)+": → "+remote)
		}
	}
	return out
}

// enumComHijack, HKCU CLSID InprocServer32 kayitlarini tarar. SUPHELI (Temp/Downloads/
// Public'te DLL) olanlari ayri doner; digerlerini (AppData'daki mesru per-user COM, ör.
// Teams/OneDrive) sadece sayar — gurultuyu bulgudan ayirmak icin.
func enumComHijack() (suspicious []string, otherCount int) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Classes\CLSID`, registry.READ)
	if err != nil {
		return nil, 0
	}
	defer k.Close()
	clsids, _ := k.ReadSubKeyNames(-1)
	for i, id := range clsids {
		if i >= 3000 { // guvenlik siniri
			break
		}
		dll, err := nativeapi.RegString(registry.CURRENT_USER, `Software\Classes\CLSID\`+id+`\InprocServer32`, "")
		if err != nil || dll == "" {
			continue
		}
		low := strings.ToLower(dll)
		if strings.Contains(low, `\windows\`) || strings.Contains(low, `\program files`) {
			continue // sistem/kurulu yazilim
		}
		switch {
		case strings.Contains(low, `\temp\`) || strings.Contains(low, `\downloads\`) || strings.Contains(low, `\public\`):
			if len(suspicious) < 20 {
				suspicious = append(suspicious, id+"→"+dll)
			}
		case strings.Contains(low, `\users\`) || strings.Contains(low, `\appdata\`) || strings.Contains(low, `\programdata\`):
			otherCount++
		}
	}
	return suspicious, otherCount
}
