// Package schema, results.json icin stabil veri modelini ve surumleme bilgisini tanimlar.
// Plan: "Veri Modeli, results.json Semasi & Test-ID" bolumu.
package schema

const (
	// SchemaVersion: results.json sema surumu. profile alani eklendiginde minor artirildi.
	SchemaVersion = "1.1"
	// CatalogVersion: test katalogu (00-13) surumu. Fleet diff bunun uzerine kurulur.
	// 0.2: 01-031/02-004 surucu-enum (ikincil disk/USB + profil) + 12-013/12-014
	// (registry arac kisitlamasi kozmetik tespiti + HKCU persistence yazma yuzeyi)
	// + 07-013 (DoH/DNS filtreleme baypas yuzeyi).
	// 0.3: 09-010 (WiFi PSK duz-metin, native WlanAPI) + 09-011 (tarayici kimlik
	// deposu) + 05-020 (read-only persistence envanteri) + 10-010 (hassas yerel
	// artefakt okunabilirligi). harici bir DFIR aracı DFIR toplayicisindan turetilmis vektorler.
	// 0.4: Module 14 (kullanici kilitleme/kisitlama) — Denetim Masasi/Ayarlar, Gorev
	// Yoneticisi, CMD, Calistir/DisallowRun, surucu gizleme, kisisellestirme, ekran
	// kilidi, parola+kilitleme politikasi (native NetUserModalsGet), RDP yonlendirme.
	// 0.5: Module 15 (MDM/Intune uygulanan CSP envanteri) + 12-006 event-log temizleme
	// YETENEGI (silmeden) + 12-015 gelismis audit policy (native AuditQuerySystemPolicy)
	// + 13 gercek AD enum (native LDAP/wldap32: Kerberoast/AS-REP/delegation/ADCS-ESC1 +
	// domain trust) + 03-003 ASR obfuscated-script kanaryasi.
	// 0.6: Module 16 (genisletilmis sertlestirme) — Secure Boot, yerel admin/built-in
	// hesap hijyeni (native NetUserEnum+SID), anonim enum/null-session, Windows Recall,
	// pano/bulut panosu, VSS anti-ransomware, yama guncelligi, Windows Hello, Point-and-
	// Print (PrintNightmare), mDNS/NetBIOS, OneDrive senkron, kamera/mik + cihaz kontrolu.
	// 0.7: CHT-05-005 WMI event subscription kalicilik artik GERCEK guvenli yetenek probu
	// (yalniz __EventFilter PutInstance/DeleteInstance — consumer/binding YOK, calistirilabilir
	// zincir olusmaz; el-yazimi COM, manifest + invoke-cleanup geri-alma ile). Stub kaldirildi.
	// 0.8: CHT-10-010 artik PSReadline gecmisinin ICERIGINI tarar (SAM/LSASS dump, comsvcs
	// MiniDump, ExecutionPolicy Bypass, EncodedCommand, mimikatz, vssadmin delete, net user
	// /add) ve eslesme bulursa riski Yuksek'e cikarir. CHT-16-002 artik yerel Administrators
	// grubunun TAM uyeligini (native NetLocalGroupGetMembers level 2) listeler; ic ice AD
	// gruplari + built-in disi standing local admin'ler yuzeye cikar. Karsilastirmali DFIR
	// (harici bir DFIR aracı) analizinden turetilmis kapanislar. Ikisi de pasif/salt-okunur.
	// 0.9: Module 01 LOLBAS vektorleri artik presence-only degil — -EnableNoisy ile her
	// LOLBin'in abuse yolu ZARARSIZ marker kanaryasiyla fiilen calistirilip AppLocker/WDAC/
	// ASR/EDR engelliyor mu olculur (regsvr32 scrobj, mshta HTA, certutil, bitsadmin, wmic
	// process-call, esentutl, rundll32 ShellExec, schtasks; hepsi manifest'e kaydedilip aninda
	// temizlenir). Marker yoksa ama komut calistiysa Partial (yanlis "Blocked" guvencesi yok).
	// UI/enjeksiyon riskli LOLBin'ler (msiexec/cmstp/mavinject/msdt/hh) durustce presence kalir.
	// 0.10: Module 17 (Ek Konfigurasyon Denetimleri) — ilk 16'da kapsanmayan yaygin yanlis
	// yapilandirma/eksik sertlestirme kontrolleri (hepsi pasif): yerel SMB paylasimlari +
	// AutoShareWks (native NetShareEnum), CachedLogonsCount (offline MSCACHE), Kerberos zayif
	// sifreleme (RC4/DES), exploit korumasi (SEHOP/ASLR), hosts override, artik kimlik-dokum
	// artefaktlari (sam.bak/*.dmp), eslenmis ag suruculeri, COM hijack yuzeyi (HKCU CLSID).
	// 0.11: Module 18 (Calisan Cihazi Sikilastirma Derinligi) — "kisitli calisan cihazi"
	// vizyonu: calisan sirkete/veriye/cihaza zarar verebilir mi? Yazilabilir servis ikili
	// dizini (binary-replace privesc), yetkisiz yazilim kurulumu (MSI/sideload/Store), rogue
	// ag (ICS/koprü ile egress baypas), yetkisiz uzak erisim (Uzak Yardim/Remote Registry).
	// 0.12: Module 19 (Veri Sizintisi Derinligi) — kisitli calisan cihazdan sirket verisini
	// disari cikarma kanallari (Modul 06 uzerine): yerlesik/harici exfil araclari (curl/ftp/
	// scp/certutil/bitsadmin/rclone), kisisel bulut istemcileri (Dropbox/Drive/MEGA), sifreli
	// arsivleme (7z/WinRAR — content-DLP baypas), tasinabilir medya (CD/DVD + WPD/MTP telefon),
	// yerel posta verisi (.pst). Hepsi pasif (dosya varligi + registry).
	// 0.13: Module 20 (Kimlik & Kalicilik Yuzeyi Derinligi) — hassas HKLM registry ACL zayifligi
	// (Run/Services/IFEO yazmadan yazilabilirlik testi → privesc/persistence), IFEO debugger
	// hijack + erisilebilirlik arka kapisi (sethc/utilman), DPAPI/Credentials/Vault okunabilirligi,
	// kayitli RDP kimlik/baglantilari. Hepsi pasif (RegOpenKey SET_VALUE + dosya/registry envanteri).
	// 0.14: Module 21 (Yurutme Kacisi & Fiziksel Erisim) — izlemesiz yurutme ortami (kurulu
	// hypervisor VMware/VBox/Hyper-V + WSL distrolari), yorumlayici/runtime yuzeyi (Python/Node/
	// Perl/git-bash — AppLocker EXE-kurali baypas), kurtarma ortami (WinRE) & offline disk
	// tampering (WinRE varligi + C: BitLocker koruma durumu). Pasif (varlik/registry/WMI).
	// 0.15: Module 22 (Ag Saldiri Yuzeyi Derinligi) — LLMNR(12-002)/mDNS(16-010) uzerine:
	// NBT-NS per-adapter poisoning (Responder), IPv6/mitm6 yuzeyi (rogue DHCPv6→NTLM relay),
	// ag-katmani sertlestirme (ICMP redirect / IP source routing / IP forwarding pivot). Pasif registry.
	// 0.16: Module 23 (Guncelleme & Kablosuz/Cevre Birimi Butunlugu) — WSUS-over-HTTP guncelleme
	// MITM (zararli yama/driver enjeksiyonu), kayitli acik/otomatik-baglanan WLAN profilleri
	// (evil-twin/karma; native WlanGetProfile authentication+connectionMode), cihaz-kurulum
	// kontrolu derinligi (DenyUnspecified + sinif deny/allow → BadUSB/HID). Pasif.
	// 0.17: Module 24 (Gorunurluk & Yerel Politika Derinligi) — tehlikeli kullanici-haklari
	// atamasi (native LsaEnumerateAccountsWithUserRight; SeDebug/SeImpersonate/SeBackup vb. genis
	// gruplara mi verilmis → privesc), event log retention/boyut (adli gorunurluk), ETW autologger
	// butunlugu (EventLog-Security/Defender autologger kapatilarak izleme korlestirme). Pasif.
	// 0.18: Module 25 (Kimlik Dogrulama & Oturum Sertlestirme Derinligi) — convenience PIN /
	// picture password ile parola zayiflatma, akilli-kart cikarma + fast-user-switching + son-
	// kullanici oturum-kilit bosluklari, EFS ile veriyi DLP/admin/adli'den gizleme yuzeyi. Pasif.
	// 0.19: Module 26 (Tarayici Saldiri Yuzeyi Derinligi) — alternatif/yonetilmeyen tarayicilar
	// (Firefox/Brave/Tor/Opera/Chrome — URL-filter/DLP baypas, Tor=anonim exfil), Edge SmartScreen/
	// indirme korumasi (11-004 iskeletti), kisisel-hesaba sign-in/sync (Edge+Chrome — veri exfil). Pasif.
	CatalogVersion = "0.19"
	// ToolVersion: chtester ikili surumu. Katalog 0.6 (Module 14/15/16) + denetim
	// raporundaki (DENETIM-RAPORU.md) yuksek/orta bulgularin kapatilmasiyla hizalandi:
	// per-modul+per-vektor panik kurtarma, WMI LockOSThread, scope validFrom/validUntil/
	// test-sinifi zorlamasi + HMAC butunluk, tipli registry revert, task/servis revert
	// dogrulamasi, bozuk manifest koruma.
	ToolVersion = "0.6.1"
)

// Result, her vektorun (Test-ID) urettigi standart sonuc nesnesidir.
type Result struct {
	TestID            string   `json:"testId"`
	Category          string   `json:"category"`
	Name              string   `json:"name"`
	Target            string   `json:"target,omitempty"`
	AttemptedMethods  []string `json:"attemptedMethods"`
	Result            string   `json:"result"` // Allowed|Blocked|Partial|Error|NotApplicable
	BlockingMechanism string   `json:"blockingMechanism"`
	Detected          string   `json:"detected"` // Yes|No|Unknown
	DetectionEvidence []string `json:"detectionEvidence"`
	TelemetryWeight   string   `json:"telemetryWeight"` // None|Low|Med|High
	EvasionApplied    []string `json:"evasionApplied"`
	Evidence          string   `json:"evidence"`
	RiskWhenOpen      string   `json:"riskWhenOpen"` // Critical|High|Medium|Low|Info
	RiskScore         int      `json:"riskScore"`    // 0-100
	Recommendation    string   `json:"recommendation"`
	Mapping           Mapping  `json:"mapping"`
	TierRequired      int      `json:"tierRequired"` // 0-3
	SkipReason        string   `json:"skipReason,omitempty"`
	DeviceID          string   `json:"deviceId"`
	DurationMs        int64    `json:"durationMs"`
	Timestamp         string   `json:"timestamp"` // ISO-8601
}

// Mapping, bulgunun cerceve eslemesi (CIS / MS-Baseline / ASR / MITRE ATT&CK).
type Mapping struct {
	CIS        string `json:"cis,omitempty"`
	MSBaseline string `json:"msBaseline,omitempty"`
	ASRID      string `json:"asrId,omitempty"`
	Attack     string `json:"attack,omitempty"`
}

// Report, results.json'un kok nesnesi: ust-veri + sonuc listesi.
type Report struct {
	SchemaVersion  string   `json:"schemaVersion"`
	CatalogVersion string   `json:"catalogVersion"`
	ToolVersion    string   `json:"toolVersion"`
	Tier           int      `json:"tier"`
	TierReason     string   `json:"tierReason"`
	Profile        string   `json:"profile"` // Audit|Stealth
	BootstrapVector string  `json:"bootstrapVector"`
	OSBuild        string   `json:"osBuild"`
	Arch           string   `json:"arch"`
	DomainJoin     string   `json:"domainJoin"`
	IntuneManaged  bool     `json:"intuneManaged"`
	EDRDetected    []string `json:"edrDetected"`
	DeviceID       string   `json:"deviceId"`
	Hostname       string   `json:"hostname,omitempty"`
	StartedAt      string   `json:"startedAt"`
	FinishedAt     string   `json:"finishedAt"`
	Flags          RunFlags `json:"flags"`
	Results        []Result `json:"results"`
}

// RunFlags, calismayi belirleyen bayraklarin kaydi (rapora gomulur).
type RunFlags struct {
	PassiveOnly     bool `json:"passiveOnly"`
	EnableNoisy     bool `json:"enableNoisy"`
	SkipDestructive bool `json:"skipDestructive"`
	WhatIf          bool `json:"whatIf"`
}

// Result deger sabitleri.
const (
	ResultAllowed       = "Allowed"
	ResultBlocked       = "Blocked"
	ResultPartial       = "Partial"
	ResultError         = "Error"
	ResultNotApplicable = "NotApplicable"

	DetectedYes     = "Yes"
	DetectedNo      = "No"
	DetectedUnknown = "Unknown"

	BlockNone    = "None"
	BlockUnknown = "Unknown"

	TelemetryNone = "None"
	TelemetryLow  = "Low"
	TelemetryMed  = "Med"
	TelemetryHigh = "High"

	RiskCritical = "Critical"
	RiskHigh     = "High"
	RiskMedium   = "Medium"
	RiskLow      = "Low"
	RiskInfo     = "Info"

	ProfileAudit   = "Audit"
	ProfileStealth = "Stealth"

	// SkipReason sabitleri
	SkipTierInsufficient = "TierInsufficient"
	SkipNoiseGateClosed  = "NoiseGateClosed"
	SkipNotApplicableOS  = "NotApplicableOS"
	SkipTimeout          = "Timeout"
	SkipBudgetExhausted  = "BudgetExhausted"
	SkipPassiveOnly      = "PassiveOnly"
	SkipWhatIf           = "WhatIf"
	SkipNotImplemented   = "NotImplemented" // vektor planli ama henuz uygulanmadi (iskelet)
)
