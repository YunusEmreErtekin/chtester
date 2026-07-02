package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat09 = "09-Credential"

// Module09, kimlik bilgisi & kimlik dogrulama yuzeyini test eder.
// Pasif okumalar + (gate'li) yetenek kontrolleri — DUMP ALMADAN, secret OKUMADAN.
type Module09 struct{}

func NewModule09() *Module09 { return &Module09{} }

func (Module09) ID() string   { return "09" }
func (Module09) Name() string { return "Kimlik Bilgisi & Kimlik Doğrulama" }

func (m Module09) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat09)

	// 09.2 LSA koruma duruşu (pasif)
	b.add("CHT-09-002", "LSA koruma duruşu (RunAsPPL/WDigest/CredGuard)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1003.001"
		r.AttemptedMethods = []string{"registry Lsa/WDigest"}
		runAsPPL, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL")
		wdigest, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, "UseLogonCredential")
		cached, _ := nativeapi.RegString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "CachedLogonsCount")
		lsaCfg, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "LsaCfgFlags")
		r.Evidence = fmt.Sprintf("RunAsPPL=%d; WDigest.UseLogonCredential=%d; CachedLogonsCount=%q; CredGuard(LsaCfgFlags)=%d",
			runAsPPL, wdigest, cached, lsaCfg)
		var rec []string
		if runAsPPL == 0 { // 1=açık, 2=açık+UEFI kilitli; yalnız 0 kapalı
			rec = append(rec, "RunAsPPL/LSA Protection kapalı")
		}
		if wdigest == 1 {
			rec = append(rec, "WDigest plaintext cred AÇIK (kritik)")
		}
		if len(rec) > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Düzeltilmeli: " + joinSemi(rec)
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence += " — LSA koruması makul"
		}
	})

	// 09.3 LSASS handle acabiliyor muyum (yetenek — DUMP ALMADAN), gate'li
	b.add("CHT-09-003", "LSASS handle açma yeteneği (dump ALMADAN)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskCritical
		r.Mapping.Attack = "T1003.001"
		r.AttemptedMethods = []string{"FindPID lsass", "OpenProcess(VM_READ) + hemen kapat"}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		pid, ok := nativeapi.FindProcessID("lsass.exe")
		if !ok {
			r.Result = schema.ResultError
			r.Evidence = "lsass.exe PID bulunamadı"
			return
		}
		canOpen, err := nativeapi.CanOpenProcessVMRead(pid)
		if canOpen {
			r.Result = schema.ResultAllowed
			r.Evidence = fmt.Sprintf("LSASS'a VM_READ handle AÇILABILDI (pid=%d, dump alınmadı) — credential-dump yüzeyi açık", pid)
			r.Recommendation = "RunAsPPL + Credential Guard + EDR LSASS koruması etkinleştirilmeli."
		} else {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "Permission"
			r.Detected = schema.DetectedUnknown
			r.Evidence = "LSASS handle açılamadı (iyi): " + truncate(fmt.Sprint(err), 100)
		}
	})

	// 09.4 Credential Manager / vault envanteri (sayim — secret OKUMADAN), gate'li
	b.add("CHT-09-004", "Credential Manager envanteri (secret okumadan)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1555.004"
		r.AttemptedMethods = []string{"CredEnumerateW (yalnız sayım)"}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		count, notFound, err := credCount()
		if err != nil && !notFound {
			r.Result = schema.ResultBlocked
			r.Evidence = "Credential Manager listelenemedi: " + truncate(err.Error(), 100)
			return
		}
		// Kullanici kendi vault'unu listeleyebiliyor (0 olsa bile yetenek var).
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("Credential Manager listelenebildi: %d kayıt erişilebilir (secret okunmadı)", count)
		if count > 0 {
			r.Recommendation = "Kayıtlı credential'lar DPAPI ile korunsa da kullanıcı bağlamında erişilebilir; hassas hesaplar burada tutulmamalı."
		} else {
			r.RiskWhenOpen = schema.RiskMedium
			r.Evidence += " (kayıt yok)"
		}
	})

	// 09.7 SAM/SYSTEM hive okunabilirligi (pasif)
	b.add("CHT-09-007", "SAM/SYSTEM hive okunabilirliği", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1003.002"
		r.AttemptedMethods = []string{"os.Open config\\SAM"}
		sr := systemRoot()
		var readable []string
		for _, h := range []string{"SAM", "SYSTEM", "SECURITY"} {
			p := sr + `\System32\config\` + h
			if f, err := os.Open(p); err == nil {
				f.Close()
				readable = append(readable, h)
			}
		}
		if len(readable) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "SAM/SYSTEM/SECURITY hive'ları kilitli/okunamıyor (iyi)"
			return
		}
		r.Result = schema.ResultAllowed
		r.RiskWhenOpen = schema.RiskCritical
		r.Evidence = "Okunabilir hive: " + joinSemi(readable) + " (shadow/backup ile offline dump yüzeyi)"
		r.Recommendation = "Hive'lar normalde kilitli olmalı; SeBackup/shadow-copy yolları izlenmeli."
	})

	// 09.10 Kayitli WiFi PSK duz-metin dokumu (gate'li — kimlik cikarimi; native WlanAPI)
	b.add("CHT-09-010", "Kayıtlı WiFi PSK düz-metin dökümü", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1552"
		r.AttemptedMethods = []string{"WlanGetProfile (WLAN_PROFILE_GET_PLAINTEXT_KEY)"}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		profs, ok := nativeapi.WiFiProfiles()
		if !ok {
			r.Result = schema.ResultNotApplicable
			r.SkipReason = schema.SkipNotApplicableOS
			r.Evidence = "WLAN servisi/arabirimi yok — uygulanamaz"
			return
		}
		if len(profs) == 0 {
			r.Result = schema.ResultBlocked
			r.Evidence = "Kayıtlı WLAN profili yok"
			return
		}
		clear := 0
		for _, p := range profs {
			if p.HasClearKey {
				clear++
			}
		}
		if clear > 0 {
			r.Result = schema.ResultAllowed
			r.Evidence = fmt.Sprintf("Standart kullanıcı %d/%d WLAN profilinin PSK'sını düz-metin okuyabildi (anahtarlar raporlanmadı)", clear, len(profs))
			r.Recommendation = "Kurumsal ağda PSK yerine 802.1X/EAP-TLS; ortak PSK rotasyonu; cihazda kayıtlı profiller sınırlandırılmalı."
		} else {
			r.Result = schema.ResultBlocked
			r.Evidence = fmt.Sprintf("%d WLAN profili var ama düz-metin PSK kurtarılamadı (802.1X/EAP olabilir)", len(profs))
		}
	})

	// 09.11 Tarayici kayitli kimlik deposu erisimi (pasif — yalniz varlik+okunabilirlik)
	b.add("CHT-09-011", "Tarayıcı kayıtlı kimlik deposu erişimi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1555.003"
		r.AttemptedMethods = []string{"Login Data / logins.json varlık + okuma probe"}
		local := os.Getenv("LOCALAPPDATA")
		roaming := os.Getenv("APPDATA")
		var stores int
		for _, base := range []string{
			filepath.Join(local, `Google\Chrome\User Data`),
			filepath.Join(local, `Microsoft\Edge\User Data`),
		} {
			for _, prof := range chromeProfiles(base) {
				if readableNonEmpty(filepath.Join(prof, "Login Data")) {
					stores++
				}
			}
		}
		ffRoot := filepath.Join(roaming, `Mozilla\Firefox\Profiles`)
		if entries, err := os.ReadDir(ffRoot); err == nil {
			for _, e := range entries {
				if e.IsDir() && readableNonEmpty(filepath.Join(ffRoot, e.Name(), "logins.json")) {
					stores++
				}
			}
		}
		if stores == 0 {
			r.Result = schema.ResultNotApplicable
			r.RiskWhenOpen = schema.RiskMedium
			r.Evidence = "Okunabilir tarayıcı kimlik deposu bulunamadı (kayıtlı şifre yok veya tarayıcı yok)"
			return
		}
		r.Result = schema.ResultAllowed
		r.Evidence = fmt.Sprintf("%d tarayıcı kimlik deposu kullanıcı tarafından okunabilir — DPAPI kullanıcı bağlamında çözülebilir (etkin düz-metin)", stores)
		r.Recommendation = "Tarayıcı parola yöneticisi GPO ile kapatılmalı (PasswordManagerEnabled=0); kurumsal parola kasası; bkz. CHT-11-006."
	})

	return b.results()
}

// credCount, kullanici credential store'undaki kayit sayisini doner (secret OKUMADAN).
// notFound=true => store bos (ERROR_NOT_FOUND); bu bir hata degil, yetenek var demektir.
func credCount() (count int, notFound bool, err error) {
	const errorNotFound = 1168 // ERROR_NOT_FOUND
	advapi := windows.NewLazySystemDLL("advapi32.dll")
	credEnum := advapi.NewProc("CredEnumerateW")
	credFree := advapi.NewProc("CredFree")
	var n uint32
	var creds uintptr
	r, _, callErr := credEnum.Call(0, 0, uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&creds)))
	if r == 0 {
		if se, ok := callErr.(windows.Errno); ok && se == errorNotFound {
			return 0, true, nil
		}
		return 0, false, callErr
	}
	if creds != 0 {
		credFree.Call(creds)
	}
	return int(n), false, nil
}

func joinSemi(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += "; "
		}
		out += v
	}
	return out
}
