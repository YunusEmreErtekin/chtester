// Package app, uctan uca calismayi (bootstrap -> kesif -> Tier -> modüller -> rapor
// -> cleanup) orkestre eder. Hem CLI hem GUI bunu cagirir.
package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"chtester/internal/cleanup"
	appctx "chtester/internal/context"
	"chtester/internal/harness"
	"chtester/internal/modules"
	"chtester/internal/report"
	"chtester/internal/schema"
	"chtester/internal/scopesig"
	"chtester/internal/sink"
)

// Options, bir calismayi belirleyen girdiler.
type Options struct {
	Profile         string // Audit|Stealth
	PassiveOnly     bool
	EnableNoisy     bool
	SkipDestructive bool
	WhatIf          bool
	ScopePath       string
	OutDir          string // bos ise sink secimi yapilir
	BudgetSec       int    // toplam calisma butcesi (sn); 0 = sinirsiz
	Seed            int64  // zamanlama jitter'i icin (0 ise saatten turetilir)
}

// Result, calismanin ciktisi.
type RunOutput struct {
	Report   *schema.Report
	JSONPath string
	TXTPath  string
	HTMLPath string
	SinkDir  string
}

// FuncLogger, bir closure'i Logger arayuzune cevirir.
type FuncLogger func(format string, args ...any)

func (f FuncLogger) Logf(format string, args ...any) { f(format, args...) }

// Execute, tum akisi calistirir. log nil olabilir.
func Execute(opts Options, log harness.Logger) (*RunOutput, error) {
	if log == nil {
		log = FuncLogger(func(string, ...any) {})
	}
	started := time.Now()

	// --- Bootstrap: bu ikili birincil vektor olarak calisti ---
	bootstrapVector := "chtester.exe (primary)"
	log.Logf("Bootstrap: %s", bootstrapVector)

	// --- 00 kesif ---
	log.Logf("Ortam kesfi calisiyor...")
	env := appctx.Discover()
	log.Logf("DeviceId=%s Tier=%d (%s)", env.DeviceID, env.Tier, env.TierReason)

	// --- Profil dogrulama ---
	profile := opts.Profile
	if profile == "" {
		profile = schema.ProfileAudit
	}
	if profile == schema.ProfileStealth {
		if ok, why := stealthAuthorized(opts.ScopePath); !ok {
			return nil, fmt.Errorf("DoubleBlindNotAuthorized: -Profile Stealth icin scope.json'da doubleBlindAuthorized:true gerekli (%s)", why)
		}
		if opts.PassiveOnly {
			log.Logf("UYARI: -Profile Stealth -PassiveOnly birlikte verildi; pasif okuma SOC aktivitesi uretmez (Stealth etkisiz).")
		}
	}

	// --- Sink secimi (DLP'den bagimsiz) ---
	outDir := opts.OutDir
	if outDir == "" {
		exeDir := "."
		if exe, err := os.Executable(); err == nil {
			exeDir = filepath.Dir(exe)
		}
		s, err := sink.Select(exeDir)
		for _, a := range s.Attempts {
			log.Logf("sink: %s", a)
		}
		if err != nil {
			return nil, fmt.Errorf("yazilabilir sink yok: %w", err)
		}
		outDir = s.Dir
	} else {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return nil, fmt.Errorf("cikti dizini olusturulamadi: %w", err)
		}
	}
	log.Logf("Cikti dizini: %s", outDir)

	// --- Cihaz + tarih damgali alt-klasor: Results/<hostname>_<YYYYMMDD_HHMMSS>/ ---
	// Boylece her cihazin/calismanin ciktisi ayri, karismayan bir klasorde toplanir.
	runName := sanitizeName(env.Hostname)
	if runName == "" {
		runName = env.DeviceID
	}
	runName += "_" + started.Format("20060102_150405")
	if rd := filepath.Join(outDir, runName); os.MkdirAll(rd, 0o755) == nil {
		outDir = rd
		log.Logf("Çalışma klasörü: %s", outDir)
	}

	// --- Cleanup manifest (Stealth'te de tam ve diske yazili) ---
	manifest, err := cleanup.New(filepath.Join(outDir, "manifest.json"))
	if err != nil {
		log.Logf("UYARI: manifest olusturulamadi: %v", err)
	}

	// --- Harness baglami ---
	seed := opts.Seed
	if seed == 0 {
		seed = started.UnixNano()
	}
	budget := time.Duration(opts.BudgetSec) * time.Second
	flags := schema.RunFlags{
		PassiveOnly:     opts.PassiveOnly,
		EnableNoisy:     opts.EnableNoisy,
		SkipDestructive: opts.SkipDestructive,
		WhatIf:          opts.WhatIf,
	}
	// Gurultulu [N] testler gecerli scope artefakti ister (plan: "artefakt yoksa calismamali").
	// Yalniz ticket degil; gecerlilik penceresi (validFrom/validUntil) + test sinifi da zorlanir.
	if flags.EnableNoisy {
		if ok, why := validateScope(opts.ScopePath, started, "noisy"); !ok {
			log.Logf("UYARI: -EnableNoisy verildi ama yetki artefakti gecersiz — gurultulu [N] testler calismayacak (NoiseGateClosed: %s).", why)
			flags.EnableNoisy = false
		} else {
			log.Logf("Yetki artefakti dogrulandi (%s).", why)
		}
	}
	ctx := harness.NewRunContext(profile, env.Tier, env.DeviceID, flags, manifest, log, seed, budget)

	// --- Modüller: 00 (baglam) + Faz 2 cekirdek (01,02,03,04,06) ---
	exeDir := "."
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
	}
	runner := harness.NewRunner(ctx,
		appctx.NewModule00(env, opts.ScopePath),
		modules.NewModule01(),
		modules.NewModule02(),
		modules.NewModule03(),
		modules.NewModule04(),
		modules.NewModule06(exeDir),
		// Faz 3: kalan pasif sertlestirme
		modules.NewModule07(),
		modules.NewModule08(),
		modules.NewModule10(),
		modules.NewModule11(),
		modules.NewModule12(),
		// Faz 6: kullanici kilitleme / kisitlama durusu (pasif)
		modules.NewModule14(),
		// Faz 7: MDM/Intune uygulanan CSP politika envanteri (pasif)
		modules.NewModule15(),
		// Faz 8: genisletilmis sertlestirme (firmware/hesap/anti-ransomware, pasif)
		modules.NewModule16(),
		// Faz 9: ek konfigurasyon denetimleri (SMB share/cached-cred/kerberos/hosts/dump, pasif)
		modules.NewModule17(),
		// Faz 10: calisan cihazi sikilastirma derinligi (privesc/kurulum/rogue-ag/uzak-erisim, pasif)
		modules.NewModule18(),
		// Faz 11: veri sizintisi derinligi (exfil araclari/bulut/arsiv/tasinabilir-medya/posta, pasif)
		modules.NewModule19(),
		// Faz 12: kimlik & kalicilik yuzeyi (registry ACL/IFEO/DPAPI/RDP, pasif)
		modules.NewModule20(),
		// Faz 13: yurutme kacisi & fiziksel/kurtarma erisimi (VM/WSL/yorumlayici/WinRE, pasif)
		modules.NewModule21(),
		// Faz 14: ag saldiri yuzeyi (NBT-NS/IPv6-mitm6/ICMP-redirect/forwarding, pasif)
		modules.NewModule22(),
		// Faz 15: guncelleme butunlugu + kablosuz/cevre birimi (WSUS-HTTP/evil-twin/BadUSB, pasif)
		modules.NewModule23(),
		// Faz 16: gorunurluk & yerel politika (privilege assignment/log retention/ETW autologger, pasif)
		modules.NewModule24(),
		// Faz 17: kimlik dogrulama & oturum sertlestirme (convenience-PIN/smartcard/EFS, pasif)
		modules.NewModule25(),
		// Faz 18: tarayici saldiri yuzeyi (alternatif-tarayici/SmartScreen/kisisel-sync, pasif)
		modules.NewModule26(),
		// Faz 4: gurultulu/yikici (gate'li: -EnableNoisy + scope)
		modules.NewModule05(),
		modules.NewModule09(),
		modules.NewModule13(env),
	)
	results := runner.Run()

	// --- Rapor nesnesi ---
	rep := &schema.Report{
		SchemaVersion:   schema.SchemaVersion,
		CatalogVersion:  schema.CatalogVersion,
		ToolVersion:     schema.ToolVersion,
		Tier:            env.Tier,
		TierReason:      env.TierReason,
		Profile:         profile,
		BootstrapVector: bootstrapVector,
		OSBuild:         fmt.Sprintf("%d.%d.%d", env.OSMajor, env.OSMinor, env.OSBuild),
		Arch:            env.Arch,
		DomainJoin:      env.DomainJoin,
		IntuneManaged:   env.IntuneManaged,
		EDRDetected:     env.EDRDetected,
		DeviceID:        env.DeviceID,
		Hostname:        env.Hostname,
		StartedAt:       started.UTC().Format(time.RFC3339),
		FinishedAt:      time.Now().UTC().Format(time.RFC3339),
		Flags:           flags,
		Results:         results,
	}

	// --- Cleanup guvenlik agi: geri-alinmamis ne kaldiysa geri al, sonra isaretle ---
	if manifest != nil {
		if pending := manifest.PendingActions(); len(pending) > 0 {
			log.Logf("UYARI: %d geri-alinmamis degisiklik kaldi, guvenlik agi calisiyor...", len(pending))
			for _, ur := range manifest.UndoAll() {
				log.Logf("cleanup: [%v] %s -> %s", ur.OK, ur.Action.Target, ur.Message)
			}
		}
		_ = manifest.MarkCleaned()
	}

	// --- Yaz ---
	jsonPath, txtPath, htmlPath, werr := report.WriteAll(outDir, rep)
	if werr != nil {
		return nil, fmt.Errorf("rapor yazilamadi: %w", werr)
	}
	log.Logf("Rapor yazildi: %s", outDir)

	return &RunOutput{Report: rep, JSONPath: jsonPath, TXTPath: txtPath, HTMLPath: htmlPath, SinkDir: outDir}, nil
}

// scopeSearchPaths, scope.json'un aranacagi yollari sirayla doner.
// sanitizeName, hostname'i klasor-guvenli hale getirir (Windows gecersiz karakterleri + bosluk -> _).
func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	return strings.Map(func(r rune) rune {
		switch r {
		case '\\', '/', ':', '*', '?', '"', '<', '>', '|', ' ':
			return '_'
		}
		return r
	}, s)
}

func scopeSearchPaths(scopePath string) []string {
	paths := []string{}
	if scopePath != "" {
		paths = append(paths, scopePath)
	}
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "scope.json"))
	}
	return append(paths, "scope.json")
}

// stripBOM, UTF-8 BOM'u (varsa) kaldirir; bazi editorler/PowerShell BOM ekler.
func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// validateScope, yetki artefaktini TAM dogrular (yalniz ticket varligi DEGIL):
//   - ticket dolu mu,
//   - simdi gecerlilik penceresinde mi (validFrom <= now <= validUntil),
//   - istenen test sinifi (ornek "noisy") allowedTestClasses icinde mi.
// Boylece suresi dolmus ya da kapsam-disi bir yetkiyle gurultulu test calismaz.
func validateScope(scopePath string, now time.Time, requireClass string) (ok bool, reason string) {
	for _, p := range scopeSearchPaths(scopePath) {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var sc struct {
			Ticket                string   `json:"ticket"`
			ValidFrom             string   `json:"validFrom"`
			ValidUntil            string   `json:"validUntil"`
			AllowedTestClasses    []string `json:"allowedTestClasses"`
			DoubleBlindAuthorized bool     `json:"doubleBlindAuthorized"`
			Signature             string   `json:"signature"`
		}
		if json.Unmarshal(stripBOM(data), &sc) != nil {
			return false, "scope.json cozumlenemedi: " + p
		}
		if sc.Ticket == "" {
			return false, "scope.json ticket alani bos: " + p
		}
		// Butunluk: HMAC anahtari (CHTESTER_SCOPE_HMAC_KEY) tanimliysa imza ZORUNLU ve
		// dogrulanmali; anahtar yoksa imzasiz scope geriye-uyum icin kabul edilir (ama
		// imza varsa anahtarsiz dogrulanamayacagi icin reddedilir). Boylece saha
		// operatoru scope'u (kapsam/gecerlilik) gizlice degistiremez.
		integ := scopesig.Check(scopesig.Doc{
			Ticket:                sc.Ticket,
			ValidFrom:             sc.ValidFrom,
			ValidUntil:            sc.ValidUntil,
			AllowedTestClasses:    sc.AllowedTestClasses,
			DoubleBlindAuthorized: sc.DoubleBlindAuthorized,
		}, scopesig.KeyFromEnv(), sc.Signature)
		if !integ.OK {
			return false, "scope butunluk: " + integ.Reason + " (" + p + ")"
		}
		if sc.ValidFrom != "" {
			if t, e := time.Parse(time.RFC3339, sc.ValidFrom); e == nil && now.Before(t) {
				return false, "yetki henuz baslamadi (validFrom=" + sc.ValidFrom + ")"
			}
		}
		if sc.ValidUntil != "" {
			if t, e := time.Parse(time.RFC3339, sc.ValidUntil); e == nil && now.After(t) {
				return false, "yetki suresi DOLMUS (validUntil=" + sc.ValidUntil + ")"
			}
		}
		if requireClass != "" && len(sc.AllowedTestClasses) > 0 {
			allowed := false
			for _, c := range sc.AllowedTestClasses {
				if c == requireClass {
					allowed = true
					break
				}
			}
			if !allowed {
				return false, "test sinifi '" + requireClass + "' allowedTestClasses'da yok"
			}
		}
		return true, "ticket=" + sc.Ticket + "; " + integ.Reason + " (" + p + ")"
	}
	return false, "scope.json bulunamadi"
}

// stealthAuthorized, scope.json icinde doubleBlindAuthorized:true var mi diye bakar.
func stealthAuthorized(scopePath string) (bool, string) {
	for _, p := range scopeSearchPaths(scopePath) {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var sc struct {
			DoubleBlindAuthorized bool `json:"doubleBlindAuthorized"`
		}
		if json.Unmarshal(stripBOM(data), &sc) == nil {
			if sc.DoubleBlindAuthorized {
				return true, p
			}
			return false, "scope.json bulundu ama doubleBlindAuthorized=false"
		}
	}
	return false, "scope.json bulunamadi"
}
