// Package modules, 01-13 test modullerini barindirir. common.go ortak yardimcilar.
package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/cleanup"
	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

// builder, bir modul icinde tek tip sonuc uretimi icin yardimci.
type builder struct {
	ctx *harness.RunContext
	cat string
	out []schema.Result
}

func newBuilder(ctx *harness.RunContext, category string) *builder {
	return &builder{ctx: ctx, cat: category}
}

// add, yeni bir vektor sonucu olusturur, build closure'ini calistirir, finalize edip toplar.
// Vektor closure'i panik-kurtarmalidir: tek bir vektorun panigi ayni moduldeki diger
// vektorleri dusurmez; o vektor Error sonucuyla isaretlenir.
func (b *builder) add(id, name string, fn func(r *schema.Result)) {
	start := time.Now()
	r := b.ctx.NewResult(id, b.cat, name)
	func() {
		defer func() {
			if p := recover(); p != nil {
				r.Result = schema.ResultError
				r.Evidence = "vektor panigi (kurtarildi): " + fmt.Sprint(p)
				b.ctx.Log.Logf("[%s] vektor PANIK kurtarildi: %v", id, p)
			}
		}()
		fn(r)
	}()
	b.ctx.Finalize(r, start)
	b.out = append(b.out, *r)
	b.ctx.Pace()
}

func (b *builder) results() []schema.Result { return b.out }

// markNotImplemented, gate'i gecmis ama henuz GERCEKTEN uygulanmamis (iskelet) bir
// vektoru durustce isaretler. Partial yerine NotApplicable + NotImplemented kullanir:
// boylece rapor "test edildi" izlenimi vermez ve risk skoru sahte sismez.
func markNotImplemented(r *schema.Result, detail string) {
	r.Result = schema.ResultNotApplicable
	r.SkipReason = schema.SkipNotImplemented
	r.Evidence = "Henuz uygulanmadi (planli iskelet): " + detail
}

// systemRoot, %SystemRoot% (ornek C:\Windows).
func systemRoot() string {
	if sr := os.Getenv("SystemRoot"); sr != "" {
		return sr
	}
	return `C:\Windows`
}

// fileExists, dosya var mi.
func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// binPaths, bir System32 ikilisi icin System32 + SysWOW64 yollarini doner (var olanlar).
func binPaths(name string) []string {
	sr := systemRoot()
	var found []string
	for _, dir := range []string{filepath.Join(sr, "System32"), filepath.Join(sr, "SysWOW64")} {
		p := filepath.Join(dir, name)
		if fileExists(p) {
			found = append(found, p)
		}
	}
	return found
}

// runResult, bir komut calistirmanin sonucu.
type runResult struct {
	ExitCode int
	Output   string
	TimedOut bool
	Err      error
}

// runCmd, bir komutu timeout ile calistirir; cikti + cikis kodu doner.
func runCmd(timeout time.Duration, path string, args ...string) runResult {
	cmd := exec.Command(path, args...)
	type res struct {
		out  []byte
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		o, e := cmd.CombinedOutput()
		ch <- res{o, e}
	}()
	select {
	case r := <-ch:
		rr := runResult{Output: strings.TrimSpace(string(r.out)), Err: r.err}
		if r.err != nil {
			if ee, ok := r.err.(*exec.ExitError); ok {
				rr.ExitCode = ee.ExitCode()
			} else {
				rr.ExitCode = -1
			}
		}
		return rr
	case <-time.After(timeout):
		// Process henuz baslamamis olabilir (cok kisa timeout / yuk) — nil-deref panigi onle.
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return runResult{TimedOut: true, ExitCode: -1, Err: errTimeout}
	}
}

var errTimeout = &timeoutError{}

type timeoutError struct{}

func (*timeoutError) Error() string { return "timeout" }

// regKeyExists, HKLM altinda bir anahtar var mi (modüller icin kisayol).
func regKeyExists(path string) bool {
	return nativeapi.RegKeyExists(registry.LOCAL_MACHINE, path)
}

// tryRegWriteProbe, HKLM altinda bir anahtara yazma yetkisini test eder
// (gecici deger yaz + sil). Yazilamiyorsa hata doner.
func tryRegWriteProbe(path string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	const name = "cht-write-probe"
	if err := k.SetDWordValue(name, 1); err != nil {
		return err
	}
	_ = k.DeleteValue(name)
	return nil
}

// canRegWrite, var olan bir registry anahtarina YAZMA yetkisi olup olmadigini ACL
// uzerinden olcer: SET_VALUE ile acmaya calisir, deger YAZMAZ ve hemen kapatir —
// kalinti birakmaz, gurultu uretmez (Stealth dostu). Anahtar yoksa false.
func canRegWrite(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// recordFileCreate, cleanup manifesti icin bir "dosya olusturuldu" eylemi uretir.
func recordFileCreate(path, testID string) cleanup.Action {
	return cleanup.Action{
		ID:     "file:" + path,
		Type:   cleanup.ActionFileCreate,
		Target: path,
		HadOld: false,
		TestID: testID,
	}
}

// tryWriteProbe, bir dizine yazip silmeyi dener; yazilabilir mi doner.
func tryWriteProbe(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	p := filepath.Join(dir, ".cht-probe")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		return false
	}
	_ = os.Remove(p)
	return true
}

// extraWritableRoots, mantiksal suruculeri tarayip yazilabilir KOKLERINI doner
// (ikincil sabit disk D:\ ve cikarilabilir USB). AppLocker default kurallari yalniz
// %WINDIR%/%PROGRAMFILES%'e guvenir; bu surucu kokleri kapsam disi kalir ve oradan
// exec mumkunse gercek bir bypass yuzeyidir (saha bulgusu). Sistem surucusu (C:\)
// zaten ayri yollarla kapsandigindan atlanir; ag (remote)/CD-ROM atlanir.
func extraWritableRoots() []string {
	sysDrive := strings.ToUpper(os.Getenv("SystemDrive")) // or. "C:"
	var out []string
	for _, d := range nativeapi.LogicalDrives() {
		if d.Type != nativeapi.DriveFixed && d.Type != nativeapi.DriveRemovable {
			continue
		}
		if sysDrive != "" && strings.HasPrefix(strings.ToUpper(d.Root), sysDrive) {
			continue
		}
		if tryWriteProbe(d.Root) {
			out = append(out, d.Root)
		}
	}
	return out
}

// dgStatus, Win32_DeviceGuard'tan okunan CALISAN durumu (registry "yapilandirilmis"
// degil, gercek calisan).
type dgStatus struct {
	OK               bool
	VBS              int // 0 off, 1 enabled-not-running, 2 running
	CIEnforce        int // 0 off, 1 audit, 2 enforced
	HVCIRunning      bool
	CredGuardRunning bool
}

// deviceGuard, Win32_DeviceGuard WMI sinifini okur (native COM, x/sys; bkz. nativeapi/wmi.go).
// Standart kullanicida okunabilir — bu sinif admin gerektirmez.
func deviceGuard() dgStatus {
	rows, err := nativeapi.WMIQuery(`root\Microsoft\Windows\DeviceGuard`,
		"SELECT * FROM Win32_DeviceGuard",
		[]string{"VirtualizationBasedSecurityStatus", "CodeIntegrityPolicyEnforcementStatus", "SecurityServicesRunning"})
	if err != nil || len(rows) == 0 {
		return dgStatus{}
	}
	row := rows[0]
	st := dgStatus{OK: true, VBS: atoiSafe(row["VirtualizationBasedSecurityStatus"]), CIEnforce: atoiSafe(row["CodeIntegrityPolicyEnforcementStatus"])}
	for _, s := range strings.Split(row["SecurityServicesRunning"], ",") {
		switch strings.TrimSpace(s) {
		case "1":
			st.CredGuardRunning = true // CredGuard
		case "2":
			st.HVCIRunning = true // HVCI
		}
	}
	return st
}

// atoiSafe, basit non-negatif tamsayi cozumleme (hatasiz; ilk gecersiz karakterde durur).
func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// dirFileCount, bir dizin agacindaki dosya sayisini doner (okuma hatalari yutulur).
func dirFileCount(dir string) int {
	var n int
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// readableNonEmpty, dosya var + bos degil + ilk byte okunabiliyor mu (icerik kopyalanmaz).
func readableNonEmpty(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() || fi.Size() == 0 {
		return false
	}
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// chromeProfiles, bir Chromium "User Data" kokunun altindaki profil dizinlerini doner
// (Default + "Profile N").
func chromeProfiles(base string) []string {
	var out []string
	entries, err := os.ReadDir(base)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if n := e.Name(); n == "Default" || strings.HasPrefix(n, "Profile ") {
			out = append(out, filepath.Join(base, n))
		}
	}
	return out
}

// expand, %ENV% degiskenlerini cozer (Windows tarzi %VAR%).
func expand(p string) string {
	for {
		i := strings.IndexByte(p, '%')
		if i < 0 {
			break
		}
		j := strings.IndexByte(p[i+1:], '%')
		if j < 0 {
			break
		}
		name := p[i+1 : i+1+j]
		p = p[:i] + os.Getenv(name) + p[i+1+j+1:]
	}
	return p
}
