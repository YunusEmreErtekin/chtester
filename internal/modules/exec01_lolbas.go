package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"chtester/internal/cleanup"
	"chtester/internal/harness"
	"chtester/internal/schema"
)

// exec01_lolbas.go: LOLBAS vektorlerine GERCEK (guvenli kanarya) engelleme testi ekler.
// Presence-only "Partial" yerine, -EnableNoisy ile her LOLBin'in abuse yolunu ZARARSIZ bir
// payload'la fiilen calistirir ve AppLocker/WDAC/ASR/EDR engelliyor mu olcer:
//   - Payload yalnizca Temp'e bir marker dosyasi yazar (CHT_LOL_OK). Ag/zarar YOK.
//   - Butun gecici dosya + task'lar manifest'e kaydedilir ve aninda silinir.
//   - Marker yazildi   -> Allowed (abuse engellenmedi).
//   - Net politika engeli (process baslamadi/erisim reddi) -> Blocked.
//   - Calisti ama marker dogrulanamadi -> Partial (YANLIS "Blocked" guvencesi vermemek icin).
// UI/enjeksiyon riski tasiyan LOLBin'ler (msiexec dialog, cmstp INF, mavinject injection,
// msdt, hh help) guvenli sekilde fiilen calistirilamaz; bunlar presence + durust not kalir.

const lolMarker = "CHT_LOL_OK"

// runLolbasCanary, l.bin'e gore guvenli abuse kanaryasini secer. Cagiran (loop) yalnizca
// ctx.NoisyAllowed() dogruyken cagirir; boylece Tier-agnostik (Tier 1'de de) calisir.
func runLolbasCanary(ctx *harness.RunContext, r *schema.Result, l lolbin, exePath string) {
	base := strings.ToLower(filepath.Base(l.bin))
	// SRP zorunluysa, script/cocuk-surec doguran kanaryalar MODAL "Restrictions" dialogu
	// tetikler ve run'i kesintiye ugratir. Bu durumda kanaryayi CALISTIRMADAN Blocked(SRP)
	// raporlariz — hem dialog spam'ini onler hem de dogru verdict'i verir (kontrol calisiyor).
	spawnsChild := map[string]bool{
		"regsvr32.exe": true, "mshta.exe": true, "rundll32.exe": true,
		"wmic.exe": true, "schtasks.exe": true,
	}
	if spawnsChild[base] && srpBlocksExec() {
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = "SRP"
		r.Evidence = "SRP (Software Restriction Policies) zorunlu — bu LOLBin'in script/proxy-exec abuse'u politikayla engelli (pasif tespit; modal 'Restrictions' dialogu tetiklememek için fiili kanarya çalıştırılmadı)"
		r.Recommendation = "SRP mevcut kontrolü sağlıyor; merkezi yönetim + loglama için AppLocker/WDAC'e geçiş önerilir."
		return
	}
	switch base {
	case "regsvr32.exe":
		lolRegsvr32(ctx, r, exePath)
	case "mshta.exe":
		lolMshta(ctx, r, exePath)
	case "certutil.exe":
		lolCertutil(ctx, r, exePath)
	case "bitsadmin.exe":
		lolBitsadmin(ctx, r, exePath)
	case "wmic.exe":
		lolWmic(ctx, r, exePath)
	case "esentutl.exe":
		lolEsentutl(ctx, r, exePath)
	case "rundll32.exe":
		lolRundll32(ctx, r, exePath)
	case "schtasks.exe":
		lolSchtasks(ctx, r, exePath)
	case "msiexec.exe", "cmstp.exe", "mavinject.exe", "msdt.exe", "hh.exe":
		// UI dialog / INF / DLL enjeksiyonu / Follina riski — guvenli fiili abuse tanimlanamaz.
		r.Evidence += " — aktif abuse testi güvenli değil (UI/enjeksiyon riski); yalnızca varlık raporlandı"
	default:
		// msbuild/installutil vb. genelde System32'de degil (NotApplicable'a dusmus olur).
		r.Evidence += " — bu LOLBin için güvenli aktif kanarya tanımlı değil (varlık raporlandı)"
	}
}

// --- ortak yardimcilar ---

func lolTmp(name string) string { return filepath.Join(os.TempDir(), name) }

func jsEscape(p string) string { return strings.ReplaceAll(p, `\`, `\\`) } // JScript string literali icin

// lolWrite, gecici payload'i manifest'e kaydeder ve yazar.
func lolWrite(ctx *harness.RunContext, testID, path, content string) error {
	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(recordFileCreate(path, testID))
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

// lolRecordMarker, henuz yazilmamis marker dosyasini temizlik icin kaydeder.
func lolRecordMarker(ctx *harness.RunContext, testID, path string) {
	_ = os.Remove(path)
	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(recordFileCreate(path, testID))
	}
}

// waitMarker, async payload'lar (rundll32/schtasks) icin marker'i kisa sure bekler.
func waitMarker(path string, attempts int) bool {
	for i := 0; i < attempts; i++ {
		if markerHit(path) {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return markerHit(path)
}

func markerHit(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(data), lolMarker)
}

// lolClassify, marker/engel sinyaline gore sonucu belirler. Marker yoksa AMA komut calistiysa
// Partial doner (yanlis "Blocked" guvencesi vermez); yalnizca net engelde Blocked.
func lolClassify(r *schema.Result, res runResult, markPath, tech string) {
	switch {
	case markerHit(markPath):
		r.Result = schema.ResultAllowed
		r.BlockingMechanism = schema.BlockNone
		r.Evidence = tech + " ZARARSIZ kanaryası çalıştı (marker yazıldı) — proxy-exec engellenmedi"
		r.Recommendation = "AppLocker/WDAC + ASR (obfuscated script/child-process) + EDR ile bu LOLBin abuse'u engellenmeli."
	case res.TimedOut:
		r.Result = schema.ResultError
		r.SkipReason = schema.SkipTimeout
		r.Evidence = tech + ": timeout"
	case isLaunchBlocked(res):
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = schema.BlockUnknown
		r.Evidence = fmt.Sprintf("%s ENGELLENDİ (process başlamadı/erişim reddi, exit=%d): %s",
			tech, res.ExitCode, truncate(errStr(res), 140))
	default:
		// Calisti ama marker dogrulanamadi: kesin degil.
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("%s çalıştı fakat marker doğrulanamadı (exit=%d) — engel kesin değil; ortam/recipe farkı olabilir",
			tech, res.ExitCode)
	}
}

// isLaunchBlocked, komutun POLITIKA nedeniyle baslamadigini/engellendigini sezgisel belirler.
func isLaunchBlocked(res runResult) bool {
	if res.Err != nil && strings.TrimSpace(res.Output) == "" {
		return true
	}
	low := strings.ToLower(res.Output)
	for _, k := range []string{"applocker", "was prevented", "blocked by", "group policy", "access is denied", "erişim engellendi", "policy"} {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

func errStr(res runResult) string {
	if res.Err != nil {
		return res.Err.Error()
	}
	return res.Output
}

// srpBlocksExec, SRP'nin (Software Restriction Policies) YAPILANDIRILMIS olup olmadigini
// PASIF okur. Anahtar varsa engelleyici KABUL EDILIR — DefaultLevel'a bakilmaz: cunku
// DefaultLevel=Unrestricted (0x40000) olsa bile kullanici-yazilabilir yollara (Temp) DENY
// path-kurali eklenmis olabilir (yaygin kurumsal config) ve bu, script/cocuk-surec
// kanaryalarinda modal "Restrictions" dialogu uretir. Dialog riskini tamamen ortadan
// kaldirmak icin SRP yapilandirilmissa exec-kanaryalari hic calistirmayiz.
func srpBlocksExec() bool {
	return regKeyExists(`SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers`)
}

// --- LOLBin bazli guvenli kanaryalar (payload sadece marker yazar) ---

func lolRegsvr32(ctx *harness.RunContext, r *schema.Result, exe string) {
	mark := lolTmp("cht-lol-regsvr.txt")
	sct := lolTmp("cht-lol.sct")
	lolRecordMarker(ctx, r.TestID, mark)
	content := `<?XML version="1.0"?>
<scriptlet><registration progid="CHT" classid="{F0001111-0000-0000-0000-0000FEEDACDC}">
<script language="JScript"><![CDATA[
try{var f=new ActiveXObject("Scripting.FileSystemObject");var t=f.CreateTextFile("` + jsEscape(mark) + `",true);t.WriteLine("` + lolMarker + `");t.Close();}catch(e){}
]]></script></registration></scriptlet>`
	if err := lolWrite(ctx, r.TestID, sct, content); err != nil {
		r.Result = schema.ResultError
		r.Evidence = "sct yazılamadı: " + err.Error()
		return
	}
	defer os.Remove(sct)
	defer os.Remove(mark)
	res := runCmd(10*time.Second, exe, "/s", "/u", "/n", "/i:"+sct, "scrobj.dll")
	lolClassify(r, res, mark, "regsvr32 scrobj (Squiblydoo)")
}

func lolMshta(ctx *harness.RunContext, r *schema.Result, exe string) {
	mark := lolTmp("cht-lol-mshta.txt")
	hta := lolTmp("cht-lol.hta")
	lolRecordMarker(ctx, r.TestID, mark)
	content := `<html><head><HTA:APPLICATION SHOWINTASKBAR="no" WINDOWSTATE="minimize"/>
<script language="JScript">
try{var f=new ActiveXObject("Scripting.FileSystemObject");var t=f.CreateTextFile("` + jsEscape(mark) + `",true);t.WriteLine("` + lolMarker + `");t.Close();}catch(e){}
window.close();
</script></head><body></body></html>`
	if err := lolWrite(ctx, r.TestID, hta, content); err != nil {
		r.Result = schema.ResultError
		r.Evidence = "hta yazılamadı: " + err.Error()
		return
	}
	defer os.Remove(hta)
	defer os.Remove(mark)
	res := runCmd(10*time.Second, exe, hta)
	waitMarker(mark, 12)
	lolClassify(r, res, mark, "mshta HTA")
}

func lolCertutil(ctx *harness.RunContext, r *schema.Result, exe string) {
	src := lolTmp("cht-lol-src.txt")
	enc := lolTmp("cht-lol.b64")
	dec := lolTmp("cht-lol-dec.txt")
	if err := lolWrite(ctx, r.TestID, src, lolMarker+"\r\n"); err != nil {
		r.Result = schema.ResultError
		r.Evidence = "kaynak yazılamadı: " + err.Error()
		return
	}
	lolRecordMarker(ctx, r.TestID, enc)
	lolRecordMarker(ctx, r.TestID, dec)
	defer os.Remove(src)
	defer os.Remove(enc)
	defer os.Remove(dec)
	_ = runCmd(8*time.Second, exe, "-encode", src, enc)
	res := runCmd(8*time.Second, exe, "-decode", enc, dec)
	lolClassify(r, res, dec, "certutil -encode/-decode (yerel)")
}

func lolBitsadmin(ctx *harness.RunContext, r *schema.Result, exe string) {
	src := lolTmp("cht-lol-bsrc.txt")
	dst := lolTmp("cht-lol-bdst.txt")
	if err := lolWrite(ctx, r.TestID, src, lolMarker+"\r\n"); err != nil {
		r.Result = schema.ResultError
		r.Evidence = "kaynak yazılamadı: " + err.Error()
		return
	}
	lolRecordMarker(ctx, r.TestID, dst)
	defer os.Remove(src)
	defer os.Remove(dst)
	res := runCmd(20*time.Second, exe, "/transfer", "chtjob", "/download", "/priority", "normal",
		"file:///"+filepath.ToSlash(src), dst)
	lolClassify(r, res, dst, "bitsadmin yerel transfer")
}

func lolWmic(ctx *harness.RunContext, r *schema.Result, exe string) {
	mark := lolTmp("cht-lol-wmic.txt")
	lolRecordMarker(ctx, r.TestID, mark)
	defer os.Remove(mark)
	res := runCmd(12*time.Second, exe, "process", "call", "create",
		`cmd.exe /c echo `+lolMarker+`> "`+mark+`"`)
	waitMarker(mark, 12)
	lolClassify(r, res, mark, "wmic process call create")
}

func lolEsentutl(ctx *harness.RunContext, r *schema.Result, exe string) {
	src := lolTmp("cht-lol-esrc.txt")
	dst := lolTmp("cht-lol-edst.txt")
	if err := lolWrite(ctx, r.TestID, src, lolMarker+"\r\n"); err != nil {
		r.Result = schema.ResultError
		r.Evidence = "kaynak yazılamadı: " + err.Error()
		return
	}
	lolRecordMarker(ctx, r.TestID, dst)
	defer os.Remove(src)
	defer os.Remove(dst)
	res := runCmd(10*time.Second, exe, "/y", src, "/d", dst, "/o")
	lolClassify(r, res, dst, "esentutl /y kopyalama")
}

func lolRundll32(ctx *harness.RunContext, r *schema.Result, exe string) {
	mark := lolTmp("cht-lol-rundll.txt")
	lolRecordMarker(ctx, r.TestID, mark)
	defer os.Remove(mark)
	res := runCmd(10*time.Second, exe, "shell32.dll,ShellExec_RunDLL",
		"cmd.exe", "/c echo "+lolMarker+`> "`+mark+`"`)
	waitMarker(mark, 12)
	lolClassify(r, res, mark, "rundll32 ShellExec_RunDLL")
}

func lolSchtasks(ctx *harness.RunContext, r *schema.Result, exe string) {
	mark := lolTmp("cht-lol-schtasks.txt")
	const tn = "CHT_LOL_CANARY"
	lolRecordMarker(ctx, r.TestID, mark)
	// Task olusturmayi manifest'e kaydet (yarida kesilirse invoke-cleanup siler).
	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(cleanup.Action{
			ID: "task:" + tn, Type: cleanup.ActionTaskCreate, Target: tn, TestID: r.TestID,
		})
	}
	defer os.Remove(mark)
	defer runCmd(10*time.Second, exe, "/delete", "/f", "/tn", tn) // aninda geri al
	create := runCmd(12*time.Second, exe, "/create", "/f", "/tn", tn,
		"/tr", `cmd /c echo `+lolMarker+`> "`+mark+`"`, "/sc", "once", "/st", "23:59")
	if isLaunchBlocked(create) {
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = schema.BlockUnknown
		r.Evidence = "schtasks /create ENGELLENDİ: " + truncate(errStr(create), 140)
		return
	}
	_ = runCmd(12*time.Second, exe, "/run", "/tn", tn)
	waitMarker(mark, 20)
	lolClassify(r, create, mark, "schtasks proxy-exec (oluştur+çalıştır)")
}
