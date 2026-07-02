package sink

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tryWritable, dizini olusturup gercek bir yazma probu yapar ve kalinti birakmaz.
func TestTryWritable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "yeni", "alt")
	if err := tryWritable(dir); err != nil {
		t.Fatalf("yazilabilir dizinde tryWritable hata verdi: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("dizin okunamadi: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("write-probe kalinti birakti: %v", entries)
	}
}

// Select, ilk yazilabilir adayi (USB/ExeDir) secmeli ve denemeyi bulgu olarak kaydetmeli.
func TestSelectChoosesFirstWritable(t *testing.T) {
	exeDir := t.TempDir()
	s, err := Select(exeDir)
	if err != nil {
		t.Fatalf("yazilabilir exeDir varken Select hata verdi: %v", err)
	}
	if s.Chosen != "USB/ExeDir" {
		t.Errorf("Chosen=%q, USB/ExeDir bekleniyordu", s.Chosen)
	}
	want := filepath.Join(exeDir, "Results")
	if s.Dir != want {
		t.Errorf("Dir=%q, %q bekleniyordu", s.Dir, want)
	}
	if len(s.Attempts) == 0 || !strings.Contains(s.Attempts[0], "OK") {
		t.Errorf("ilk deneme OK olarak kaydedilmedi: %v", s.Attempts)
	}
}

// Select, ilk aday yazilamazsa bir sonrakine dusmeli ve "yazilamadi"yi bulgu olarak
// kaydetmeli ("USB'ye yazilamadi da bir bulgudur" ilkesi).
func TestSelectFallbackRecordsFailure(t *testing.T) {
	// exeDir'i var olan bir DOSYA yap: altinda "Results" dizini olusturulamaz -> ilk aday FAIL.
	tmp := t.TempDir()
	fileAsDir := filepath.Join(tmp, "exe-bir-dosya")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Select(fileAsDir)
	if err != nil {
		t.Fatalf("fallback ile yazilabilir sink bulunmaliydi: %v", err)
	}
	if s.Chosen == "USB/ExeDir" {
		t.Error("dosya-altindaki ExeDir secilmemeliydi, fallback bekleniyordu")
	}
	if len(s.Attempts) < 2 || !strings.Contains(s.Attempts[0], "FAIL") {
		t.Errorf("ilk aday FAIL olarak kaydedilmedi: %v", s.Attempts)
	}
}
