package modules

import (
	"os"
	"path/filepath"
	"testing"

	"chtester/internal/schema"
)

func TestAtoiSafe(t *testing.T) {
	cases := map[string]int{
		"0": 0, "5": 5, "123": 123,
		"12abc": 12, // ilk gecersiz karakterde durur
		"abc":   0,  // bastan gecersiz
		"":      0,
		"007":   7,
	}
	for in, want := range cases {
		if got := atoiSafe(in); got != want {
			t.Errorf("atoiSafe(%q)=%d, istenen %d", in, got, want)
		}
	}
}

func TestExpand(t *testing.T) {
	t.Setenv("CHT_TEST_VAR", "VALUE")
	cases := map[string]string{
		"%CHT_TEST_VAR%":              "VALUE",
		`X\%CHT_TEST_VAR%\Y`:          `X\VALUE\Y`,
		"no-vars-here":                "no-vars-here",
		"%CHT_TEST_VAR%-%CHT_TEST_VAR%": "VALUE-VALUE",
		"%UNCLOSED":                   "%UNCLOSED", // kapanmamis % aynen kalir
	}
	for in, want := range cases {
		if got := expand(in); got != want {
			t.Errorf("expand(%q)=%q, istenen %q", in, got, want)
		}
	}
}

func TestFileExistsAndReadable(t *testing.T) {
	dir := t.TempDir()
	full := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(full, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if !fileExists(full) {
		t.Error("var olan dosya icin fileExists=false")
	}
	if fileExists(filepath.Join(dir, "yok.txt")) {
		t.Error("olmayan dosya icin fileExists=true")
	}
	if fileExists(dir) {
		t.Error("dizin icin fileExists=true olmamali")
	}
	if !readableNonEmpty(full) {
		t.Error("dolu dosya readableNonEmpty=false")
	}
	if readableNonEmpty(empty) {
		t.Error("bos dosya readableNonEmpty=true olmamali")
	}
	if readableNonEmpty(dir) {
		t.Error("dizin readableNonEmpty=true olmamali")
	}
}

func TestDirFileCount(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(dir, "1.txt"),
		filepath.Join(dir, "2.txt"),
		filepath.Join(sub, "3.txt"),
	} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := dirFileCount(dir); got != 3 {
		t.Errorf("dirFileCount=%d, istenen 3", got)
	}
}

func TestChromeProfiles(t *testing.T) {
	base := t.TempDir()
	for _, d := range []string{"Default", "Profile 1", "Profile 2", "Cache", "Local State Dir"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Dosya (dizin degil) sayilmamali.
	if err := os.WriteFile(filepath.Join(base, "Profile X.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := chromeProfiles(base)
	if len(got) != 3 {
		t.Fatalf("3 profil bekleniyordu (Default + Profile 1/2), bulundu %d: %v", len(got), got)
	}
}

func TestTryWriteProbe(t *testing.T) {
	dir := t.TempDir()
	if !tryWriteProbe(filepath.Join(dir, "yeni-altdizin")) {
		t.Error("yazilabilir dizinde tryWriteProbe=false")
	}
	// Sonda kalinti birakmamali (.cht-probe silinir).
	if entries, _ := os.ReadDir(filepath.Join(dir, "yeni-altdizin")); len(entries) != 0 {
		t.Errorf("tryWriteProbe kalinti birakti: %v", entries)
	}
}

func TestMarkNotImplemented(t *testing.T) {
	r := &schema.Result{Result: schema.ResultAllowed}
	markNotImplemented(r, "X")
	if r.Result != schema.ResultNotApplicable {
		t.Errorf("Result=%s, NotApplicable bekleniyordu", r.Result)
	}
	if r.SkipReason != schema.SkipNotImplemented {
		t.Errorf("SkipReason=%s, NotImplemented bekleniyordu", r.SkipReason)
	}
}

func TestSystemRootFallback(t *testing.T) {
	// SystemRoot tanimsizken bile bos donmemeli.
	if systemRoot() == "" {
		t.Error("systemRoot bos dondu")
	}
}
