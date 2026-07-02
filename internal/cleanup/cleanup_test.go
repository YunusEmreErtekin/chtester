package cleanup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecordReloadUndone(t *testing.T) {
	p := filepath.Join(t.TempDir(), "manifest.json")
	m, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Record(Action{ID: "a1", Type: ActionFileCreate, Target: "x"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Yeniden yukle: 1 pending olmali.
	m2, err := New(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := len(m2.PendingActions()); got != 1 {
		t.Fatalf("1 pending bekleniyordu, %d", got)
	}

	// Geri-alindi isaretle: yeniden yuklemede 0 pending.
	m2.MarkActionUndone("a1")
	m3, _ := New(p)
	if got := len(m3.PendingActions()); got != 0 {
		t.Errorf("undone sonrasi 0 pending bekleniyordu, %d", got)
	}
}

func TestCorruptManifestPreservedNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(p, []byte("{ bu bozuk json "), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := New(p)
	if err == nil {
		t.Error("bozuk manifest hata dondurmeliydi")
	}
	if m == nil {
		t.Fatal("taze manifest donmeliydi (nil degil)")
	}

	// Bozuk dosya .corrupt-* olarak korunmali (ezilmemeli).
	matches, _ := filepath.Glob(p + ".corrupt-*")
	if len(matches) == 0 {
		t.Error("bozuk manifest .corrupt-* olarak korunmaliydi")
	}

	// Taze manifest yazilabilmeli.
	if err := m.Record(Action{ID: "n", Type: ActionFileCreate, Target: "y"}); err != nil {
		t.Fatalf("taze manifest'e yazilamadi: %v", err)
	}
}

func TestStripBOM(t *testing.T) {
	in := append([]byte{0xEF, 0xBB, 0xBF}, []byte("{}")...)
	if string(stripBOM(in)) != "{}" {
		t.Error("BOM kaldirilmali")
	}
	if string(stripBOM([]byte("{}"))) != "{}" {
		t.Error("BOM yoksa degismemeli")
	}
}
