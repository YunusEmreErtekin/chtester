// Package sink, yazilabilir cikti hedefini secer (USB -> Temp -> Desktop -> ProgramData).
// Plan: "Guvenli yazilabilir sink + fallback". Sink secimi DLP testinden (modul 06)
// BAGIMSIZ yapilir — dongusel bagimlilik yok. "USB'ye yazilamadi" da bir bulgudur.
package sink

import (
	"fmt"
	"os"
	"path/filepath"
)

// Sink, secilen cikti dizini ve nasil secildigi.
type Sink struct {
	Dir       string   // Results dizini (mutlak yol)
	Chosen    string   // secilen aday tipi (USB/Temp/Desktop/ProgramData)
	Attempts  []string // denenen adaylar + sonuc (bulgu olarak rapora gider)
}

// candidate, sink aday dizini.
type candidate struct {
	label string
	dir   string
}

// Select, ilk yazilabilir adayi secer. exeDir, ikilinin bulundugu dizin (USB koku adayi).
func Select(exeDir string) (*Sink, error) {
	home, _ := os.UserHomeDir()
	temp := os.TempDir()
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}

	candidates := []candidate{
		{"USB/ExeDir", filepath.Join(exeDir, "Results")},
		{"Temp", filepath.Join(temp, "chtester-Results")},
		{"Desktop", filepath.Join(home, "Desktop", "chtester-Results")},
		{"ProgramData", filepath.Join(programData, "chtester", "chtester-Results")},
	}

	s := &Sink{}
	for _, c := range candidates {
		if err := tryWritable(c.dir); err != nil {
			s.Attempts = append(s.Attempts, fmt.Sprintf("%s (%s): FAIL - %v", c.label, c.dir, err))
			continue
		}
		s.Attempts = append(s.Attempts, fmt.Sprintf("%s (%s): OK", c.label, c.dir))
		s.Dir = c.dir
		s.Chosen = c.label
		return s, nil
	}
	return s, fmt.Errorf("hicbir sink yazilabilir degil; konsola dusulecek")
}

// tryWritable, dizini olusturup gercek bir yazma denemesi yapar.
func tryWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	probe := filepath.Join(dir, ".write-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return err
	}
	return os.Remove(probe)
}
