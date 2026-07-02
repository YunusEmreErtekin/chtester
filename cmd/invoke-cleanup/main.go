// Command invoke-cleanup, chtester'in yazdigi manifest.json'u okuyup tum geri-alinmamis
// degisiklikleri geri alir. Ana ikili cokse/oldurulse bile tam temizlik saglar.
// Plan: "Bagimsiz invoke-cleanup.exe ayni manifesti okur" (Stealth'te de gecerli).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"chtester/internal/cleanup"
)

func main() {
	manifestPath := flag.String("manifest", "", "manifest.json yolu (boş ise yaygın konumlar aranır)")
	flag.Parse()

	path := *manifestPath
	if path == "" {
		path = findManifest()
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "manifest.json bulunamadı; -manifest ile yol verin")
		os.Exit(1)
	}
	fmt.Println("Manifest:", path)

	m, err := cleanup.New(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest okunamadı:", err)
		os.Exit(1)
	}

	pending := m.PendingActions()
	if len(pending) == 0 {
		fmt.Println("Geri alınacak değişiklik yok (temiz).")
		_ = m.MarkCleaned()
		return
	}
	fmt.Printf("%d geri-alınmamış değişiklik bulundu, geri alınıyor...\n", len(pending))

	results := m.UndoAll()
	okCount, failCount := 0, 0
	for _, res := range results {
		status := "OK"
		if !res.OK {
			status = "BAŞARISIZ"
			failCount++
		} else {
			okCount++
		}
		fmt.Printf("  [%s] %s %s -> %s\n", status, res.Action.Type, res.Action.Target, res.Message)
	}
	if failCount == 0 {
		_ = m.MarkCleaned()
		fmt.Printf("Temizlik tamam: %d geri alındı, kalıntı yok.\n", okCount)
	} else {
		fmt.Printf("Temizlik kısmi: %d OK, %d başarısız — manuel inceleme gerekir.\n", okCount, failCount)
		os.Exit(2)
	}
}

// findManifest, yaygin sink konumlarinda manifest.json arar.
func findManifest() string {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "Results", "manifest.json"))
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "manifest.json"))
	}
	temp := os.TempDir()
	candidates = append(candidates, filepath.Join(temp, "chtester-Results", "manifest.json"))
	home, _ := os.UserHomeDir()
	candidates = append(candidates, filepath.Join(home, "Desktop", "chtester-Results", "manifest.json"))
	pd := os.Getenv("ProgramData")
	if pd != "" {
		candidates = append(candidates, filepath.Join(pd, "chtester", "chtester-Results", "manifest.json"))
	}
	candidates = append(candidates, "manifest.json", filepath.Join("Results", "manifest.json"))
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}
