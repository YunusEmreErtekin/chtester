// Command chtester-aggregate, birden cok cihazin results.json ciktilarini Test-ID bazli
// tek filo (fleet) raporunda birlestirir ve outlier/sistemik-zayiflik tespiti yapar.
// Plan §Faz 5 — Ölçek & saha.
package main

import (
	"flag"
	"fmt"
	"os"

	"chtester/internal/aggregate"
)

func main() {
	out := flag.String("out", "FleetReport", "Filo raporu çıktı dizini")
	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."} // varsayilan: mevcut dizini tara
	}

	reports, err := aggregate.LoadReports(paths)
	if err != nil {
		fmt.Fprintln(os.Stderr, "yükleme hatası:", err)
		os.Exit(1)
	}
	if len(reports) == 0 {
		fmt.Fprintln(os.Stderr, "results.json bulunamadı. Kullanım: chtester-aggregate [dizin|dosya ...] -out FleetReport")
		os.Exit(1)
	}

	fleet := aggregate.Build(reports)
	jsonPath, csvPath, htmlPath, werr := aggregate.WriteAll(*out, fleet)
	if werr != nil {
		fmt.Fprintln(os.Stderr, "rapor yazılamadı:", werr)
		os.Exit(1)
	}

	fmt.Println("==================== FILO ÖZETİ ====================")
	fmt.Printf("Cihaz sayısı       : %d\n", fleet.DeviceCount)
	fmt.Printf("Benzersiz Test-ID  : %d\n", len(fleet.TestStats))
	fmt.Printf("Sistemik zayıflık  : %d\n", len(fleet.SystemicIssues))
	fmt.Printf("Toplam outlier     : %d\n", fleet.TotalOutliers)
	fmt.Printf("Katalog sürümleri  : %v\n", fleet.CatalogVersions)
	if len(fleet.SystemicIssues) > 0 {
		fmt.Printf("Sistemik Test-ID'ler: %v\n", fleet.SystemicIssues)
	}
	fmt.Println("Çıktılar:")
	fmt.Printf("  - %s\n  - %s\n  - %s\n", jsonPath, csvPath, htmlPath)
	fmt.Println("====================================================")
}
