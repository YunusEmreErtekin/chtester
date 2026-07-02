// Command chtester, client cihaz sertlestirme test aracinin ana ikilisidir.
// Faz 1-8 tamam: bootstrap + 00 baglam kesfi + Capability Tier + 14 kategori /
// ~112 vektor (katalog 0.6) + uc formatta rapor + filo birlestirme + bagimsiz
// temizlik. Denetim bulgulari (DENETIM-RAPORU.md) kapatildi.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"chtester/internal/app"
	"chtester/internal/gui"
	"chtester/internal/schema"
)

// consoleLogger, ilerlemeyi stderr'e yazar (cikti diske garanti, konsol flash olsa bile).
type consoleLogger struct{}

func (consoleLogger) Logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func main() {
	var (
		profile     = flag.String("Profile", "Audit", "Calisma profili: Audit | Stealth")
		passiveOnly = flag.Bool("PassiveOnly", true, "Yalniz pasif okuma (varsayilan). Aktif test icin -PassiveOnly=false")
		enableNoisy = flag.Bool("EnableNoisy", false, "Gurultulu [N] testleri etkinlestir (scope artefakti gerekir)")
		skipDestr   = flag.Bool("SkipDestructive", false, "Yikici testleri atla")
		whatIf      = flag.Bool("WhatIf", false, "Hicbir degisiklik yapma; ne calisacakti listele")
		scopePath   = flag.String("ScopePath", "", "scope.json (yetki artefakti) yolu")
		outDir      = flag.String("Out", "", "Cikti dizini (bos ise USB->Temp->Desktop->ProgramData secilir)")
		budgetSec   = flag.Int("BudgetSec", 0, "Toplam calisma butcesi (saniye); 0 = sinirsiz")
		useGUI      = flag.Bool("gui", false, "Basit grafik arayuzunu ac")
		openReport  = flag.Bool("OpenReport", false, "Bitince HTML raporu tarayicida ac")
	)
	flag.Parse()

	if *useGUI {
		if err := gui.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "GUI baslatilamadi:", err)
			os.Exit(1)
		}
		return
	}

	opts := app.Options{
		Profile:         *profile,
		PassiveOnly:     *passiveOnly,
		EnableNoisy:     *enableNoisy,
		SkipDestructive: *skipDestr,
		WhatIf:          *whatIf,
		ScopePath:       *scopePath,
		OutDir:          *outDir,
		BudgetSec:       *budgetSec,
	}

	out, err := app.Execute(opts, consoleLogger{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "HATA:", err)
		os.Exit(2)
	}

	printSummary(out)

	if *openReport {
		_ = exec.Command("cmd", "/c", "start", "", out.HTMLPath).Start()
	}
}

func printSummary(out *app.RunOutput) {
	rep := out.Report
	counts := map[string]int{}
	for _, r := range rep.Results {
		counts[r.Result]++
	}
	fmt.Println()
	fmt.Println("==================== OZET ====================")
	fmt.Printf("DeviceId : %s\n", rep.DeviceID)
	fmt.Printf("Tier     : %d (%s)\n", rep.Tier, rep.TierReason)
	fmt.Printf("Profil   : %s\n", rep.Profile)
	fmt.Printf("Vektor   : %d  | Allowed=%d Blocked=%d Partial=%d Error=%d NA=%d\n",
		len(rep.Results), counts[schema.ResultAllowed], counts[schema.ResultBlocked],
		counts[schema.ResultPartial], counts[schema.ResultError], counts[schema.ResultNotApplicable])
	fmt.Printf("Cikti    : %s\n", out.SinkDir)
	fmt.Printf("  - %s\n  - %s\n  - %s\n", out.JSONPath, out.TXTPath, out.HTMLPath)
	fmt.Println("==============================================")
}
