package modules

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat06 = "06-DLP"

// Module06, tasinabilir medya / DLP / veri sizdirma kontrollerini test eder.
// Pasif politika okuma + (gate'li) aktif yazma denemesi. Sink seciminden BAGIMSIZ.
type Module06 struct {
	SinkDir string // sink modülünden bagimsiz; USB yazma denemesi icin exe dizini USB adayi
	ExeDir  string
}

func NewModule06(exeDir string) *Module06 { return &Module06{ExeDir: exeDir} }

func (Module06) ID() string   { return "06" }
func (Module06) Name() string { return "Taşınabilir Medya / DLP" }

func (m Module06) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat06)

	// 06.2 USB storage policy (pasif)
	b.add("CHT-06-002", "USB storage / removable media policy", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1052.001"
		r.AttemptedMethods = []string{"USBSTOR Start", "RemovableStorageDevices policy"}
		usbStart, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\USBSTOR`, "Start")
		denyRead, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}`, "Deny_Read")
		denyWrite, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}`, "Deny_Write")
		r.Evidence = fmt.Sprintf("USBSTOR.Start=%d (4=disabled); Deny_Read=%d Deny_Write=%d", usbStart, denyRead, denyWrite)
		switch {
		case usbStart == 4 || denyWrite == 1:
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "GPO"
			r.Recommendation = "USB depolama kisitli (iyi)."
		default:
			r.Result = schema.ResultAllowed
			r.Recommendation = "USB depolama yazma açık görünüyor — DLP/removable policy değerlendirilmeli."
		}
	})

	// 06.1 USB/harici yazma denemesi (aktif; sink'ten bagimsiz)
	b.add("CHT-06-001", "Taşınabilir medyaya yazma denemesi", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1052.001"
		r.AttemptedMethods = []string{"exe-dizini (USB adayı) yazma probe"}
		if !ctx.GateActive(r, 2, false) {
			return
		}
		exeDir := m.ExeDir
		if exeDir == "" {
			if exe, err := os.Executable(); err == nil {
				exeDir = filepath.Dir(exe)
			}
		}
		// Sadece exe-dizini gercekten kaldirilabilir bir surucudeyse anlamli; yine de probe ederiz.
		probe := filepath.Join(exeDir, ".cht-dlp-probe")
		err := os.WriteFile(probe, []byte("dlp-test"), 0o600)
		if err == nil {
			_ = os.Remove(probe)
			r.Result = schema.ResultAllowed
			r.Evidence = "exe-dizinine (USB adayı) yazilabildi: " + exeDir
			r.Recommendation = "Kurumsal veri USB'ye kopyalanabilir; DLP içerik denetimi (06.11) gerekli."
		} else {
			r.Result = schema.ResultBlocked
			r.BlockingMechanism = "DLP"
			r.Evidence = "yazma engellendi: " + err.Error()
		}
	})

	// 06.10 Diger cikis kanallari (pasif): Bluetooth / Nearby / tethering
	b.add("CHT-06-010", "Diğer çıkış kanalları (BT/Nearby/tethering)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.AttemptedMethods = []string{"servis/registry pasif okuma"}
		bt := nativeapi.ServiceInstalled("bthserv")
		nearby, _ := nativeapi.RegDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\System`, "EnableCdp")
		r.Result = schema.ResultPartial
		r.Evidence = fmt.Sprintf("BluetoothSvc=%v; CDP/Nearby policy(EnableCdp)=%d", bt, nearby)
		r.Recommendation = "Kullanilmayan cikis kanallari (BT/Nearby Sharing/tethering) GPO ile kapatilmali."
	})

	// 06.11 Content-DLP (aktif/gürültülü) — gate
	b.add("CHT-06-011", "İçerik-DLP testi (sentetik PII/kart deseni)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1567"
		r.AttemptedMethods = []string{"sentetik test-kredikartı/PII deseni", "uzantı/şifreli arşiv bypass"}
		if !ctx.GateActive(r, 2, true) {
			return
		}
		markNotImplemented(r, "icerik-DLP testi (sentetik PII/kart deseni + kanal POST)")
	})

	return b.results()
}
