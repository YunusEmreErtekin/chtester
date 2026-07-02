package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/cleanup"
	"chtester/internal/harness"
	"chtester/internal/nativeapi"
	"chtester/internal/schema"
)

const cat05 = "05-Persistence"

// Module05, kalicilik (persistence) vektorlerini test eder. HEPSI gurultulu [N]:
// -EnableNoisy + gecerli scope ister. Her vektor: manifest'e yaz -> degisiklik yap ->
// dogrula -> ANINDA geri al -> manifest'te isaretle. invoke-cleanup.exe ayni manifesti okur.
type Module05 struct{}

func NewModule05() *Module05 { return &Module05{} }

func (Module05) ID() string   { return "05" }
func (Module05) Name() string { return "Kalıcılık (Persistence)" }

const persistMarker = "chtester-persist-canary"

func (m Module05) Run(ctx *harness.RunContext) []schema.Result {
	b := newBuilder(ctx, cat05)

	// 05.1 Run key (HKCU)
	b.add("CHT-05-001", "Run key kalıcılığı (HKCU)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1547.001"
		r.TierRequired = 2
		if !ctx.GateActive(r, 2, true) {
			return
		}
		safeRegPersist(ctx, r, registry.CURRENT_USER, "HKCU",
			`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, persistMarker,
			`C:\Windows\System32\cmd.exe /c rem chtester`)
	})

	// 05.1b RunOnce (HKCU)
	b.add("CHT-05-001b", "RunOnce kalıcılığı (HKCU)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1547.001"
		if !ctx.GateActive(r, 2, true) {
			return
		}
		safeRegPersist(ctx, r, registry.CURRENT_USER, "HKCU",
			`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, persistMarker,
			`C:\Windows\System32\cmd.exe /c rem chtester`)
	})

	// 05.4 Startup klasoru (kullanici)
	b.add("CHT-05-004", "Startup klasörü kalıcılığı (kullanıcı)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1547.001"
		if !ctx.GateActive(r, 2, true) {
			return
		}
		appdata := os.Getenv("APPDATA")
		startup := filepath.Join(appdata, `Microsoft\Windows\Start Menu\Programs\Startup`, "chtester-canary.cmd")
		safeFilePersist(ctx, r, startup, "@echo off\r\nrem chtester persistence canary\r\n")
	})

	// 05.2 Scheduled task (schtasks create/delete — cikis kodu, lokalize parse yok)
	b.add("CHT-05-002", "Scheduled task kalıcılığı", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1053.005"
		if !ctx.GateActive(r, 2, true) {
			return
		}
		safeTaskPersist(ctx, r)
	})

	// 05.15 PowerShell profile
	b.add("CHT-05-015", "PowerShell profile kalıcılığı", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskMedium
		r.Mapping.Attack = "T1546.013"
		if !ctx.GateActive(r, 2, true) {
			return
		}
		docs := os.Getenv("USERPROFILE")
		profile := filepath.Join(docs, `Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`)
		// Profil zaten varsa DOKUNMA (idempotent + kullanici verisini koruma) — sadece yoksa test et.
		if fileExists(profile) {
			r.Result = schema.ResultPartial
			r.Evidence = "PS profil dosyası zaten mevcut — üzerine yazılmadı (kullanıcı verisi korundu); yazılabilirlik testi atlandı"
			return
		}
		safeFilePersist(ctx, r, profile, "# chtester persistence canary\r\n")
	})

	// 05.3 Servis olusturma (admin/Tier 3)
	b.add("CHT-05-003", "Servis oluşturma kalıcılığı", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1543.003"
		if !ctx.GateActive(r, 3, true) {
			return
		}
		safeServicePersist(ctx, r)
	})

	// 05.5 WMI event subscription (admin/Tier 3) — GUVENLI YETENEK PROBU
	b.add("CHT-05-005", "WMI event subscription kalıcılığı", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1546.003"
		if !ctx.GateActive(r, 3, true) {
			return
		}
		safeWMIFilterPersist(ctx, r)
	})

	// 05.20 Mevcut persistence envanteri (PASIF — read-only; yazma yapmaz, gate'siz)
	b.add("CHT-05-020", "Mevcut persistence envanteri (read-only)", func(r *schema.Result) {
		r.RiskWhenOpen = schema.RiskHigh
		r.Mapping.Attack = "T1547.001"
		r.AttemptedMethods = []string{"Run/RunOnce/Startup/ScheduledTask registry+dizin okuma"}
		var runVals []string
		collect := func(root registry.Key, rootName, path string) {
			if m, err := nativeapi.RegStringValues(root, path); err == nil {
				for name, val := range m {
					runVals = append(runVals, rootName+`\`+name+"="+val)
				}
			}
		}
		collect(registry.CURRENT_USER, "HKCU-Run", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
		collect(registry.CURRENT_USER, "HKCU-RunOnce", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`)
		collect(registry.LOCAL_MACHINE, "HKLM-Run", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)

		appdata := os.Getenv("APPDATA")
		startupCount := dirFileCount(filepath.Join(appdata, `Microsoft\Windows\Start Menu\Programs\Startup`))
		taskCount := dirFileCount(filepath.Join(systemRoot(), `System32\Tasks`))

		userprofile := strings.ToLower(os.Getenv("USERPROFILE"))
		userWritable := 0
		for _, v := range runVals {
			lv := strings.ToLower(v)
			if (userprofile != "" && strings.Contains(lv, userprofile)) ||
				strings.Contains(lv, `\appdata\`) || strings.Contains(lv, `\temp\`) ||
				strings.Contains(lv, `\public\`) {
				userWritable++
			}
		}
		r.Evidence = fmt.Sprintf("RunKeys=%d; Startup-dosya=%d; Zamanlanmış-görev=%d; kullanıcı-yazılabilir-yoldan=%d",
			len(runVals), startupCount, taskCount, userWritable)
		if userWritable > 0 {
			r.Result = schema.ResultAllowed
			r.Recommendation = "Kullanıcı-yazılabilir yoldan başlayan autostart girdileri incelenmeli; HKCU Run/RunOnce ACL ile kapatılamaz, ASR(T1547)+EDR ile izlenmeli. Aktif yazma testi: CHT-05-001 (-EnableNoisy)."
		} else {
			r.Result = schema.ResultPartial
			r.RiskWhenOpen = schema.RiskMedium
			r.Recommendation = "Standart autostart envanteri; HKCU Run yine de kullanıcı tarafından yazılabilir (bkz. CHT-12-014)."
		}
	})

	return b.results()
}

// safeRegPersist, registry persistence: eski deger oku -> manifest -> yaz -> dogrula -> geri al.
func safeRegPersist(ctx *harness.RunContext, r *schema.Result, root registry.Key, rootName, path, name, data string) {
	r.AttemptedMethods = []string{"eski deger oku", "manifest kaydet", "yaz", "doğrula", "geri al"}
	r.Target = rootName + `\` + path + `\` + name

	// Mevcut durumu oku (idempotency + revert icin).
	oldVal, oldErr := readRegString(root, path, name)
	hadOld := oldErr == nil
	keyExisted := nativeapi.RegKeyExists(root, path) // revert'te artik anahtar birakmamak icin

	actionID := fmt.Sprintf("reg:%s:%s:%s", rootName, path, name)
	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(cleanup.Action{
			ID: actionID, Type: cleanup.ActionRegistrySet, Root: rootName,
			Target: path, ValueName: name, ValueType: "SZ", OldValue: oldVal, HadOld: hadOld,
			CreatedKey: !keyExisted, TestID: r.TestID,
		})
	}

	// Yaz.
	k, _, err := registry.CreateKey(root, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = schema.BlockUnknown
		r.Evidence = "anahtar açılamadı/yazılamadı: " + truncate(err.Error(), 120)
		return
	}
	werr := k.SetStringValue(name, data)
	k.Close()
	if werr != nil {
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = schema.BlockUnknown
		r.Evidence = "değer yazılamadı (engellendi): " + truncate(werr.Error(), 120)
		revertRegPersist(ctx, root, path, name, oldVal, hadOld, !keyExisted, actionID)
		return
	}

	// Doğrula.
	got, _ := readRegString(root, path, name)
	wrote := got == data

	// ANINDA geri al.
	revertRegPersist(ctx, root, path, name, oldVal, hadOld, !keyExisted, actionID)

	if wrote {
		r.Result = schema.ResultAllowed
		r.Detected = schema.DetectedUnknown
		r.Evidence = "Persistence YAZILABILDI ve doğrulandı (anında geri alındı). Engellenmedi."
		r.Recommendation = "Bu kalıcılık konumu izlenmeli/engellenmeli (ASR persistence + EDR)."
	} else {
		r.Result = schema.ResultPartial
		r.Evidence = "Yazma denendi ama doğrulama eşleşmedi (kısmi/engelli)"
	}
}

func revertRegPersist(ctx *harness.RunContext, root registry.Key, path, name, oldVal string, hadOld, createdKey bool, actionID string) {
	k, err := registry.OpenKey(root, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err == nil {
		if hadOld {
			_ = k.SetStringValue(name, oldVal)
		} else {
			_ = k.DeleteValue(name)
		}
		k.Close()
		// Anahtari biz olusturduysak ve bos kaldiysa anahtari da sil (tam geri-alma).
		if !hadOld && createdKey {
			_ = registry.DeleteKey(root, path)
		}
	}
	if ctx.Manifest != nil {
		ctx.Manifest.MarkActionUndone(actionID)
	}
}

// safeFilePersist, dosya persistence: manifest -> yaz -> dogrula -> sil.
func safeFilePersist(ctx *harness.RunContext, r *schema.Result, path, content string) {
	r.AttemptedMethods = []string{"manifest kaydet", "yaz", "doğrula", "sil"}
	r.Target = path
	actionID := "file:" + path

	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(recordFileCreate(path, r.TestID))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		r.Result = schema.ResultBlocked
		r.Evidence = "dizin oluşturulamadı: " + truncate(err.Error(), 100)
		if ctx.Manifest != nil {
			ctx.Manifest.MarkActionUndone(actionID)
		}
		return
	}
	err := os.WriteFile(path, []byte(content), 0o600)
	wrote := err == nil && fileExists(path)
	_ = os.Remove(path) // ANINDA geri al
	if ctx.Manifest != nil {
		ctx.Manifest.MarkActionUndone(actionID)
	}
	if wrote {
		r.Result = schema.ResultAllowed
		r.Evidence = "Dosya yazılabildi ve doğrulandı (anında silindi). Engellenmedi: " + path
		r.Recommendation = "Bu kalıcılık konumu (Startup/profil) izlenmeli."
	} else {
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = schema.BlockUnknown
		r.Evidence = "yazılamadı (engellendi): " + truncate(fmt.Sprint(err), 120)
	}
}

// safeTaskPersist, schtasks ile gorev olustur/sil (cikis kodu; lokalize parse yok).
func safeTaskPersist(ctx *harness.RunContext, r *schema.Result) {
	r.AttemptedMethods = []string{"schtasks /create", "doğrula /query", "schtasks /delete"}
	const taskName = `\chtester-persist-canary`
	r.Target = taskName
	actionID := "task:" + taskName

	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(cleanup.Action{
			ID: actionID, Type: cleanup.ActionTaskCreate, Target: taskName, TestID: r.TestID,
		})
	}
	create := runCmd(15*time.Second, "schtasks.exe", "/create", "/tn", taskName, "/tr",
		`cmd.exe /c rem chtester`, "/sc", "once", "/st", "23:59", "/f")
	created := create.ExitCode == 0
	// ANINDA geri al.
	runCmd(15*time.Second, "schtasks.exe", "/delete", "/tn", taskName, "/f")
	if ctx.Manifest != nil {
		ctx.Manifest.MarkActionUndone(actionID)
	}
	if created {
		r.Result = schema.ResultAllowed
		r.Evidence = "Scheduled task oluşturulabildi (anında silindi). Engellenmedi."
		r.Recommendation = "Kullanıcı scheduled task ile kalıcılık kurabiliyor — izlenmeli (Event 4698)."
	} else {
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = schema.BlockUnknown
		r.Evidence = "task oluşturulamadı (engellendi): " + truncate(create.Output, 140)
	}
}

// safeServicePersist, sc ile servis olustur/sil (admin gerekir).
func safeServicePersist(ctx *harness.RunContext, r *schema.Result) {
	r.AttemptedMethods = []string{"sc create", "sc delete"}
	const svcName = "chtester-persist-canary"
	r.Target = svcName
	actionID := "svc:" + svcName

	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(cleanup.Action{
			ID: actionID, Type: cleanup.ActionServiceCreate, Target: svcName, TestID: r.TestID,
		})
	}
	create := runCmd(15*time.Second, "sc.exe", "create", svcName, "binPath=",
		`C:\Windows\System32\cmd.exe /c rem chtester`, "start=", "demand")
	created := create.ExitCode == 0
	runCmd(15*time.Second, "sc.exe", "delete", svcName)
	if ctx.Manifest != nil {
		ctx.Manifest.MarkActionUndone(actionID)
	}
	if created {
		r.Result = schema.ResultAllowed
		r.Evidence = "Servis oluşturulabildi (anında silindi)."
		r.Recommendation = "Servis oluşturma kalıcılığı izlenmeli (Event 7045)."
	} else {
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = "Permission"
		r.Evidence = "servis oluşturulamadı: " + truncate(create.Output, 140)
	}
}

const wmiFilterCanary = "chtester-persist-canary"

// safeWMIFilterPersist, WMI kalicilik YETENEGINI guvenli alt kume ile test eder: root\
// subscription altinda yalniz ASLA-TETIKLENMEYEN bir __EventFilter yazar — consumer ve
// FilterToConsumerBinding OLUSTURMAZ, yani calistirilabilir kalicilik zinciri ASLA olusmaz.
// Desen: manifest'e yaz -> PutInstance -> dogrula -> ANINDA DeleteInstance -> isaretle.
// Surec olurse invoke-cleanup ayni filter'i ActionWMIFilterCreate uzerinden siler.
func safeWMIFilterPersist(ctx *harness.RunContext, r *schema.Result) {
	r.AttemptedMethods = []string{"__EventFilter PutInstance (consumer/binding YOK)", "doğrula", "DeleteInstance"}
	r.Target = `root\subscription:__EventFilter.Name="` + wmiFilterCanary + `"`
	actionID := "wmi:" + wmiFilterCanary

	if ctx.Manifest != nil {
		_ = ctx.Manifest.Record(cleanup.Action{
			ID: actionID, Type: cleanup.ActionWMIFilterCreate, Target: wmiFilterCanary, TestID: r.TestID,
		})
	}

	// Gecerli ama pratikte tetiklenmeyen intrinsic-event sorgusu (cok buyuk WITHIN; binding yok).
	const benignQuery = `SELECT * FROM __InstanceModificationEvent WITHIN 999999 WHERE TargetInstance ISA 'Win32_LocalTime'`
	createErr := nativeapi.WMICreateEventFilter(wmiFilterCanary, benignQuery, `root\cimv2`)
	created := createErr == nil && nativeapi.WMIEventFilterExists(wmiFilterCanary)

	// ANINDA geri al. Y-3 ilkesi: yalniz filter GERCEKTEN yoksa undone isaretle —
	// silme basarisiz olup filter durursa eylem PENDING kalsin ki invoke-cleanup tekrar denesin
	// (sahte "temizlendi" yok).
	delErr := nativeapi.WMIDeleteEventFilter(wmiFilterCanary)
	stillExists := delErr != nil && nativeapi.WMIEventFilterExists(wmiFilterCanary)
	if ctx.Manifest != nil && !stillExists {
		ctx.Manifest.MarkActionUndone(actionID)
	}

	switch {
	case created:
		r.Result = schema.ResultAllowed
		r.Evidence = "WMI __EventFilter YAZILABILDI ve doğrulandı (consumer/binding oluşturulmadı; anında silindi). WMI kalıcılık yüzeyi açık."
		r.Recommendation = "root\\subscription yazımı kısıtlanmalı/izlenmeli (WMI persistence T1546.003; Sysmon Event 19/20/21, MDE WmiPersistence)."
		if stillExists {
			r.Evidence += " UYARI: silme BAŞARISIZ, filter HÂLÂ MEVCUT (" + truncate(fmt.Sprint(delErr), 100) + ") — invoke-cleanup ile temizleyin (manifest'te pending bırakıldı)."
		}
	case createErr != nil:
		r.Result = schema.ResultBlocked
		r.BlockingMechanism = schema.BlockUnknown
		r.Evidence = "WMI __EventFilter oluşturulamadı (engellendi/yetki yok): " + truncate(createErr.Error(), 140)
	default:
		r.Result = schema.ResultPartial
		r.Evidence = "PutInstance hata vermedi ama doğrulama filter'ı bulamadı (kısmi/engelli)."
	}
}

// readRegString, registry string deger okur (revert icin).
func readRegString(root registry.Key, path, name string) (string, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	return v, err
}
