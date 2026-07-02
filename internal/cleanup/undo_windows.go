//go:build windows

package cleanup

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"chtester/internal/nativeapi"
)

// UndoResult, tek bir eylemin geri-alma sonucu.
type UndoResult struct {
	Action  Action
	OK      bool
	Message string
}

// UndoAll, manifestteki geri-alinmamis tum eylemleri TERS sirayla geri alir (idempotent).
// Bagimsiz invoke-cleanup.exe ve normal akis sonu bunu cagirir.
func (m *Manifest) UndoAll() []UndoResult {
	m.mu.Lock()
	actions := make([]Action, len(m.Actions))
	copy(actions, m.Actions)
	m.mu.Unlock()

	var results []UndoResult
	for i := len(actions) - 1; i >= 0; i-- {
		a := actions[i]
		if a.UndoneAt != "" {
			continue
		}
		ok, msg := undoOne(a)
		results = append(results, UndoResult{Action: a, OK: ok, Message: msg})
		if ok {
			m.MarkActionUndone(a.ID)
		}
	}
	return results
}

func undoOne(a Action) (bool, string) {
	switch a.Type {
	case ActionRegistrySet:
		return undoRegistry(a)
	case ActionFileCreate:
		return undoFile(a)
	case ActionTaskCreate:
		return undoTask(a)
	case ActionServiceCreate:
		return undoService(a)
	case ActionWMIFilterCreate:
		return undoWMIFilter(a)
	default:
		return false, "bilinmeyen eylem tipi: " + string(a.Type)
	}
}

// undoWMIFilter, olusturulan __EventFilter'i siler. Zaten yoksa idempotent OK
// (WMIDeleteEventFilter WBEM_E_NOT_FOUND'u yutar); gercek silme hatasinda false.
func undoWMIFilter(a Action) (bool, string) {
	if err := nativeapi.WMIDeleteEventFilter(a.Target); err != nil {
		return false, "WMI __EventFilter SILINEMEDI (hala mevcut olabilir): " + err.Error()
	}
	return true, "WMI __EventFilter silindi (veya zaten yok)"
}

func rootKey(root string) (registry.Key, bool) {
	switch root {
	case "HKCU":
		return registry.CURRENT_USER, true
	case "HKLM":
		return registry.LOCAL_MACHINE, true
	default:
		return 0, false
	}
}

// undoRegistry, eski deger varsa (ORIJINAL TIPIYLE) geri yazar; yoksa olusturulan
// degeri siler. Bu eylem anahtari da olusturduysa (CreatedKey) ve anahtar bos kaldiysa
// anahtari da siler (tam geri-alma).
func undoRegistry(a Action) (bool, string) {
	rk, ok := rootKey(a.Root)
	if !ok {
		return false, "gecersiz root: " + a.Root
	}
	k, err := registry.OpenKey(rk, a.Target, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		// Anahtar yoksa zaten temiz kabul (idempotent).
		return true, "anahtar yok (idempotent): " + err.Error()
	}
	if a.HadOld {
		werr := writeTypedValue(k, a.ValueName, a.ValueType, a.OldValue)
		k.Close()
		if werr != nil {
			return false, "eski deger geri yazilamadi: " + werr.Error()
		}
		return true, "eski deger geri yazildi (tip=" + valueTypeOr(a.ValueType) + ")"
	}
	delErr := k.DeleteValue(a.ValueName)
	k.Close()
	msg := "olusturulan deger silindi"
	if delErr != nil {
		msg = "deger zaten yok (idempotent)"
	}
	// Bu eylem anahtari da olusturmussa ve bos kaldiysa anahtari da sil.
	if a.CreatedKey {
		if derr := registry.DeleteKey(rk, a.Target); derr == nil {
			msg += "; olusturulan anahtar da silindi"
		}
	}
	return true, msg
}

func valueTypeOr(t string) string {
	if t == "" {
		return "SZ"
	}
	return t
}

// writeTypedValue, bir registry degerini ORIJINAL tipiyle geri yazar. Tip bos ise SZ.
// (Bugun yalniz SZ kullaniliyor; ileride DWORD/QWORD/EXPAND/MULTI persistence eklenirse
// revert tip-bozmadan calisir.)
func writeTypedValue(k registry.Key, name, vtype, val string) error {
	switch strings.ToUpper(vtype) {
	case "DWORD":
		n, _ := strconv.ParseUint(val, 10, 32)
		return k.SetDWordValue(name, uint32(n))
	case "QWORD":
		n, _ := strconv.ParseUint(val, 10, 64)
		return k.SetQWordValue(name, n)
	case "EXPAND_SZ":
		return k.SetExpandStringValue(name, val)
	case "MULTI_SZ":
		return k.SetStringsValue(name, strings.Split(val, "\x00"))
	default: // SZ veya bos
		return k.SetStringValue(name, val)
	}
}

func undoFile(a Action) (bool, string) {
	if err := os.Remove(a.Target); err != nil {
		if os.IsNotExist(err) {
			return true, "dosya zaten yok (idempotent)"
		}
		return false, "dosya silinemedi: " + err.Error()
	}
	return true, "dosya silindi"
}

func undoTask(a Action) (bool, string) {
	out, _, err := runCapture("schtasks.exe", "/delete", "/tn", a.Target, "/f")
	if err == nil {
		return true, "scheduled task silindi"
	}
	// Silme basarisiz: gercekten yok mu, yoksa silinemedi mi? /query ile teyit et.
	// /query gorevi BULAMAZSA hata doner => gorev zaten yok (idempotent OK).
	// /query gorevi BULURSA basariliyla doner => silme GERCEKTEN basarisiz (kalinti!).
	if _, _, qerr := runCapture("schtasks.exe", "/query", "/tn", a.Target); qerr != nil {
		return true, "scheduled task zaten yok (idempotent): " + trim(string(out))
	}
	return false, "scheduled task SILINEMEDI (hala mevcut): " + trim(string(out))
}

func undoService(a Action) (bool, string) {
	out, code, err := runCapture("sc.exe", "delete", a.Target)
	if err == nil {
		return true, "servis silindi"
	}
	// sc.exe Win32 hata kodunu exit-code olarak doner.
	// 1060 = ERROR_SERVICE_DOES_NOT_EXIST => zaten yok (idempotent OK).
	const errServiceDoesNotExist = 1060
	if code == errServiceDoesNotExist {
		return true, "servis zaten yok (idempotent)"
	}
	return false, fmt.Sprintf("servis SILINEMEDI (exit=%d, hala mevcut olabilir): %s", code, trim(string(out)))
}

// runCapture, komutu calistirip cikti + exit-code + hata doner.
func runCapture(name string, args ...string) (out []byte, exitCode int, err error) {
	cmd := exec.Command(name, args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return out, exitCode, err
}

func trim(s string) string {
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
