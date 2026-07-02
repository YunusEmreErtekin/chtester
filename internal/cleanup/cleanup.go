// Package cleanup, aktif testlerin geri-alinabilirligi icin idempotent manifest yonetir.
// Plan: "Saglam temizlik" — her degisiklikten ONCE diske manifest yaz; bagimsiz
// invoke-cleanup.exe ayni manifesti okuyup geri alir. Stealth istisnasi YOK:
// manifest her zaman tam ve diske yazilir.
package cleanup

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ActionType, geri alinabilir degisiklik tipini belirtir.
type ActionType string

const (
	ActionRegistrySet ActionType = "registry_set" // registry deger yazildi
	ActionFileCreate  ActionType = "file_create"   // dosya olusturuldu
	ActionTaskCreate  ActionType = "task_create"   // scheduled task olusturuldu
	ActionServiceCreate ActionType = "service_create"
	ActionWMIFilterCreate ActionType = "wmi_filter_create" // root\subscription __EventFilter olusturuldu
)

// Action, manifest'te tek bir geri-alinabilir degisiklik.
type Action struct {
	ID         string     `json:"id"`
	Type       ActionType `json:"type"`
	Root       string     `json:"root,omitempty"`       // registry kok: "HKCU" | "HKLM"
	Target     string     `json:"target"`               // registry yolu / dosya yolu / task adi
	ValueName  string     `json:"valueName,omitempty"`  // registry deger adi
	ValueType  string     `json:"valueType,omitempty"`  // registry deger tipi: SZ|DWORD|QWORD|EXPAND_SZ|MULTI_SZ (bos=SZ)
	OldValue   string     `json:"oldValue,omitempty"`   // onceki deger (yoksa bos => sil)
	HadOld     bool       `json:"hadOld"`               // onceden deger var miydi
	CreatedKey bool       `json:"createdKey,omitempty"` // bu eylem registry ANAHTARINI olusturdu mu (revert'te sil)
	CreatedAt  string     `json:"createdAt"`
	UndoneAt   string     `json:"undoneAt,omitempty"`
	TestID     string     `json:"testId,omitempty"`
}

// MarkActionUndone, bir eylemi geri-alindi olarak isaretler (ID ile).
func (m *Manifest) MarkActionUndone(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.Actions {
		if m.Actions[i].ID == id && m.Actions[i].UndoneAt == "" {
			m.Actions[i].UndoneAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
	_ = m.flush()
}

// PendingActions, henuz geri alinmamis eylemleri doner.
func (m *Manifest) PendingActions() []Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Action
	for _, a := range m.Actions {
		if a.UndoneAt == "" {
			out = append(out, a)
		}
	}
	return out
}

// Manifest, tum geri-alinabilir degisikliklerin diske yazili kaydidir.
type Manifest struct {
	path    string
	mu      sync.Mutex
	Version string   `json:"version"`
	Created string   `json:"created"`
	Cleaned bool     `json:"cleaned"`
	Actions []Action `json:"actions"`
}

// New, verilen yolda manifest olusturur (varsa yukler).
func New(path string) (*Manifest, error) {
	m := &Manifest{path: path, Version: "1", Created: time.Now().UTC().Format(time.RFC3339)}
	if data, err := os.ReadFile(path); err == nil {
		data = stripBOM(data)
		if uerr := json.Unmarshal(data, m); uerr != nil {
			// Bozuk manifest EZILMEMELI (kalinti/kurtarma riski): yana tasi, taze basla.
			// Operator .corrupt dosyasindan geri-alinmamis eylemleri inceleyebilir.
			aside := fmt.Sprintf("%s.corrupt-%d", path, time.Now().UnixNano())
			_ = os.Rename(path, aside)
			fresh := &Manifest{path: path, Version: "1", Created: time.Now().UTC().Format(time.RFC3339)}
			return fresh, fmt.Errorf("bozuk manifest yana tasindi (%s); taze manifest baslatildi: %w", aside, uerr)
		}
		m.path = path
	}
	return m, m.flush()
}

// stripBOM, UTF-8 BOM'u (varsa) kaldirir; bazi editorler/PowerShell BOM ekler.
func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// Record, bir degisikligi DEGISIKLIKTEN ONCE manifeste yazar ve diske flush eder.
func (m *Manifest) Record(a Action) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	m.Actions = append(m.Actions, a)
	return m.flush()
}

// MarkCleaned, temizlik tamamlandiginda manifesti isaretler.
func (m *Manifest) MarkCleaned() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Cleaned = true
	return m.flush()
}

// Path, manifest dosya yolunu doner.
func (m *Manifest) Path() string { return m.path }

// flush, manifesti atomik (best-effort) diske yazar. Cagiran kilidi tutmali.
func (m *Manifest) flush() error {
	if m.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}
