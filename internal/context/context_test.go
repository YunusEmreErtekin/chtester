package context

import (
	"strings"
	"testing"
)

// determineTier, aktif/gurultulu testlerin hangi yetki seviyesinde kosacagini belirleyen
// guvenlik-kritik karardir; matrisi regresyona karsi kilitliyoruz.
func TestDetermineTier(t *testing.T) {
	cases := []struct {
		name     string
		env      Env
		wantTier int
	}{
		{"admin token her seyi ezer", Env{IsAdmin: true, PSLanguageMode: "ConstrainedLanguage"}, 3},
		{"standart + FullLanguage", Env{PSLanguageMode: "FullLanguage"}, 2},
		{"FullLanguage buyuk-kucuk duyarsiz", Env{PSLanguageMode: "fulllanguage"}, 2},
		{"ConstrainedLanguage", Env{PSLanguageMode: "ConstrainedLanguage", PSAvailable: true}, 1},
		{"PS yok", Env{PSAvailable: false}, 1},
		{"PS var ama mode belirsiz", Env{PSAvailable: true, PSLanguageMode: "Unknown"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := c.env
			got, reason := determineTier(&e)
			if got != c.wantTier {
				t.Errorf("determineTier=%d, istenen %d (%s)", got, c.wantTier, reason)
			}
			if reason == "" {
				t.Error("TierReason bos donmemeli")
			}
		})
	}
}

// deviceID, KVKK/gizlilik iddiasinin (PII icermez) somut guvencesidir: ayni hostname
// deterministik ayni kimligi uretmeli, ham hostname cikti icinde GORUNMEMELI.
func TestDeviceIDDeterministicAndPIIFree(t *testing.T) {
	const host = "TEST-LAPTOP-01"
	a := deviceID(host)
	b := deviceID(host)
	if a != b {
		t.Errorf("ayni hostname farkli deviceID uretti: %q != %q", a, b)
	}
	if deviceID("BASKA-HOST") == a {
		t.Error("farkli hostname ayni deviceID uretti")
	}
	if len(a) < 16 {
		t.Errorf("deviceID cok kisa: %q", a)
	}
	if strings.Contains(strings.ToLower(a), strings.ToLower(host)) {
		t.Errorf("deviceID ham hostname'i sizdiriyor: %q", a)
	}
	// Ilk 16 karakter sha256 hex onekidir.
	for _, ch := range a[:16] {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			t.Errorf("deviceID oneki hex degil: %q", a)
			break
		}
	}
}

// detectArch, WOW64 altinda gercek mimariyi (ARCHITEW6432) tercih etmeli.
func TestDetectArchPrefersWow64(t *testing.T) {
	t.Setenv("PROCESSOR_ARCHITECTURE", "x86")
	t.Setenv("PROCESSOR_ARCHITEW6432", "AMD64")
	if got := detectArch(); got != "AMD64" {
		t.Errorf("WOW64 altinda detectArch=%q, AMD64 bekleniyordu", got)
	}

	t.Setenv("PROCESSOR_ARCHITEW6432", "")
	if got := detectArch(); got != "x86" {
		t.Errorf("ARCHITEW6432 yokken detectArch=%q, x86 bekleniyordu", got)
	}
}

// deriveLanguageMode, __PSLockdownPolicy=4 sinyalini PowerShell BASLATMADAN CLM'e cevirmeli
// (Stealth/double-blind ilkesi: kesif kendi telemetrisini uretmemeli).
func TestDeriveLanguageModeLockdownEnv(t *testing.T) {
	t.Setenv("__PSLockdownPolicy", "4")
	if got := deriveLanguageMode(); got != "ConstrainedLanguage" {
		t.Errorf("__PSLockdownPolicy=4 ile deriveLanguageMode=%q, ConstrainedLanguage bekleniyordu", got)
	}
}
