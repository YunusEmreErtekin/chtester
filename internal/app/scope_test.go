package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"chtester/internal/scopesig"
)

func writeScope(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var refNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func TestValidateScopeValid(t *testing.T) {
	p := writeScope(t, `{"ticket":"TEST-1","validFrom":"2026-01-01T00:00:00Z","validUntil":"2026-12-31T23:59:59Z","allowedTestClasses":["passive","noisy"]}`)
	ok, why := validateScope(p, refNow, "noisy")
	if !ok {
		t.Errorf("gecerli yetki kabul edilmeliydi: %s", why)
	}
}

func TestValidateScopeExpired(t *testing.T) {
	p := writeScope(t, `{"ticket":"TEST-1","validUntil":"2026-03-01T00:00:00Z","allowedTestClasses":["noisy"]}`)
	ok, why := validateScope(p, refNow, "noisy")
	if ok {
		t.Error("suresi dolmus yetki REDDEDILMELIYDI")
	}
	if want := "DOLMUS"; !contains(why, want) {
		t.Errorf("sebep %q icermeli, %q", want, why)
	}
}

func TestValidateScopeNotYetValid(t *testing.T) {
	p := writeScope(t, `{"ticket":"TEST-1","validFrom":"2026-09-01T00:00:00Z","allowedTestClasses":["noisy"]}`)
	if ok, _ := validateScope(p, refNow, "noisy"); ok {
		t.Error("henuz baslamamis yetki reddedilmeliydi")
	}
}

func TestValidateScopeClassNotAllowed(t *testing.T) {
	p := writeScope(t, `{"ticket":"TEST-1","allowedTestClasses":["passive","active-safe"]}`)
	if ok, _ := validateScope(p, refNow, "noisy"); ok {
		t.Error("noisy izinli degilken reddedilmeliydi")
	}
}

func TestValidateScopeEmptyTicket(t *testing.T) {
	p := writeScope(t, `{"ticket":"","allowedTestClasses":["noisy"]}`)
	if ok, _ := validateScope(p, refNow, "noisy"); ok {
		t.Error("bos ticket reddedilmeliydi")
	}
}

// --- HMAC butunluk imzasi senaryolari ---

const hmacKey = "engagement-key-2026"

func signedScope(t *testing.T, d scopesig.Doc, classesJSON string) string {
	t.Helper()
	sig := scopesig.Sign(d, []byte(hmacKey))
	return writeScope(t, `{"ticket":"`+d.Ticket+`","validUntil":"`+d.ValidUntil+`","allowedTestClasses":`+classesJSON+`,"signature":"`+sig+`"}`)
}

// Anahtar tanimliyken gecerli imza KABUL edilmeli.
func TestValidateScopeSignedValid(t *testing.T) {
	t.Setenv(scopesig.EnvKey, hmacKey)
	d := scopesig.Doc{Ticket: "TEST-1", ValidUntil: "2026-12-31T23:59:59Z", AllowedTestClasses: []string{"noisy"}}
	p := signedScope(t, d, `["noisy"]`)
	if ok, why := validateScope(p, refNow, "noisy"); !ok {
		t.Errorf("dogru imzali scope kabul edilmeliydi: %s", why)
	}
}

// Anahtar tanimliyken imzasiz scope REDDEDILMELI.
func TestValidateScopeKeySetButUnsigned(t *testing.T) {
	t.Setenv(scopesig.EnvKey, hmacKey)
	p := writeScope(t, `{"ticket":"TEST-1","validUntil":"2026-12-31T23:59:59Z","allowedTestClasses":["noisy"]}`)
	if ok, why := validateScope(p, refNow, "noisy"); ok {
		t.Errorf("anahtar tanimliyken imzasiz scope reddedilmeliydi: %s", why)
	}
}

// Imza dogru ama scope sonradan DEGISTIRILMIS (validUntil uzatilmis) -> RED.
func TestValidateScopeTampered(t *testing.T) {
	t.Setenv(scopesig.EnvKey, hmacKey)
	d := scopesig.Doc{Ticket: "TEST-1", ValidUntil: "2026-12-31T23:59:59Z", AllowedTestClasses: []string{"noisy"}}
	sig := scopesig.Sign(d, []byte(hmacKey))
	// Imza eski tarih icin uretildi; dosyada validUntil uzatildi.
	p := writeScope(t, `{"ticket":"TEST-1","validUntil":"2030-01-01T00:00:00Z","allowedTestClasses":["noisy"],"signature":"`+sig+`"}`)
	if ok, why := validateScope(p, refNow, "noisy"); ok {
		t.Errorf("degistirilmis scope reddedilmeliydi: %s", why)
	}
}

// Anahtar tanimsizken imzali scope dogrulanamaz -> RED (imza yok sayilmaz).
func TestValidateScopeSignedButNoKey(t *testing.T) {
	t.Setenv(scopesig.EnvKey, "")
	d := scopesig.Doc{Ticket: "TEST-1", ValidUntil: "2026-12-31T23:59:59Z", AllowedTestClasses: []string{"noisy"}}
	p := signedScope(t, d, `["noisy"]`)
	if ok, why := validateScope(p, refNow, "noisy"); ok {
		t.Errorf("anahtarsiz imzali scope reddedilmeliydi: %s", why)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
