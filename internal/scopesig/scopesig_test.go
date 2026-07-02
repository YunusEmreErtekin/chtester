package scopesig

import "testing"

var sampleDoc = Doc{
	Ticket:                "CHT-2026-001",
	ValidFrom:             "2026-01-01T00:00:00Z",
	ValidUntil:            "2026-12-31T23:59:59Z",
	AllowedTestClasses:    []string{"noisy", "passive"},
	DoubleBlindAuthorized: true,
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := []byte("super-secret-engagement-key")
	sig := Sign(sampleDoc, key)
	if !Verify(sampleDoc, key, sig) {
		t.Fatal("kendi imzasi dogrulanmadi")
	}
}

func TestCanonicalClassOrderIndependent(t *testing.T) {
	key := []byte("k")
	a := sampleDoc
	b := sampleDoc
	b.AllowedTestClasses = []string{"passive", "noisy"} // ters sira
	if Sign(a, key) != Sign(b, key) {
		t.Error("test-sinifi dizilim sirasi imzayi degistirmemeli (kanonik siralama)")
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	key := []byte("k")
	sig := Sign(sampleDoc, key)
	tampered := sampleDoc
	tampered.ValidUntil = "2030-01-01T00:00:00Z" // suresi uzatilmis
	if Verify(tampered, key, sig) {
		t.Error("degistirilmis scope ESKI imzayla gecmemeli")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	sig := Sign(sampleDoc, []byte("right-key"))
	if Verify(sampleDoc, []byte("wrong-key"), sig) {
		t.Error("yanlis anahtar reddedilmeliydi")
	}
}

func TestVerifyRejectsBadHex(t *testing.T) {
	if Verify(sampleDoc, []byte("k"), "not-hex-zzzz") {
		t.Error("gecersiz hex imza reddedilmeliydi")
	}
}

func TestCheckGate(t *testing.T) {
	key := []byte("k")
	goodSig := Sign(sampleDoc, key)
	cases := []struct {
		name   string
		key    []byte
		sig    string
		wantOK bool
	}{
		{"anahtar-yok imza-yok -> gecer (geriye uyum)", nil, "", true},
		{"anahtar-yok imza-var -> red", nil, goodSig, false},
		{"anahtar-var imza-yok -> red", key, "", false},
		{"anahtar-var dogru-imza -> gecer", key, goodSig, true},
		{"anahtar-var yanlis-imza -> red", key, "deadbeef", false},
	}
	for _, c := range cases {
		if got := Check(sampleDoc, c.key, c.sig); got.OK != c.wantOK {
			t.Errorf("%s: OK=%v istenen=%v (%s)", c.name, got.OK, c.wantOK, got.Reason)
		}
	}
}

func TestKeyFromEnv(t *testing.T) {
	t.Setenv(EnvKey, "abc123")
	if string(KeyFromEnv()) != "abc123" {
		t.Error("anahtar ortamdan okunmadi")
	}
	t.Setenv(EnvKey, "")
	if KeyFromEnv() != nil {
		t.Error("bos ortam degiskeni nil donmeli")
	}
}
