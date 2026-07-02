// Package scopesig, yetki artefakti (scope.json) icin HMAC-SHA256 butunluk
// imzasini uretir ve dogrular. Amac: "ticket dolu olsun yeter" yuzeysel kontrolu
// otesinde, scope'un (kapsam/gecerlilik/test-sinifi) saha operatorunce DEGISTIRILEMEZ
// olmasini saglamak. Anahtar disaridan (CHTESTER_SCOPE_HMAC_KEY) gelir; ikiliye gomulmez.
//
// Imza, JSON serilestirmesinin kaprislerinden (alan sirasi/bosluk/BOM) bagimsiz olsun
// diye SABIT bir kanonik metin uzerinden hesaplanir. Boylece imzalayan (engagement lideri)
// ile dogrulayan (chtester) ayni baytlari uretir.
package scopesig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"strings"
)

// EnvKey, HMAC anahtarinin okundugu ortam degiskeni.
const EnvKey = "CHTESTER_SCOPE_HMAC_KEY"

// Doc, imzaya giren yetki alanlari (signature haric).
type Doc struct {
	Ticket                string
	ValidFrom             string
	ValidUntil            string
	AllowedTestClasses    []string
	DoubleBlindAuthorized bool
}

// Canonical, imzanin uzerinde hesaplandigi deterministik metni uretir.
// Test siniflari siralanir; boylece dizilim farki imzayi bozmaz.
func Canonical(d Doc) string {
	classes := append([]string(nil), d.AllowedTestClasses...)
	sort.Strings(classes)
	db := "false"
	if d.DoubleBlindAuthorized {
		db = "true"
	}
	// Alanlar arasi ayrac olarak \n; alan-ici ayrac olarak "," (siniflar zaten \n icermez).
	return strings.Join([]string{
		d.Ticket,
		d.ValidFrom,
		d.ValidUntil,
		strings.Join(classes, ","),
		db,
	}, "\n")
}

// Sign, verilen anahtarla kanonik metnin HMAC-SHA256'sini hex olarak doner.
func Sign(d Doc, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(Canonical(d)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify, sunulan hex imzanin anahtarla uyup uymadigini SABIT-ZAMANLI karsilastirir.
// Hex cozulemezse veya uyumsuzsa false.
func Verify(d Doc, key []byte, sigHex string) bool {
	want := Sign(d, key)
	got, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		return false
	}
	wantBytes, _ := hex.DecodeString(want)
	return hmac.Equal(wantBytes, got)
}

// KeyFromEnv, CHTESTER_SCOPE_HMAC_KEY ortam degiskenini bayt anahtara cevirir.
// Tanimsiz/bos ise nil doner (imza zorlamasi kapali — geriye uyum).
func KeyFromEnv() []byte {
	v := os.Getenv(EnvKey)
	if v == "" {
		return nil
	}
	return []byte(v)
}

// Result, butunluk dogrulamasinin sonucu (insan-okunur sebep ile).
type Result struct {
	OK     bool
	Reason string
}

// Check, anahtar/imza kombinasyonuna gore butunluk kapisini uygular:
//   - anahtar yok + imza yok  -> GECER (imzasiz; geriye uyum, "butunluk dogrulanmadi")
//   - anahtar yok + imza var   -> RED   (imza var ama dogrulanamiyor; anahtar sagla)
//   - anahtar var + imza yok    -> RED   (imza zorunlu; scope imzalanmali)
//   - anahtar var + imza var     -> HMAC eslesirse GECER, aksi halde RED
func Check(d Doc, key []byte, sigHex string) Result {
	hasKey := len(key) > 0
	hasSig := strings.TrimSpace(sigHex) != ""
	switch {
	case !hasKey && !hasSig:
		return Result{OK: true, Reason: "imzasiz (butunluk dogrulanmadi)"}
	case !hasKey && hasSig:
		return Result{OK: false, Reason: "scope imzali ama " + EnvKey + " tanimli degil — imza dogrulanamiyor"}
	case hasKey && !hasSig:
		return Result{OK: false, Reason: "imza zorunlu (" + EnvKey + " tanimli) ama scope imzasiz"}
	default:
		if Verify(d, key, sigHex) {
			return Result{OK: true, Reason: "HMAC imza dogrulandi"}
		}
		return Result{OK: false, Reason: "HMAC imza UYMUYOR (scope degistirilmis veya anahtar yanlis)"}
	}
}
