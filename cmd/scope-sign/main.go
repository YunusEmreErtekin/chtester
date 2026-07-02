// Command scope-sign, bir scope.json yetki artefaktini HMAC-SHA256 ile imzalar.
// Engagement lideri bunu BIR KEZ calistirir; saha operatoru imzayi degistiremez
// (chtester CHTESTER_SCOPE_HMAC_KEY tanimliysa imzayi dogrular, bkz. internal/scopesig).
//
// Kullanim:
//
//	scope-sign -in scope.json [-out scope.json] [-key <hmac-key>]
//
// Anahtar -key bayragiyla veya CHTESTER_SCOPE_HMAC_KEY ortam degiskeniyle verilir.
// -out verilmezse imzali JSON stdout'a yazilir (dosyayi ezmez).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"chtester/internal/scopesig"
)

func main() {
	in := flag.String("in", "scope.json", "girdi scope.json yolu")
	out := flag.String("out", "", "cikti yolu (bos ise stdout)")
	keyFlag := flag.String("key", "", "HMAC anahtari (bos ise "+scopesig.EnvKey+" ortam degiskeni)")
	flag.Parse()

	key := []byte(*keyFlag)
	if len(key) == 0 {
		key = scopesig.KeyFromEnv()
	}
	if len(key) == 0 {
		fmt.Fprintln(os.Stderr, "HATA: anahtar yok — -key verin veya "+scopesig.EnvKey+" ayarlayin")
		os.Exit(2)
	}

	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "HATA: scope okunamadi:", err)
		os.Exit(2)
	}
	data = stripBOM(data)

	// Tum alanlari koru (bilinmeyenler dahil) ama imzayi yeniden hesapla.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		fmt.Fprintln(os.Stderr, "HATA: scope JSON cozulemedi:", err)
		os.Exit(2)
	}
	if s, _ := raw["ticket"].(string); s == "" {
		fmt.Fprintln(os.Stderr, "HATA: ticket alani bos — imzalanmaz")
		os.Exit(2)
	}

	doc := scopesig.Doc{
		Ticket:                str(raw["ticket"]),
		ValidFrom:             str(raw["validFrom"]),
		ValidUntil:            str(raw["validUntil"]),
		AllowedTestClasses:    strSlice(raw["allowedTestClasses"]),
		DoubleBlindAuthorized: boolOf(raw["doubleBlindAuthorized"]),
	}
	raw["signature"] = scopesig.Sign(doc, key)

	enc, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "HATA: JSON yazilamadi:", err)
		os.Exit(2)
	}
	enc = append(enc, '\n')

	if *out == "" {
		os.Stdout.Write(enc)
		return
	}
	if err := os.WriteFile(*out, enc, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "HATA: cikti yazilamadi:", err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "Imzalandi ->", *out)
}

func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

func str(v any) string { s, _ := v.(string); return s }

func boolOf(v any) bool { b, _ := v.(bool); return b }

func strSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
