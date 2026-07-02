package nativeapi

import "testing"

// WMIEventFilterExists, var olmayan bir filter icin false donmeli. GUVENLI: salt-okunur
// sorgu, admin gerektirmez, yan etki birakmaz (rastgele-isimli filter kesinlikle yok).
// COM baglanti + root\subscription sorgu + bicimsel dogrulamayi calistirir (cokmemeli).
func TestWMIEventFilterExistsAbsent(t *testing.T) {
	if WMIEventFilterExists("chtester-kesinlikle-yok-zxqv-9171") {
		t.Error("var olmayan __EventFilter icin Exists=true dondu")
	}
}

func TestNormalizeArch(t *testing.T) {
	cases := map[string]string{
		"amd64":   "x64",
		"x64":     "x64",
		"AMD64":   "x64", // buyuk-kucuk harf duyarsiz
		"386":     "x86",
		"x86":     "x86",
		"arm64":   "arm64",
		"ARM64":   "arm64",
		"unknown": "unknown", // taninmayan aynen doner
	}
	for in, want := range cases {
		if got := NormalizeArch(in); got != want {
			t.Errorf("NormalizeArch(%q)=%q, istenen %q", in, got, want)
		}
	}
}
