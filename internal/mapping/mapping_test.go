package mapping

import (
	"regexp"
	"testing"

	"chtester/internal/schema"
)

// For, bilinen Test-ID icin eslemeyi, bilinmeyen icin bos Mapping dondurmeli.
func TestForLookup(t *testing.T) {
	if got := For("CHT-00-006").Attack; got != "T1059.001" {
		t.Errorf("CHT-00-006 Attack=%q, T1059.001 bekleniyordu", got)
	}
	if got := For("CHT-YOK-999"); (got != schema.Mapping{}) {
		t.Errorf("bilinmeyen Test-ID bos Mapping dondurmeliydi, donen: %+v", got)
	}
}

// Merkezi tablo iyi-bicimli olmali: anahtarlar CHT-NN-NNN desenine uymali ve her
// girdi en az bir cerceve alani (CIS/MSBaseline/ASR/ATT&CK) tasimali. Bu guard, ileride
// eklenen bos/hatali-anahtarli eslemeleri regresyon olarak yakalar.
func TestTableWellFormed(t *testing.T) {
	idRe := regexp.MustCompile(`^CHT-\d\d-\d{3}[a-z]?$`)
	for id, m := range table {
		if !idRe.MatchString(id) {
			t.Errorf("tablo anahtari Test-ID desenine uymuyor: %q", id)
		}
		empty := m.CIS == "" && m.MSBaseline == "" && m.ASRID == "" && m.Attack == ""
		if empty {
			t.Errorf("%s icin tum cerceve alanlari bos — anlamsiz eslemeyi kaldirin veya doldurun", id)
		}
	}
}
