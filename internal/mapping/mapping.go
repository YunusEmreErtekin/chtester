// Package mapping, bulgulari CIS / MS Security Baseline / ASR / MITRE ATT&CK'e baglar.
// Faz 1'de iskelet + bilinen birkac eslemе; vektorler yazildikca genisletilir.
package mapping

import "chtester/internal/schema"

// table, Test-ID -> cerceve eslemesi. Modul yazarken buraya eklenir.
var table = map[string]schema.Mapping{
	"CHT-00-006": {Attack: "T1059.001", CIS: "18.9.x PowerShell"}, // PS LanguageMode
	"CHT-00-008": {Attack: "T1518.001"},                           // EDR/AV tespiti
	"CHT-02-001": {CIS: "AppLocker", MSBaseline: "Application Control", Attack: "T1218"},
	"CHT-03-002": {ASRID: "ASR-multiple", Attack: "T1562.001"},
}

// For, verilen Test-ID icin eslemeyi doner (yoksa bos Mapping).
func For(testID string) schema.Mapping {
	return table[testID]
}
