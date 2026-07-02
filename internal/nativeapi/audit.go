// audit.go, gelismis denetim (advanced audit) politikasini native AuditQuerySystemPolicy
// (advapi32) ile okur. Shell-out (auditpol) YOK. Sistem politikasini okumak
// SeSecurityPrivilege ister (genelde admin); standart kullanicida sorgu basarisiz olur
// ve cagiran Partial isaretler.
package nativeapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procAuditQuerySystemPolicy = advapi32.NewProc("AuditQuerySystemPolicy")
	procAuditFree              = advapi32.NewProc("AuditFree")
)

// auditPolicyInformation, AUDIT_POLICY_INFORMATION ile ayni yerlesim.
type auditPolicyInformation struct {
	AuditSubCategoryGuid windows.GUID
	AuditingInformation  uint32 // bit0=Success, bit1=Failure
	AuditCategoryGuid    windows.GUID
}

// AuditSetting, tek bir denetim alt-kategorisinin durumu.
type AuditSetting struct {
	Name    string
	Success bool
	Failure bool
}

// wellKnownAuditSubcategories, kritik alt-kategori GUID'leri (sabit, lokalize degil).
var wellKnownAuditSubcategories = []struct {
	name string
	guid string
}{
	{"Process Creation", "{0CCE922B-69AE-11D9-BED3-505054503030}"},
	{"Logon", "{0CCE9215-69AE-11D9-BED3-505054503030}"},
	{"Logoff", "{0CCE9216-69AE-11D9-BED3-505054503030}"},
	{"Audit Policy Change", "{0CCE922F-69AE-11D9-BED3-505054503030}"},
	{"File System (Object Access)", "{0CCE921D-69AE-11D9-BED3-505054503030}"},
	{"Registry (Object Access)", "{0CCE921E-69AE-11D9-BED3-505054503030}"},
}

// AdvancedAuditPolicy, kritik alt-kategorilerin denetim durumunu doner. ok=false ise
// politika okunamadi (genelde SeSecurityPrivilege/admin gerekir).
func AdvancedAuditPolicy() (settings []AuditSetting, ok bool) {
	n := len(wellKnownAuditSubcategories)
	guids := make([]windows.GUID, n)
	for i, sc := range wellKnownAuditSubcategories {
		g, err := windows.GUIDFromString(sc.guid)
		if err != nil {
			return nil, false
		}
		guids[i] = g
	}
	var pPolicy uintptr
	r, _, _ := procAuditQuerySystemPolicy.Call(
		uintptr(unsafe.Pointer(&guids[0])), uintptr(n), uintptr(unsafe.Pointer(&pPolicy)))
	if r == 0 || pPolicy == 0 {
		return nil, false
	}
	defer procAuditFree.Call(pPolicy)
	arr := unsafe.Slice((*auditPolicyInformation)(unsafe.Pointer(pPolicy)), n)
	for i := range arr {
		settings = append(settings, AuditSetting{
			Name:    wellKnownAuditSubcategories[i].name,
			Success: arr[i].AuditingInformation&1 != 0,
			Failure: arr[i].AuditingInformation&2 != 0,
		})
	}
	return settings, true
}

// HasPrivilege, mevcut token uzerinde verilen privilege var mi (ornek SeSecurityPrivilege).
func HasPrivilege(name string) bool {
	for _, p := range Privileges() {
		if p == name {
			return true
		}
	}
	return false
}
