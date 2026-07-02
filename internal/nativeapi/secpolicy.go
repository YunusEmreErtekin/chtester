// secpolicy.go, yerel hesap parola/kilitleme politikasini native NetUserModalsGet
// (netapi32.dll) ile okur. Shell-out (net accounts) YOK: lokalizasyon-bagimsiz,
// ConstrainedLanguage/AppLocker-script kisitlarindan etkilenmez. Standart kullanici
// okuyabilir. Domain uyesinde yerel SAM modals'ini doner (etkin domain GPO'sunu degil).
package nativeapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modnetapi32          = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserModalsGet = modnetapi32.NewProc("NetUserModalsGet")
	procNetApiBufferFree = modnetapi32.NewProc("NetApiBufferFree")
)

const timeqForever = 0xFFFFFFFF // TIMEQ_FOREVER: parola hic suresi dolmaz

// PasswordPolicy, yerel parola politikasi (USER_MODALS_INFO_0).
type PasswordPolicy struct {
	OK            bool
	MinLength     uint32
	MaxAgeDays    uint32
	NeverExpires  bool
	HistoryLength uint32
}

// LockoutPolicy, yerel hesap kilitleme politikasi (USER_MODALS_INFO_3).
type LockoutPolicy struct {
	OK          bool
	Threshold   uint32 // 0 => kilitleme yok
	DurationSec uint32
	WindowSec   uint32
}

// PasswordPolicyInfo, NetUserModalsGet level 0 ile parola politikasini okur.
func PasswordPolicyInfo() PasswordPolicy {
	var buf uintptr
	r, _, _ := procNetUserModalsGet.Call(0, 0, uintptr(unsafe.Pointer(&buf)))
	if r != 0 || buf == 0 {
		return PasswordPolicy{}
	}
	defer procNetApiBufferFree.Call(buf)
	type info0 struct {
		minLen, maxAge, minAge, forceLogoff, histLen uint32
	}
	p := (*info0)(unsafe.Pointer(buf))
	pp := PasswordPolicy{OK: true, MinLength: p.minLen, HistoryLength: p.histLen}
	if p.maxAge == timeqForever {
		pp.NeverExpires = true
	} else {
		pp.MaxAgeDays = p.maxAge / 86400
	}
	return pp
}

// LockoutPolicyInfo, NetUserModalsGet level 3 ile kilitleme politikasini okur.
func LockoutPolicyInfo() LockoutPolicy {
	var buf uintptr
	r, _, _ := procNetUserModalsGet.Call(0, 3, uintptr(unsafe.Pointer(&buf)))
	if r != 0 || buf == 0 {
		return LockoutPolicy{}
	}
	defer procNetApiBufferFree.Call(buf)
	type info3 struct {
		dur, window, threshold uint32
	}
	p := (*info3)(unsafe.Pointer(buf))
	return LockoutPolicy{OK: true, Threshold: p.threshold, DurationSec: p.dur, WindowSec: p.window}
}
