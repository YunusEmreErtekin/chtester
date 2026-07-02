// userrights.go, yerel kullanici-haklari ATAMASINI (privilege assignment) native LSA ile okur:
// hangi hesaplar/gruplar belirli bir hakka (ör. SeDebugPrivilege) sahip. Modules/04-004 yalniz
// MEVCUT token'in privilege'lerine bakar; bu, POLITIKA atamasini (ör. "Users grubu SeDebug'a
// sahip mi") verir. Shell-out YOK.
package nativeapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32lsa               = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy            = modadvapi32lsa.NewProc("LsaOpenPolicy")
	procLsaClose                 = modadvapi32lsa.NewProc("LsaClose")
	procLsaFreeMemory            = modadvapi32lsa.NewProc("LsaFreeMemory")
	procLsaEnumAccountsWithRight = modadvapi32lsa.NewProc("LsaEnumerateAccountsWithUserRight")
)

type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *lsaUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type lsaEnumerationInformation struct {
	Sid *windows.SID
}

const (
	policyViewLocalInformation = 0x00000001
	policyLookupNames          = 0x00000800
)

// AccountsWithRight, verilen kullanici hakkina (ör. "SeDebugPrivilege") sahip hesaplarin
// adlarini (DOMAIN\ad; cozulemezse SID) doner. Hak kimseye atanmamissa/okunamazsa bos doner.
func AccountsWithRight(right string) []string {
	var handle uintptr
	var oa lsaObjectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))
	r, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&oa)),
		policyViewLocalInformation|policyLookupNames, uintptr(unsafe.Pointer(&handle)))
	if r != 0 || handle == 0 {
		return nil
	}
	defer procLsaClose.Call(handle)

	u16, err := windows.UTF16FromString(right)
	if err != nil {
		return nil
	}
	us := lsaUnicodeString{
		Length:        uint16((len(u16) - 1) * 2), // null terminator haric bayt uzunlugu
		MaximumLength: uint16(len(u16) * 2),
		Buffer:        &u16[0],
	}
	var buf uintptr
	var count uint32
	r, _, _ = procLsaEnumAccountsWithRight.Call(handle, uintptr(unsafe.Pointer(&us)),
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&count)))
	if r != 0 || buf == 0 || count == 0 {
		return nil
	}
	defer procLsaFreeMemory.Call(buf)
	arr := unsafe.Slice((*lsaEnumerationInformation)(unsafe.Pointer(buf)), count)
	var out []string
	for i := range arr {
		if arr[i].Sid == nil {
			continue
		}
		name, domain, _, err := arr[i].Sid.LookupAccount("")
		switch {
		case err == nil && domain != "" && name != "":
			out = append(out, domain+`\`+name)
		case err == nil && name != "":
			out = append(out, name)
		default:
			out = append(out, arr[i].Sid.String())
		}
	}
	return out
}
