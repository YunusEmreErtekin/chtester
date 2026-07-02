// tpm.go, TPM varlik+surum bilgisini native TBS (TPM Base Services) ile okur.
// WMI/COM gerekmez, admin gerekmez — Tbsi_GetDeviceInfo yetkili surum doner.
package nativeapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modtbs               = windows.NewLazySystemDLL("tbs.dll")
	procTbsiGetDeviceInfo = modtbs.NewProc("Tbsi_GetDeviceInfo")
)

type tpmDeviceInfo struct {
	structVersion    uint32
	tpmVersion       uint32 // 1=TPM 1.2, 2=TPM 2.0
	tpmInterfaceType uint32
	tpmImpRevision   uint32
}

// TPMInfo, TPM varligi ve surumu.
type TPMInfo struct {
	Present bool
	Version string // "1.2" | "2.0" | ""
}

// TPMVersion, TBS uzerinden TPM bilgisini okur. tbs.dll yoksa/TPM yoksa Present=false.
func TPMVersion() TPMInfo {
	if err := procTbsiGetDeviceInfo.Find(); err != nil {
		return TPMInfo{}
	}
	var info tpmDeviceInfo
	r, _, _ := procTbsiGetDeviceInfo.Call(unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info)))
	if r != 0 { // TBS_SUCCESS=0; aksi halde TPM yok/erisilemez
		return TPMInfo{}
	}
	v := ""
	switch info.tpmVersion {
	case 1:
		v = "1.2"
	case 2:
		v = "2.0"
	}
	return TPMInfo{Present: true, Version: v}
}
