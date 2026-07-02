// shares.go, yerel SMB paylasimlarini native NetShareEnum (netapi32, level 2) ile listeler.
// Shell-out (net share) YOK. Admin paylasimlari (C$/ADMIN$/IPC$, STYPE_SPECIAL) ile ozel
// disk paylasimlarini (veri maruziyeti) ayirt eder.
package nativeapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var procNetShareEnum = modnetapi32.NewProc("NetShareEnum")

// shareInfo2, SHARE_INFO_2 ile ayni yerlesim (amd64 + 386 dogal hizalama).
type shareInfo2 struct {
	netname     *uint16
	stype       uint32
	remark      *uint16
	permissions uint32
	maxUses     uint32
	currentUses uint32
	path        *uint16
	passwd      *uint16
}

const stypeSpecial = 0x80000000 // STYPE_SPECIAL: admin/gizli paylasim (C$/ADMIN$/IPC$)

// ShareInfo, tek bir SMB paylasiminin ozeti.
type ShareInfo struct {
	Name    string
	Path    string
	Remark  string
	IsAdmin bool // STYPE_SPECIAL (varsayilan admin/gizli paylasim)
}

// SharesInfo, yerel paylasim envanteri.
type SharesInfo struct {
	OK     bool
	Shares []ShareInfo
}

// LocalShares, yerel SMB paylasimlarini NetShareEnum (level 2) ile listeler.
func LocalShares() SharesInfo {
	var buf uintptr
	var read, total uint32
	var resume uintptr
	r, _, _ := procNetShareEnum.Call(0, 2,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r != 0 || buf == 0 {
		return SharesInfo{}
	}
	defer procNetApiBufferFree.Call(buf)
	out := SharesInfo{OK: true}
	arr := unsafe.Slice((*shareInfo2)(unsafe.Pointer(buf)), read)
	for i := range arr {
		out.Shares = append(out.Shares, ShareInfo{
			Name:    windows.UTF16PtrToString(arr[i].netname),
			Path:    windows.UTF16PtrToString(arr[i].path),
			Remark:  windows.UTF16PtrToString(arr[i].remark),
			IsAdmin: arr[i].stype&stypeSpecial != 0,
		})
	}
	return out
}
