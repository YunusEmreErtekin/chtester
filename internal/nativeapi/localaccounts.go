// localaccounts.go, yerel hesaplari native NetUserEnum (netapi32) ile sayar ve built-in
// Administrator (RID 500) / Guest (RID 501) durumunu SID/RID uzerinden (lokalize ad
// bagimsiz) tespit eder. Shell-out (net user) YOK.
package nativeapi

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procNetUserEnum              = modnetapi32.NewProc("NetUserEnum")
	procNetLocalGroupGetMembers  = modnetapi32.NewProc("NetLocalGroupGetMembers")
)

const (
	filterNormalAccount = 0x0002     // FILTER_NORMAL_ACCOUNT
	userPrivAdmin       = 2          // USER_PRIV_ADMIN
	ufAccountDisable    = 0x0002     // UF_ACCOUNTDISABLE
	maxPreferredLength  = 0xFFFFFFFF // MAX_PREFERRED_LENGTH
)

// userInfo1, USER_INFO_1 ile ayni yerlesim (amd64 + 386 uyumlu).
type userInfo1 struct {
	name        *uint16
	password    *uint16
	passwordAge uint32
	priv        uint32
	homeDir     *uint16
	comment     *uint16
	flags       uint32
	scriptPath  *uint16
}

// LocalAccountsInfo, yerel hesap duruşunun ozeti.
type LocalAccountsInfo struct {
	OK                  bool
	Total               int
	EnabledAdmins       int      // priv=admin VE etkin yerel hesaplar
	BuiltinAdminEnabled bool     // RID 500 etkin mi
	BuiltinAdminName    string   // yeniden adlandirilmis mi (RID 500'un adi)
	GuestEnabled        bool     // RID 501 etkin mi
	AdminNames          []string // etkin admin hesap adlari
}

// LocalAccounts, yerel hesaplari sayar (NetUserEnum level 1) ve built-in RID'lerini cozer.
func LocalAccounts() LocalAccountsInfo {
	var buf uintptr
	var read, total uint32
	var resume uintptr
	r, _, _ := procNetUserEnum.Call(0, 1, filterNormalAccount,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r != 0 || buf == 0 {
		return LocalAccountsInfo{}
	}
	defer procNetApiBufferFree.Call(buf)
	info := LocalAccountsInfo{OK: true, Total: int(read)}
	arr := unsafe.Slice((*userInfo1)(unsafe.Pointer(buf)), read)
	for i := range arr {
		name := windows.UTF16PtrToString(arr[i].name)
		disabled := arr[i].flags&ufAccountDisable != 0
		if arr[i].priv == userPrivAdmin && !disabled {
			info.EnabledAdmins++
			info.AdminNames = append(info.AdminNames, name)
		}
		switch rid, ok := userRID(name); {
		case !ok:
			// SID cozulemedi; atla
		case rid == 500:
			info.BuiltinAdminName = name
			info.BuiltinAdminEnabled = !disabled
		case rid == 501:
			info.GuestEnabled = !disabled
		}
	}
	return info
}

// localGroupMembersInfo2, LOCALGROUP_MEMBERS_INFO_2 ile ayni yerlesim.
type localGroupMembersInfo2 struct {
	sid           *windows.SID
	sidUsage      uint32
	domainAndName *uint16 // "DOMAIN\\ad" — ic ice AD gruplari dahil
}

// AdminMember, yerel Administrators grubunun tek bir uyesi.
type AdminMember struct {
	Name string // DOMAIN\ad veya MAKINE\ad
	Type string // Kullanici | Grup | Diger
}

// LocalAdminInfo, yerel Administrators grubunun tam uyeligi.
type LocalAdminInfo struct {
	OK      bool
	Members []AdminMember
}

// LocalAdminMembers, yerel Administrators grubunun (well-known SID S-1-5-32-544)
// TUM uyelerini NetLocalGroupGetMembers (level 2) ile listeler. Grup adi lokalize
// oldugundan once SID'den cozulur; boylece iç içe AD gruplari (ör. "CORP\Domain
// Admins") da yakalanir. Shell-out YOK.
func LocalAdminMembers() LocalAdminInfo {
	sid, err := windows.StringToSid("S-1-5-32-544") // BUILTIN\Administrators
	if err != nil {
		return LocalAdminInfo{}
	}
	name, _, _, err := sid.LookupAccount("")
	if err != nil || name == "" {
		return LocalAdminInfo{}
	}
	groupPtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return LocalAdminInfo{}
	}
	var buf uintptr
	var read, total uint32
	var resume uintptr
	r, _, _ := procNetLocalGroupGetMembers.Call(0,
		uintptr(unsafe.Pointer(groupPtr)), 2,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r != 0 || buf == 0 {
		return LocalAdminInfo{}
	}
	defer procNetApiBufferFree.Call(buf)
	out := LocalAdminInfo{OK: true}
	arr := unsafe.Slice((*localGroupMembersInfo2)(unsafe.Pointer(buf)), read)
	for i := range arr {
		out.Members = append(out.Members, AdminMember{
			Name: windows.UTF16PtrToString(arr[i].domainAndName),
			Type: sidUsageName(arr[i].sidUsage),
		})
	}
	return out
}

// sidUsageName, SID_NAME_USE degerini Turkce etikete cevirir.
func sidUsageName(u uint32) string {
	switch u {
	case 1: // SidTypeUser
		return "Kullanıcı"
	case 2, 4, 5: // Group, Alias, WellKnownGroup
		return "Grup"
	default:
		return "Diğer"
	}
}

// userRID, yerel hesabin SID'inden RID'i (son alt-yetki) doner (built-in tespiti icin).
func userRID(name string) (uint64, bool) {
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		return 0, false
	}
	s := sid.String()
	i := strings.LastIndexByte(s, '-')
	if i < 0 {
		return 0, false
	}
	return parseUint(s[i+1:]), true
}
