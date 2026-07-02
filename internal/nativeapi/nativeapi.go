// Package nativeapi, Win32/registry native okuma sarmalayicilari saglar.
// Plan ilkesi "Native-API onceligi": gpresult/sc/netsh shell-out hem bloklanabilir
// hem lokalize (Turkce) cikti verir; bunun yerine registry/Win32 sayisal okuma.
package nativeapi

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// RegString, HKLM/HKCU vb. altindan string deger okur. Bulunamazsa ("", err).
func RegString(root registry.Key, path, name string) (string, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	return v, err
}

// RegDword, DWORD deger okur.
func RegDword(root registry.Key, path, name string) (uint64, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	return v, err
}

// RegKeyExists, bir registry anahtarinin var olup olmadigini doner.
func RegKeyExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// RegValueNames, bir anahtarin deger isimlerini listeler (ASR GUID'leri, exclusion'lar vb.).
func RegValueNames(root registry.Key, path string) ([]string, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadValueNames(-1)
}

// RegStringValues, bir anahtarin tum (deger-adi -> string) ciftlerini doner (best-effort).
func RegStringValues(root registry.Key, path string) (map[string]string, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		if v, _, e := k.GetStringValue(n); e == nil {
			out[n] = v
			continue
		}
		if v, _, e := k.GetIntegerValue(n); e == nil {
			out[n] = fmt.Sprintf("%d", v)
		}
	}
	return out, nil
}

// RegMultiString, REG_MULTI_SZ deger okur.
func RegMultiString(root registry.Key, path, name string) ([]string, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	v, _, err := k.GetStringsValue(name)
	return v, err
}

// RegSubKeys, alt anahtar isimlerini listeler.
func RegSubKeys(root registry.Key, path string) ([]string, error) {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadSubKeyNames(-1)
}

// OSVersion, gercek OS surum/build bilgisini RtlGetVersion ile doner (manifest-shim'den etkilenmez).
func OSVersion() (major, minor, build uint32) {
	type osVersionInfoEx struct {
		osVersionInfoSize uint32
		majorVersion      uint32
		minorVersion      uint32
		buildNumber       uint32
		platformID        uint32
		csdVersion        [128]uint16
		servicePackMajor  uint16
		servicePackMinor  uint16
		suiteMask         uint16
		productType       byte
		reserved          byte
	}
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	proc := ntdll.NewProc("RtlGetVersion")
	var info osVersionInfoEx
	info.osVersionInfoSize = uint32(unsafe.Sizeof(info))
	proc.Call(uintptr(unsafe.Pointer(&info)))
	return info.majorVersion, info.minorVersion, info.buildNumber
}

// IsElevated, mevcut surecin yukseltilmis (admin) token tasiyip tasimadigini doner.
func IsElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	var elevation struct{ TokenIsElevated uint32 }
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &size)
	if err != nil {
		return false
	}
	return elevation.TokenIsElevated != 0
}

// IntegrityLevel, token bütünlük seviyesini metin olarak doner (Low/Medium/High/System).
func IntegrityLevel() string {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return "Unknown"
	}
	defer token.Close()
	var size uint32
	windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return "Unknown"
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], size, &size); err != nil {
		return "Unknown"
	}
	tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	// Integrity RID, SID string'inin son bileseni (S-1-16-XXXX).
	s := tml.Label.Sid.String()
	idx := strings.LastIndex(s, "-")
	if idx < 0 {
		return "Unknown"
	}
	rid := parseUint(s[idx+1:])
	switch {
	case rid < 0x1000:
		return "Untrusted"
	case rid < 0x2000:
		return "Low"
	case rid < 0x3000:
		return "Medium"
	case rid < 0x4000:
		return "High"
	default:
		return "System"
	}
}

func parseUint(s string) uint64 {
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

// CurrentUser, DOMAIN\user formatinda mevcut kullaniciyi doner.
func CurrentUser() string {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		return ""
	}
	account, domain, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s\\%s", domain, account)
}

// Privileges, token uzerindeki privilege isimlerini doner (SeImpersonate, SeDebug vb.).
func Privileges() []string {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil
	}
	defer token.Close()
	var size uint32
	windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], size, &size); err != nil {
		return nil
	}
	priv := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	count := priv.PrivilegeCount
	all := (*[1 << 16]windows.LUIDAndAttributes)(unsafe.Pointer(&priv.Privileges[0]))[:count:count]
	var names []string
	for i := range all {
		luid := all[i].Luid
		var n uint32 = 256
		nameBuf := make([]uint16, n)
		if name := lookupPrivilegeName(&luid, nameBuf, &n); name != "" {
			names = append(names, name)
		}
	}
	return names
}

var (
	advapi32             = windows.NewLazySystemDLL("advapi32.dll")
	procLookupPrivName   = advapi32.NewProc("LookupPrivilegeNameW")
)

// lookupPrivilegeName, bir LUID'i privilege adina cevirir (advapi32 dogrudan cagri).
func lookupPrivilegeName(luid *windows.LUID, buf []uint16, n *uint32) string {
	r, _, _ := procLookupPrivName.Call(
		0,
		uintptr(unsafe.Pointer(luid)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(n)),
	)
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// ServiceRunning, verilen servis adlarindan herhangi biri kayitli/var mi diye registry'den bakar.
// (SCM API yerine pasif registry okuma — gurultu uretmez, Stealth dostu.)
func ServiceInstalled(name string) bool {
	return RegKeyExists(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name)
}

// HasMinifilterAltitude, fltmc benzeri bilgi icin minifilter altitude registry kontrolu (best-effort).
func DriverInstalled(name string) bool {
	return RegKeyExists(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name)
}

// FindProcessID, verilen isimli (ornek "lsass.exe") ilk surecin PID'ini doner.
func FindProcessID(name string) (uint32, bool) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return 0, false
	}
	target := strings.ToLower(name)
	for {
		if strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), target) ||
			strings.ToLower(windows.UTF16ToString(pe.ExeFile[:])) == target {
			return pe.ProcessID, true
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			return 0, false
		}
	}
}

// CanOpenProcessVMRead, verilen PID'e VM_READ ile handle acilabilir mi (LSASS yetenek kontrolu;
// DUMP ALMADAN). Acilabiliyorsa hemen kapatir.
func CanOpenProcessVMRead(pid uint32) (bool, error) {
	const access = windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION
	h, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		return false, err
	}
	windows.CloseHandle(h)
	return true, nil
}

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetLogicalDrives = kernel32.NewProc("GetLogicalDrives")
	procGetDriveTypeW    = kernel32.NewProc("GetDriveTypeW")
)

// Surucu tipleri (GetDriveTypeW donus degerleri).
const (
	DriveUnknown   uint32 = 0
	DriveNoRootDir uint32 = 1
	DriveRemovable uint32 = 2
	DriveFixed     uint32 = 3
	DriveRemote    uint32 = 4
	DriveCDROM     uint32 = 5
	DriveRAMDisk   uint32 = 6
)

// LogicalDrive, bir mantiksal surucu koku ve tipi.
type LogicalDrive struct {
	Root string // or. "D:\\"
	Type uint32
}

// LogicalDrives, sistemdeki mantiksal suruculeri (kok yol + tip) listeler.
// GetLogicalDrives bit maskesi + GetDriveTypeW; native cagri, shell-out yok,
// lokalizasyon-bagimsiz. AppLocker default kurallari %WINDIR%/%PROGRAMFILES%
// disini (ozellikle ikincil disk D:\ ve cikarilabilir USB) kapsamaz; bu yuzden
// surucu envanteri exec-allowed bosluk avi icin gereklidir.
func LogicalDrives() []LogicalDrive {
	mask, _, _ := procGetLogicalDrives.Call()
	var out []LogicalDrive
	for i := uint(0); i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		t, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(p)))
		out = append(out, LogicalDrive{Root: root, Type: uint32(t)})
	}
	return out
}

// NormalizeArch, calisilan mimariyi normalize eder.
func NormalizeArch(s string) string {
	s = strings.ToLower(s)
	switch s {
	case "amd64", "x64":
		return "x64"
	case "386", "x86":
		return "x86"
	case "arm64":
		return "arm64"
	default:
		return s
	}
}
