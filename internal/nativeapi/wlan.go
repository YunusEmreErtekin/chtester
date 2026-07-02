// wlan.go, kayitli WLAN profillerini ve duz-metin PSK kurtarilabilirligini
// native WlanAPI (wlanapi.dll) ile okur. Plan ilkesi geregi netsh shell-out YOK:
// lokalizasyon-bagimsiz, ConstrainedLanguage/AppLocker-script kisitlamalarindan
// etkilenmez. Secret DONMEZ — yalniz "duz-metin anahtar okunabildi mi" bayragi.
package nativeapi

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wlanapi                = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle     = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = wlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanGetProfileList = wlanapi.NewProc("WlanGetProfileList")
	procWlanGetProfile     = wlanapi.NewProc("WlanGetProfile")
	procWlanFreeMemory     = wlanapi.NewProc("WlanFreeMemory")
)

type wlanInterfaceInfo struct {
	InterfaceGUID           windows.GUID
	strInterfaceDescription [256]uint16
	isState                 uint32
}

type wlanInterfaceInfoList struct {
	dwNumberOfItems uint32
	dwIndex         uint32
	InterfaceInfo   [1]wlanInterfaceInfo
}

type wlanProfileInfo struct {
	strProfileName [256]uint16
	dwFlags        uint32
}

type wlanProfileInfoList struct {
	dwNumberOfItems uint32
	dwIndex         uint32
	ProfileInfo     [1]wlanProfileInfo
}

const wlanProfileGetPlaintextKey = 4 // WLAN_PROFILE_GET_PLAINTEXT_KEY

// WiFiProfile, bir WLAN profili: PSK duz-metin okunabilirligi + guvenlik/baglanma turu.
type WiFiProfile struct {
	SSID        string
	HasClearKey bool
	Auth        string // <authentication>: open|WPA2PSK|WPA2|WPA3SAE|...
	AutoConnect bool   // <connectionMode>=auto (menzile girince otomatik baglan)
}

// WiFiProfiles, kayitli WLAN profillerini ve her birinin duz-metin anahtarinin
// (keyMaterial) kurtarilip kurtarilamadigini doner. ikinci donus: WLAN altyapisi
// kullanilabilir mi (false => WLAN servisi/arabirimi yok, NotApplicable).
func WiFiProfiles() ([]WiFiProfile, bool) {
	var clientHandle windows.Handle
	var negotiated uint32
	r, _, _ := procWlanOpenHandle.Call(2, 0,
		uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&clientHandle)))
	if r != 0 {
		return nil, false
	}
	defer procWlanCloseHandle.Call(uintptr(clientHandle), 0)

	var ifaceList *wlanInterfaceInfoList
	r, _, _ = procWlanEnumInterfaces.Call(uintptr(clientHandle), 0,
		uintptr(unsafe.Pointer(&ifaceList)))
	if r != 0 || ifaceList == nil {
		return nil, false
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(ifaceList)))

	ifaces := unsafe.Slice(&ifaceList.InterfaceInfo[0], ifaceList.dwNumberOfItems)
	var out []WiFiProfile
	for i := range ifaces {
		guid := ifaces[i].InterfaceGUID
		var profList *wlanProfileInfoList
		r, _, _ = procWlanGetProfileList.Call(uintptr(clientHandle),
			uintptr(unsafe.Pointer(&guid)), 0, uintptr(unsafe.Pointer(&profList)))
		if r != 0 || profList == nil {
			continue
		}
		profs := unsafe.Slice(&profList.ProfileInfo[0], profList.dwNumberOfItems)
		for j := range profs {
			name := windows.UTF16ToString(profs[j].strProfileName[:])
			if name == "" {
				continue
			}
			auth, auto := profileSecurity(clientHandle, &guid, name)
			out = append(out, WiFiProfile{
				SSID: name, HasClearKey: profileHasClearKey(clientHandle, &guid, name),
				Auth: auth, AutoConnect: auto,
			})
		}
		procWlanFreeMemory.Call(uintptr(unsafe.Pointer(profList)))
	}
	return out, true
}

// profileHasClearKey, tek bir profilin XML'ini WLAN_PROFILE_GET_PLAINTEXT_KEY ile
// ister ve <keyMaterial> dolu mu diye bakar (anahtarin kendisi DONMEZ).
func profileHasClearKey(h windows.Handle, guid *windows.GUID, name string) bool {
	pn, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false
	}
	var xmlPtr *uint16
	flags := uint32(wlanProfileGetPlaintextKey)
	var access uint32
	r, _, _ := procWlanGetProfile.Call(uintptr(h), uintptr(unsafe.Pointer(guid)),
		uintptr(unsafe.Pointer(pn)), 0, uintptr(unsafe.Pointer(&xmlPtr)),
		uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&access)))
	if r != 0 || xmlPtr == nil {
		return false
	}
	xml := windows.UTF16PtrToString(xmlPtr)
	procWlanFreeMemory.Call(uintptr(unsafe.Pointer(xmlPtr)))
	return extractTag(xml, "keyMaterial") != ""
}

// profileSecurity, profil XML'inden <authentication> ve <connectionMode> cikarir
// (anahtar ISTEMEZ — plaintext bayragi yok). auth, autoConnect doner.
func profileSecurity(h windows.Handle, guid *windows.GUID, name string) (auth string, autoConnect bool) {
	pn, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", false
	}
	var xmlPtr *uint16
	var flags, access uint32
	r, _, _ := procWlanGetProfile.Call(uintptr(h), uintptr(unsafe.Pointer(guid)),
		uintptr(unsafe.Pointer(pn)), 0, uintptr(unsafe.Pointer(&xmlPtr)),
		uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&access)))
	if r != 0 || xmlPtr == nil {
		return "", false
	}
	xml := windows.UTF16PtrToString(xmlPtr)
	procWlanFreeMemory.Call(uintptr(unsafe.Pointer(xmlPtr)))
	return extractTag(xml, "authentication"), extractTag(xml, "connectionMode") == "auto"
}

// extractTag, <tag>...</tag> arasini doner (yoksa "").
func extractTag(xml, tag string) string {
	open, close := "<"+tag+">", "</"+tag+">"
	i := strings.Index(xml, open)
	if i < 0 {
		return ""
	}
	i += len(open)
	j := strings.Index(xml[i:], close)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(xml[i : i+j])
}
