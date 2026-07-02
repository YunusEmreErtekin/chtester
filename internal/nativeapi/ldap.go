// ldap.go, salt-okunur Active Directory enumerasyonunu native wldap32.dll ile yapar.
// Plan ilkesi: shell-out YOK (PowerShell AD modulu / dsquery gerektirmez), entegre
// kimlikle (mevcut domain kullanicisi) baglanir. YALNIZ SAYIM doner — kullanici adi/
// secret toplamaz. Yalniz domain'e bagli cihazda anlamlidir.
//
// NOT: Bu modul domain ortami gerektirdiginden gelistirme makinesinde (Workgroup)
// dogrulanamaz; sahada domain'e bagli cihazda teyit edilmelidir. Tum cagrilar hata-
// korumalidir ve basarisizlikta OK=false doner (panik uretmez).
package nativeapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wldap32              = windows.NewLazySystemDLL("wldap32.dll")
	procLdapInit         = wldap32.NewProc("ldap_initW")
	procLdapSetOption    = wldap32.NewProc("ldap_set_optionW")
	procLdapConnect      = wldap32.NewProc("ldap_connect")
	procLdapBindS        = wldap32.NewProc("ldap_bind_sW")
	procLdapSearchS      = wldap32.NewProc("ldap_search_sW")
	procLdapCountEntries = wldap32.NewProc("ldap_count_entries")
	procLdapFirstEntry   = wldap32.NewProc("ldap_first_entry")
	procLdapGetValues    = wldap32.NewProc("ldap_get_valuesW")
	procLdapValueFree    = wldap32.NewProc("ldap_value_freeW")
	procLdapMsgFree      = wldap32.NewProc("ldap_msgfree")
	procLdapUnbind       = wldap32.NewProc("ldap_unbind")
)

const (
	ldapPort            = 389
	ldapScopeBase       = 0
	ldapScopeSubtree    = 2
	ldapOptProtocolVer  = 0x11
	ldapVersion3        = 3
	ldapAuthNegotiate   = 0x0486 // LDAP_AUTH_NEGOTIATE (entegre/SSPI)
	ldapSuccess         = 0
)

// ADStats, salt-okunur AD enumerasyon sonucu (yalniz sayilar).
type ADStats struct {
	OK                          bool
	BaseDN                      string
	Users                       int
	Computers                   int
	Groups                      int
	Kerberoastable              int // SPN'li etkin kullanici hesaplari (T1558.003)
	ASREPRoastable              int // DONT_REQ_PREAUTH (T1558.004)
	UnconstrainedDelegation     int // TRUSTED_FOR_DELEGATION (T1187/T1134)
	ADCSTemplates               int
	ADCSEnrolleeSuppliesSubject int // ESC1 yuzeyi (T1649)
}

func u16ptr(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

// noAttrsArray, LDAP aramasinda "hicbir attribute dondurme" (OID 1.1) icin PWSTR dizisi.
// Sayim icin yeterli, agi/bellegi hafif tutar.
func noAttrsArray() *uint16 {
	// {"1.1", NULL}
	arr := []*uint16{u16ptr("1.1"), nil}
	return (*uint16)(unsafe.Pointer(&arr[0]))
}

// ldapCount, base altinda filter ile eslesen girdi sayisini doner.
func ldapCount(ld uintptr, base, filter string) (int, bool) {
	var basePtr unsafe.Pointer
	if base != "" {
		basePtr = unsafe.Pointer(u16ptr(base))
	}
	attrs := noAttrsArray()
	var res uintptr
	rc, _, _ := procLdapSearchS.Call(
		ld, uintptr(basePtr), ldapScopeSubtree,
		uintptr(unsafe.Pointer(u16ptr(filter))), uintptr(unsafe.Pointer(&attrs)), 0,
		uintptr(unsafe.Pointer(&res)))
	if rc != ldapSuccess || res == 0 {
		if res != 0 {
			procLdapMsgFree.Call(res)
		}
		return 0, false
	}
	n, _, _ := procLdapCountEntries.Call(ld, res)
	procLdapMsgFree.Call(res)
	return int(int32(n)), true
}

// rootDSEValue, rootDSE'den tek-degerli bir attribute okur (defaultNamingContext vb.).
func rootDSEValue(ld uintptr, attr string) string {
	attrs := []*uint16{u16ptr(attr), nil}
	var res uintptr
	rc, _, _ := procLdapSearchS.Call(
		ld, 0, ldapScopeBase,
		uintptr(unsafe.Pointer(u16ptr("(objectClass=*)"))),
		uintptr(unsafe.Pointer(&attrs[0])), 0, uintptr(unsafe.Pointer(&res)))
	if rc != ldapSuccess || res == 0 {
		if res != 0 {
			procLdapMsgFree.Call(res)
		}
		return ""
	}
	defer procLdapMsgFree.Call(res)
	entry, _, _ := procLdapFirstEntry.Call(ld, res)
	if entry == 0 {
		return ""
	}
	vals, _, _ := procLdapGetValues.Call(ld, entry, uintptr(unsafe.Pointer(u16ptr(attr))))
	if vals == 0 {
		return ""
	}
	defer procLdapValueFree.Call(vals)
	first := *(**uint16)(unsafe.Pointer(vals))
	if first == nil {
		return ""
	}
	return windows.UTF16PtrToString(first)
}

// ADEnumerate, mevcut domain kullanicisi baglamiyla DC'ye baglanip salt-okunur sayim yapar.
func ADEnumerate() ADStats {
	var ld uintptr
	// Serverless bind: NULL host => mevcut domain DC'si bulunur.
	ld, _, _ = procLdapInit.Call(0, ldapPort)
	if ld == 0 {
		return ADStats{}
	}
	defer procLdapUnbind.Call(ld)

	ver := uintptr(ldapVersion3)
	procLdapSetOption.Call(ld, ldapOptProtocolVer, uintptr(unsafe.Pointer(&ver)))
	procLdapConnect.Call(ld, 0)
	if rc, _, _ := procLdapBindS.Call(ld, 0, 0, ldapAuthNegotiate); rc != ldapSuccess {
		return ADStats{}
	}

	base := rootDSEValue(ld, "defaultNamingContext")
	if base == "" {
		return ADStats{}
	}
	st := ADStats{OK: true, BaseDN: base}
	st.Users, _ = ldapCount(ld, base, "(&(objectCategory=person)(objectClass=user))")
	st.Computers, _ = ldapCount(ld, base, "(objectCategory=computer)")
	st.Groups, _ = ldapCount(ld, base, "(objectCategory=group)")
	// SPN'li etkin kullanici hesaplari (Kerberoast yuzeyi), makine hesaplari haric.
	st.Kerberoastable, _ = ldapCount(ld, base,
		"(&(servicePrincipalName=*)(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
	// DONT_REQ_PREAUTH (AS-REP roast)
	st.ASREPRoastable, _ = ldapCount(ld, base,
		"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))")
	// TRUSTED_FOR_DELEGATION (unconstrained delegation)
	st.UnconstrainedDelegation, _ = ldapCount(ld, base,
		"(userAccountControl:1.2.840.113556.1.4.803:=524288)")

	// ADCS sertifika sablonlari (Configuration NC altinda)
	if cfg := rootDSEValue(ld, "configurationNamingContext"); cfg != "" {
		ctBase := "CN=Certificate Templates,CN=Public Key Services,CN=Services," + cfg
		st.ADCSTemplates, _ = ldapCount(ld, ctBase, "(objectClass=pKICertificateTemplate)")
		// ESC1 yuzeyi: ENROLLEE_SUPPLIES_SUBJECT (msPKI-Certificate-Name-Flag bit 0x1)
		st.ADCSEnrolleeSuppliesSubject, _ = ldapCount(ld, ctBase,
			"(&(objectClass=pKICertificateTemplate)(msPKI-Certificate-Name-Flag:1.2.840.113556.1.4.804:=1))")
	}
	return st
}

// --- Domain trust enumerasyonu (netapi32) ---

var procDsEnumerateDomainTrusts = modnetapi32.NewProc("DsEnumerateDomainTrustsW")

// DomainTrustCount, cihazin domain'inin guven (trust) sayisini doner (outbound+inbound).
// Forest disi/external trust'lar genis saldiri yuzeyidir. ok=false ise sorgulanamadi.
func DomainTrustCount() (count int, ok bool) {
	const dsDomainDirectOutbound = 0x2
	const dsDomainDirectInbound = 0x20
	var buf uintptr
	var n uint32
	r, _, _ := procDsEnumerateDomainTrusts.Call(0,
		uintptr(dsDomainDirectOutbound|dsDomainDirectInbound),
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r != 0 {
		return 0, false
	}
	if buf != 0 {
		procNetApiBufferFree.Call(buf)
	}
	return int(n), true
}
