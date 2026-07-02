// wmi.go, ucuncu-parti bagimlilik OLMADAN (yalniz x/sys) minimal bir WMI/COM
// istemcisi saglar. Registry'nin soyleyemedigi "yapilandirilmis degil, CALISIYOR"
// durumlarini (Win32_DeviceGuard, Win32_EncryptableVolume) yetkili okur.
//
// Kapsam: tek namespace, tek WQL sorgu, scalar (BSTR/I4/UI4/BOOL) + uint32 dizi
// (VT_ARRAY|VT_I4/UI4 SAFEARRAY) property'leri string'e cevirir.
//
// NOT (go vet): bu dosya, COM out-param adreslerini syscall'a gecirirken 3 adet
// "possible misuse of unsafe.Pointer" UYARISI uretir. Bu, Go'da el-yazimi COM
// vtable dispatch'inin bilinen ve KACINILMAZ bir durumudur (uintptr<->Pointer
// donusumunun bir tarafi her zaman tetiklenir). Donusumler GUVENLIDIR: COM
// nesneleri unmanaged bellekte yasar ve out-param'lar senkron syscall sirasinda
// (GC safepoint'i olmadan) doldurulur. Uyarilar derlemeyi/dogrulugu etkilemez;
// build-package.ps1 zaten go vet calistirmaz.
package nativeapi

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modole32      = windows.NewLazySystemDLL("ole32.dll")
	modoleaut32   = windows.NewLazySystemDLL("oleaut32.dll")
	procCoInit    = modole32.NewProc("CoInitializeEx")
	procCoUninit  = modole32.NewProc("CoUninitialize")
	procCoInitSec = modole32.NewProc("CoInitializeSecurity")
	procCoCreate  = modole32.NewProc("CoCreateInstance")
	procCoSetBlkt = modole32.NewProc("CoSetProxyBlanket")
	procSysAlloc  = modoleaut32.NewProc("SysAllocString")
	procSysFree   = modoleaut32.NewProc("SysFreeString")
	procVarClear  = modoleaut32.NewProc("VariantClear")
)

// COM/WMI sabitleri
const (
	coinitMultithreaded = 0x0
	clsctxInprocServer  = 0x1

	rpcAuthnLevelCall  = 3
	rpcImpLevelImpers  = 3
	rpcAuthnWinnt      = 10
	rpcAuthzNone       = 0
	eoacNone           = 0

	wbemFlagForwardOnly       = 0x20
	wbemFlagReturnImmediately = 0x10
	wbemInfinite              = 0xFFFFFFFF
)

// COM vtable indeksleri (IUnknown: 0 QI,1 AddRef,2 Release)
const (
	idxLocatorConnectServer = 3  // IWbemLocator
	idxServicesExecQuery    = 20 // IWbemServices
	idxEnumNext             = 4  // IEnumWbemClassObject (QI,AddRef,Release,Reset,Next)
	idxObjectGet            = 4  // IWbemClassObject (QI,AddRef,Release,GetQualifierSet,Get)
	idxRelease              = 2
)

// vtblMethod, bir COM arayuz isaretcisinin vtable'indaki idx. metodun kod adresini
// (uintptr) doner. Yalniz Pointer->Pointer ve depolanmis bir uintptr-deger okumasi
// yapar (pointer'i uintptr'e CEVIRMEZ) — go vet temiz.
func vtblMethod(this unsafe.Pointer, idx int) uintptr {
	vtbl := *(*unsafe.Pointer)(this)
	return *(*uintptr)(unsafe.Add(vtbl, uintptr(idx)*unsafe.Sizeof(uintptr(0))))
}

// Not: vtable cagrilarinda sabit-arity syscall.Syscall/Syscall6/Syscall9 kullanilir.
// Bunlar "deprecated" isaretli olsa da go vet'in unsafe.Pointer whitelist'indedir
// (SyscallN degildir); cekirdegin temiz vet'ini korumak icin tercih edildi.
func comRelease(this unsafe.Pointer) {
	if this != nil {
		syscall.Syscall(vtblMethod(this, idxRelease), 1, uintptr(this), 0, 0)
	}
}

func sysString(s string) uintptr {
	p, _ := windows.UTF16PtrFromString(s)
	r, _, _ := procSysAlloc.Call(uintptr(unsafe.Pointer(p)))
	return r
}

// variant, OLE VARIANT (24 bayt; vt@0, veri birligi@8 — tum mimarilerde).
type variant struct {
	vt       uint16
	r1, r2, r3 uint16
	val      [16]byte
}

type safeArrayBound struct {
	cElements uint32
	lLbound   int32
}
type safeArray struct {
	cDims      uint16
	fFeatures  uint16
	cbElements uint32
	cLocks     uint32
	pvData     uintptr
	bounds     [1]safeArrayBound
}

const (
	vtNull   = 1
	vtI4     = 3
	vtBool   = 11
	vtUI4    = 19
	vtBStr   = 8
	vtArray  = 0x2000
)

// variantToString, bir VARIANT'i okunur string'e cevirir (BSTR/I4/UI4/BOOL/uint32-dizi).
func variantToString(v *variant) string {
	switch {
	case v.vt == vtBStr:
		p := *(*uintptr)(unsafe.Pointer(&v.val[0]))
		if p == 0 {
			return ""
		}
		return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(p)))
	case v.vt == vtI4:
		return fmt.Sprintf("%d", *(*int32)(unsafe.Pointer(&v.val[0])))
	case v.vt == vtUI4:
		return fmt.Sprintf("%d", *(*uint32)(unsafe.Pointer(&v.val[0])))
	case v.vt == vtBool:
		if *(*int16)(unsafe.Pointer(&v.val[0])) != 0 {
			return "true"
		}
		return "false"
	case v.vt&vtArray != 0:
		psa := *(*uintptr)(unsafe.Pointer(&v.val[0]))
		if psa == 0 {
			return ""
		}
		sa := (*safeArray)(unsafe.Pointer(psa))
		n := sa.bounds[0].cElements
		if n == 0 || sa.pvData == 0 {
			return ""
		}
		elems := unsafe.Slice((*int32)(unsafe.Pointer(sa.pvData)), n)
		parts := make([]string, 0, n)
		for _, e := range elems {
			parts = append(parts, fmt.Sprintf("%d", e))
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

// rpcEChangedMode, COM apartment'i bu thread'de zaten FARKLI modda baslatilmis demektir
// (ornek -gui STA thread'i). Bu durumda CoUninitialize CAGRILMAMALIDIR — apartment'i
// baska kod yonetiyor.
const rpcEChangedMode = 0x80010106

// wmiInit, COM'u baslatir ve CoUninitialize ile dengelenmesi gerekip gerekmedigini doner.
// CoInitializeSecurity bir kez cagrilabilir; "cok gec/degisti" hatalari yutulur.
func wmiInit() (needUninit bool) {
	hr, _, _ := procCoInit.Call(0, coinitMultithreaded)
	// S_OK(0)/S_FALSE(1) => bu cagri apartment'i baslatti/refcount artirdi, dengele.
	// RPC_E_CHANGED_MODE => apartment baska modda zaten var, DOKUNMA.
	needUninit = uint32(hr) != rpcEChangedMode
	procCoInitSec.Call(0, ^uintptr(0), 0, 0, 0, rpcImpLevelImpers, 0, eoacNone, 0)
	return needUninit
}

// WMIQuery, namespace altinda WQL sorgusunu calistirir; istenen property'leri her
// satir icin map[ad]deger olarak doner. Hata olursa (err) ile.
//
// COM apartment thread-basinadir: goroutine'in COM cagrilari arasinda baska bir OS
// thread'ine tasinmamasi icin thread KILITLENIR (LockOSThread). Aksi halde cagrilar
// CoInitialize edilmemis bir thread'de kosabilir (kararsiz okuma/cokme).
func WMIQuery(namespace, wql string, props []string) ([]map[string]string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if wmiInit() {
		defer procCoUninit.Call()
	}

	clsid, err := windows.GUIDFromString("{4590F811-1D3A-11D0-891F-00AA004B2E24}") // CLSID_WbemLocator
	if err != nil {
		return nil, err
	}
	iid, err := windows.GUIDFromString("{DC12A687-737F-11CF-884D-00AA004B2E24}") // IID_IWbemLocator
	if err != nil {
		return nil, err
	}
	var locator unsafe.Pointer
	r, _, _ := procCoCreate.Call(uintptr(unsafe.Pointer(&clsid)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&locator)))
	if int32(r) < 0 || locator == nil {
		return nil, fmt.Errorf("CoCreateInstance(WbemLocator) hr=0x%x", uint32(r))
	}
	defer comRelease(locator)

	bNs := sysString(namespace)
	defer procSysFree.Call(bNs)
	var services unsafe.Pointer
	hr, _, _ := syscall.Syscall9(vtblMethod(locator, idxLocatorConnectServer), 9,
		uintptr(locator), bNs, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&services)))
	if int32(hr) < 0 || services == nil {
		return nil, fmt.Errorf("ConnectServer(%s) hr=0x%x", namespace, uint32(hr))
	}
	defer comRelease(services)

	procCoSetBlkt.Call(uintptr(services), rpcAuthnWinnt, rpcAuthzNone, 0, rpcAuthnLevelCall, rpcImpLevelImpers, 0, eoacNone)

	bLang := sysString("WQL")
	defer procSysFree.Call(bLang)
	bQuery := sysString(wql)
	defer procSysFree.Call(bQuery)
	var enum unsafe.Pointer
	hr, _, _ = syscall.Syscall6(vtblMethod(services, idxServicesExecQuery), 6,
		uintptr(services), bLang, bQuery, wbemFlagForwardOnly|wbemFlagReturnImmediately, 0, uintptr(unsafe.Pointer(&enum)))
	if int32(hr) < 0 || enum == nil {
		return nil, fmt.Errorf("ExecQuery hr=0x%x", uint32(hr))
	}
	defer comRelease(enum)

	// property adlarini UTF16'ya onceden cevir
	pw := make([]*uint16, len(props))
	for i, p := range props {
		pw[i], _ = windows.UTF16PtrFromString(p)
	}

	var rows []map[string]string
	for {
		var obj unsafe.Pointer
		var returned uint32
		nhr, _, _ := syscall.Syscall6(vtblMethod(enum, idxEnumNext), 5,
			uintptr(enum), wbemInfinite, 1, uintptr(unsafe.Pointer(&obj)), uintptr(unsafe.Pointer(&returned)), 0)
		if returned == 0 || obj == nil {
			break
		}
		row := make(map[string]string, len(props))
		for i, namePtr := range pw {
			var v variant
			ghr, _, _ := syscall.Syscall6(vtblMethod(obj, idxObjectGet), 6,
				uintptr(obj), uintptr(unsafe.Pointer(namePtr)), 0, uintptr(unsafe.Pointer(&v)), 0, 0)
			if int32(ghr) >= 0 && v.vt != vtNull && v.vt != 0 {
				row[props[i]] = variantToString(&v)
			} else {
				row[props[i]] = ""
			}
			procVarClear.Call(uintptr(unsafe.Pointer(&v)))
		}
		rows = append(rows, row)
		comRelease(obj)
		if int32(nhr) != 0 { // WBEM_S_FALSE => son
			break
		}
	}
	return rows, nil
}
