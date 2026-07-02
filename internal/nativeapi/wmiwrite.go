// wmiwrite.go, WMI repository'sine YAZMA (PutInstance/DeleteInstance) yetenegini
// el-yazimi COM ile saglar. Yalniz CHT-05-005 (WMI kalicilik yetenek probu) kullanir.
//
// GUVENLIK MODELI: bu dosya yalnizca tek bir __EventFilter olusturur/siler. Calistirilabilir
// WMI kalicilik icin __EventFilter + (CommandLine/ActiveScript)EventConsumer +
// __FilterToConsumerBinding UCLUSU gerekir; tek basina bir filter HICBIR kod calistirmaz.
// Boylece "root\subscription'a kalicilik nesnesi yazilabiliyor mu" yetenegi, calistirilabilir
// tehdit yaratmadan olculur. Cagiran zinciri ANINDA siler; manifest + invoke-cleanup yedegi var.
//
// vtable indeksleri: idxServicesExecQuery=20 ve idxObjectGet=4 calisan OKUMA yolunda
// (wmi.go) dogrulanmistir; asagidakiler ayni standart IWbemServices/IWbemClassObject
// vtable numaralandirmasinin parcasidir.
package nativeapi

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	idxServicesGetObject      = 6  // IWbemServices::GetObject
	idxServicesPutInstance    = 14 // IWbemServices::PutInstance
	idxServicesDeleteInstance = 16 // IWbemServices::DeleteInstance
	idxObjectPut              = 5  // IWbemClassObject::Put
	idxObjectSpawnInstance    = 15 // IWbemClassObject::SpawnInstance
)

const (
	wbemFlagCreateOnly = 0x2        // WBEM_FLAG_CREATE_ONLY: var olani EZME
	wbemENotFound      = 0x80041002 // WBEM_E_NOT_FOUND
)

// wmiConnect, verilen namespace'e baglanir ve IWbemServices doner. done() COM
// nesnelerini serbest birakir ve gerekirse CoUninitialize cagirir. Cagiran
// runtime.LockOSThread'i SAGLAMALIDIR (COM apartment thread-basina).
func wmiConnect(namespace string) (services unsafe.Pointer, done func(), err error) {
	needUninit := wmiInit()
	rollback := func() {
		if needUninit {
			procCoUninit.Call()
		}
	}
	clsid, err := windows.GUIDFromString("{4590F811-1D3A-11D0-891F-00AA004B2E24}") // CLSID_WbemLocator
	if err != nil {
		rollback()
		return nil, nil, err
	}
	iid, err := windows.GUIDFromString("{DC12A687-737F-11CF-884D-00AA004B2E24}") // IID_IWbemLocator
	if err != nil {
		rollback()
		return nil, nil, err
	}
	var locator unsafe.Pointer
	r, _, _ := procCoCreate.Call(uintptr(unsafe.Pointer(&clsid)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&locator)))
	if int32(r) < 0 || locator == nil {
		rollback()
		return nil, nil, fmt.Errorf("CoCreateInstance(WbemLocator) hr=0x%x", uint32(r))
	}
	bNs := sysString(namespace)
	var svc unsafe.Pointer
	hr, _, _ := syscall.Syscall9(vtblMethod(locator, idxLocatorConnectServer), 9,
		uintptr(locator), bNs, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&svc)))
	procSysFree.Call(bNs)
	if int32(hr) < 0 || svc == nil {
		comRelease(locator)
		rollback()
		return nil, nil, fmt.Errorf("ConnectServer(%s) hr=0x%x", namespace, uint32(hr))
	}
	procCoSetBlkt.Call(uintptr(svc), rpcAuthnWinnt, rpcAuthzNone, 0, rpcAuthnLevelCall, rpcImpLevelImpers, 0, eoacNone)
	done = func() {
		comRelease(svc)
		comRelease(locator)
		rollback()
	}
	return svc, done, nil
}

// bstrVariant, bir BSTR tutan VARIANT olusturur (Put icin). VARIANT verisi @8 (wmi.go ile ayni layout).
func bstrVariant(b uintptr) variant {
	var v variant
	v.vt = vtBStr
	*(*uintptr)(unsafe.Pointer(&v.val[0])) = b
	return v
}

// objectPut, bir IWbemClassObject instance'inin string property'sini yazar.
func objectPut(obj unsafe.Pointer, name, val string) error {
	np, _ := windows.UTF16PtrFromString(name)
	b := sysString(val)
	defer procSysFree.Call(b) // Put VARIANT'i KOPYALAR; BSTR'yi biz serbest birakiriz (VariantClear DEGIL — cift-free olur).
	v := bstrVariant(b)
	hr, _, _ := syscall.Syscall6(vtblMethod(obj, idxObjectPut), 5,
		uintptr(obj), uintptr(unsafe.Pointer(np)), 0, uintptr(unsafe.Pointer(&v)), 0, 0)
	if int32(hr) < 0 {
		return fmt.Errorf("Put(%s) hr=0x%x", name, uint32(hr))
	}
	return nil
}

// WMICreateEventFilter, root\subscription altinda YALNIZ bir __EventFilter olusturur
// (consumer/binding YOK; calistirilabilir kalicilik zinciri olusmaz). query, gecerli
// ama pratikte tetiklenmeyen bir intrinsic-event sorgusu olmalidir.
func WMICreateEventFilter(name, query, eventNamespace string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	svc, done, err := wmiConnect(`root\subscription`)
	if err != nil {
		return err
	}
	defer done()

	bClass := sysString("__EventFilter")
	var classObj unsafe.Pointer
	hr, _, _ := syscall.Syscall6(vtblMethod(svc, idxServicesGetObject), 6,
		uintptr(svc), bClass, 0, 0, uintptr(unsafe.Pointer(&classObj)), 0)
	procSysFree.Call(bClass)
	if int32(hr) < 0 || classObj == nil {
		return fmt.Errorf("GetObject(__EventFilter) hr=0x%x", uint32(hr))
	}
	defer comRelease(classObj)

	var inst unsafe.Pointer
	hr, _, _ = syscall.Syscall(vtblMethod(classObj, idxObjectSpawnInstance), 3,
		uintptr(classObj), 0, uintptr(unsafe.Pointer(&inst)))
	if int32(hr) < 0 || inst == nil {
		return fmt.Errorf("SpawnInstance hr=0x%x", uint32(hr))
	}
	defer comRelease(inst)

	if eventNamespace == "" {
		eventNamespace = `root\cimv2`
	}
	for _, kv := range []struct{ k, v string }{
		{"Name", name},
		{"EventNamespace", eventNamespace},
		{"QueryLanguage", "WQL"},
		{"Query", query},
	} {
		if perr := objectPut(inst, kv.k, kv.v); perr != nil {
			return perr
		}
	}

	// ppCallResult = NULL + RETURN_IMMEDIATELY YOK => TAM SENKRON: hr gercek sonuctur.
	// (Non-NULL ppCallResult verilirse PutInstance S_OK donup gercek durumu call-result'a
	// koyabilir; guvenlik aracinda yazma reddi net gorulmeli, o yuzden NULL geciyoruz.)
	hr, _, _ = syscall.Syscall6(vtblMethod(svc, idxServicesPutInstance), 5,
		uintptr(svc), uintptr(inst), wbemFlagCreateOnly, 0, 0, 0)
	if int32(hr) < 0 {
		return fmt.Errorf("PutInstance(__EventFilter) hr=0x%x", uint32(hr))
	}
	return nil
}

// WMIDeleteEventFilter, ada gore __EventFilter'i siler (geri-alma/temizlik). Zaten yoksa
// hata DONMEZ (idempotent): WBEM_E_NOT_FOUND yutulur.
func WMIDeleteEventFilter(name string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	svc, done, err := wmiConnect(`root\subscription`)
	if err != nil {
		return err
	}
	defer done()

	bPath := sysString(fmt.Sprintf(`__EventFilter.Name="%s"`, name))
	// ppCallResult = NULL => tam senkron; hr gercek sonuc.
	hr, _, _ := syscall.Syscall6(vtblMethod(svc, idxServicesDeleteInstance), 5,
		uintptr(svc), bPath, 0, 0, 0, 0)
	procSysFree.Call(bPath)
	if uint32(hr) == wbemENotFound {
		return nil // zaten yok (idempotent)
	}
	if int32(hr) < 0 {
		return fmt.Errorf("DeleteInstance(__EventFilter) hr=0x%x", uint32(hr))
	}
	return nil
}

// WMIEventFilterExists, ada gore __EventFilter var mi (yazma sonrasi dogrulama). Salt-okunur.
func WMIEventFilterExists(name string) bool {
	rows, err := WMIQuery(`root\subscription`,
		fmt.Sprintf("SELECT Name FROM __EventFilter WHERE Name='%s'", name), []string{"Name"})
	if err != nil {
		return false
	}
	return len(rows) > 0
}
