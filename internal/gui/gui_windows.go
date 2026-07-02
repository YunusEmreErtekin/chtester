//go:build windows

// Package gui, chtester icin minimal native Win32 grafik arayuzu saglar.
// Ek bagimlilik yok (yalniz golang.org/x/sys/windows). Bir pencere + profil secimi
// + "Calistir" butonu + log alani; bitince HTML raporu acar.
package gui

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"chtester/internal/app"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")

	pCreateWindowEx   = user32.NewProc("CreateWindowExW")
	pDefWindowProc    = user32.NewProc("DefWindowProcW")
	pRegisterClassEx  = user32.NewProc("RegisterClassExW")
	pGetMessage       = user32.NewProc("GetMessageW")
	pTranslateMessage = user32.NewProc("TranslateMessage")
	pDispatchMessage  = user32.NewProc("DispatchMessageW")
	pPostQuitMessage  = user32.NewProc("PostQuitMessage")
	pShowWindow       = user32.NewProc("ShowWindow")
	pUpdateWindow     = user32.NewProc("UpdateWindow")
	pSendMessage      = user32.NewProc("SendMessageW")
	pSetWindowText    = user32.NewProc("SetWindowTextW")
	pLoadCursor       = user32.NewProc("LoadCursorW")
	pSetTimer         = user32.NewProc("SetTimer")
	pEnableWindow     = user32.NewProc("EnableWindow")
	pGetSysColorBrush = user32.NewProc("GetSysColorBrush")
	pGetStockObject   = gdi32.NewProc("GetStockObject")
	pSendMessageFont  = user32.NewProc("SendMessageW")
	pGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
)

const (
	wsOverlappedWindow = 0x00CF0000
	wsVisible          = 0x10000000
	wsChild            = 0x40000000
	wsTabstop          = 0x00010000
	wsVScroll          = 0x00200000
	wsBorder           = 0x00800000
	esMultiline        = 0x0004
	esReadonly         = 0x0800
	esAutoVScroll      = 0x0040
	btnAutoCheckbox    = 0x0003
	wmCreate           = 0x0001
	wmDestroy          = 0x0002
	wmCommand          = 0x0111
	wmTimer            = 0x0113
	wmSetFont          = 0x0030
	emReplaceSel       = 0x00C2
	swShow             = 5
	idcArrow           = 32512
	colorBtnFace       = 15
	defaultGUIFont     = 17

	idRunButton  = 1001
	idStealthChk = 1002
	idLogEdit    = 1003
	idTimer      = 1
)

type guiState struct {
	hwndLog     uintptr
	hwndBtn     uintptr
	hwndStealth uintptr
	hFont       uintptr

	mu      sync.Mutex
	pending []string
	running bool
	done    bool
	output  *app.RunOutput
	err     error
}

var st guiState

func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

// Run, GUI'yi baslatir ve mesaj dongusunu calistirir (engelleyici).
func Run() error {
	hInstance, _, _ := pGetModuleHandle.Call(0)
	className := u16("ChtesterMainWindow")

	cursor, _, _ := pLoadCursor.Call(0, uintptr(idcArrow))
	bgBrush, _, _ := pGetSysColorBrush.Call(uintptr(colorBtnFace))

	type wndClassEx struct {
		cbSize        uint32
		style         uint32
		lpfnWndProc   uintptr
		cbClsExtra    int32
		cbWndExtra    int32
		hInstance     uintptr
		hIcon         uintptr
		hCursor       uintptr
		hbrBackground uintptr
		lpszMenuName  *uint16
		lpszClassName *uint16
		hIconSm       uintptr
	}
	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   syscall.NewCallback(wndProc),
		hInstance:     hInstance,
		hCursor:       cursor,
		hbrBackground: bgBrush,
		lpszClassName: className,
	}
	if ret, _, err := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); ret == 0 {
		return fmt.Errorf("RegisterClassEx: %v", err)
	}

	hwnd, _, err := pCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(u16("Client Cihaz Sertleştirme Test Aracı — chtester"))),
		uintptr(wsOverlappedWindow|wsVisible),
		100, 100, 720, 520,
		0, 0, hInstance, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowEx: %v", err)
	}

	pShowWindow.Call(hwnd, swShow)
	pUpdateWindow.Call(hwnd)

	var msg struct {
		hwnd    uintptr
		message uint32
		wParam  uintptr
		lParam  uintptr
		time    uint32
		pt      struct{ x, y int32 }
	}
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		pDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
	return nil
}

func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmCreate:
		onCreate(hwnd)
		return 0
	case wmCommand:
		id := wParam & 0xFFFF
		if id == idRunButton {
			startRun(hwnd)
		}
		return 0
	case wmTimer:
		drainLog()
		return 0
	case wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := pDefWindowProc.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func onCreate(hwnd uintptr) {
	hInstance, _, _ := pGetModuleHandle.Call(0)
	st.hFont, _, _ = pGetStockObject.Call(uintptr(defaultGUIFont))

	mk := func(class, text string, style uint32, x, y, w, h int, id int) uintptr {
		ctrl, _, _ := pCreateWindowEx.Call(
			0,
			uintptr(unsafe.Pointer(u16(class))),
			uintptr(unsafe.Pointer(u16(text))),
			uintptr(wsChild|wsVisible|style),
			uintptr(x), uintptr(y), uintptr(w), uintptr(h),
			hwnd, uintptr(id), hInstance, 0,
		)
		pSendMessageFont.Call(ctrl, wmSetFont, st.hFont, 1)
		return ctrl
	}

	mk("STATIC", "Profil ve secenekleri belirleyip 'Testi Çalıştır' tıklayın. Sonuç otomatik raporlanır.",
		0, 14, 12, 660, 20, 0)
	st.hwndStealth = mk("BUTTON", "Stealth profili (cift-kor tespit testi — scope.json gerekir)",
		btnAutoCheckbox|wsTabstop, 14, 40, 480, 22, idStealthChk)
	st.hwndBtn = mk("BUTTON", "Testi Çalıştır",
		wsTabstop, 520, 38, 160, 28, idRunButton)
	st.hwndLog = mk("EDIT", "",
		esMultiline|esReadonly|esAutoVScroll|wsVScroll|wsBorder, 14, 78, 666, 388, idLogEdit)

	appendLog("Hazır. Standart kullanıcı bağlamında pasif keşif (Faz 1) çalışacak.\r\n")
}

// isChecked, bir checkbox'in isaretli olup olmadigini doner (BM_GETCHECK=0x00F0).
func isChecked(hwnd uintptr) bool {
	r, _, _ := pSendMessage.Call(hwnd, 0x00F0, 0, 0)
	return r == 1
}

func startRun(hwnd uintptr) {
	st.mu.Lock()
	if st.running {
		st.mu.Unlock()
		return
	}
	st.running = true
	st.done = false
	st.mu.Unlock()

	pEnableWindow.Call(st.hwndBtn, 0)
	// 200ms timer: arka plan goroutine'in log tamponunu UI'ya aktarir.
	pSetTimer.Call(hwnd, uintptr(idTimer), 200, 0)

	stealth := isChecked(st.hwndStealth)
	profile := "Audit"
	if stealth {
		profile = "Stealth"
	}
	appendLog("\r\n=== Çalışma başladı (profil: " + profile + ") ===\r\n")

	go func() {
		opts := app.Options{
			Profile:     profile,
			PassiveOnly: true,
		}
		out, err := app.Execute(opts, app.FuncLogger(func(format string, args ...any) {
			appendLog(fmt.Sprintf(format, args...) + "\r\n")
		}))
		st.mu.Lock()
		st.output = out
		st.err = err
		st.done = true
		st.running = false
		st.mu.Unlock()
	}()
}

// appendLog, thread-safe sekilde log tamponuna ekler.
func appendLog(s string) {
	st.mu.Lock()
	st.pending = append(st.pending, s)
	st.mu.Unlock()
}

// drainLog, WM_TIMER icinde tamponu EDIT kontrolune yazar ve bitisi isler.
func drainLog() {
	st.mu.Lock()
	pending := st.pending
	st.pending = nil
	done := st.done
	out := st.output
	rerr := st.err
	if done {
		st.done = false // bir kez isle
	}
	st.mu.Unlock()

	for _, s := range pending {
		appendToEdit(st.hwndLog, s)
	}

	if done {
		if rerr != nil {
			appendToEdit(st.hwndLog, "\r\nHATA: "+rerr.Error()+"\r\n")
		} else if out != nil {
			appendToEdit(st.hwndLog, fmt.Sprintf("\r\n=== Tamamlandı. %d vektör. Tier %d. ===\r\n",
				len(out.Report.Results), out.Report.Tier))
			appendToEdit(st.hwndLog, "Rapor: "+out.HTMLPath+"\r\n")
			openInBrowser(out.HTMLPath)
		}
		pEnableWindow.Call(st.hwndBtn, 1)
	}
}

// appendToEdit, EDIT sonuna metin ekler (EM_SETSEL + EM_REPLACESEL).
func appendToEdit(hEdit uintptr, text string) {
	// EDIT kontrolu CRLF ister; once normalize et.
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")
	// Once secimi sona al (EM_SETSEL = 0x00B1, -1,-1 => sona)
	pSendMessage.Call(hEdit, 0x00B1, ^uintptr(0), ^uintptr(0))
	p := u16(text)
	pSendMessage.Call(hEdit, emReplaceSel, 0, uintptr(unsafe.Pointer(p)))
}

func openInBrowser(path string) {
	_ = exec.Command("cmd", "/c", "start", "", path).Start()
}
