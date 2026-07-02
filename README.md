# chtester — Windows Endpoint Hardening Assessment

A single-binary, dependency-free tool that assesses how well a Windows client
device is hardened. It runs **186 checks across 26 categories** and answers one
question: *could a user on this device harm the organization, its data, or the
device itself?*

Each finding reports whether a risky action is **allowed** (control weak or
missing) or **blocked** (control working), with a plain-language impact
explanation and a remediation hint. Output is an HTML report plus
machine-readable JSON.

## What it covers

Execution control (AppLocker/WDAC, LOLBAS, interpreters, VM/WSL), privilege
escalation, persistence, credential exposure (LSASS/SAM/DPAPI/browser),
data exfiltration (USB/WPD/cloud/archive/built-in tools), network attack surface
(LLMNR / NBT-NS / IPv6-mitm6 / ICMP), lateral movement, physical & recovery
access (WinRE/BitLocker), monitoring & logging visibility, authentication &
session hardening, browser attack surface, update integrity, and more.

## Highlights

- Runs as a **standard user**; works on locked-down (ConstrainedLanguage) devices.
- **Safe by default:** passive read-only. Active/noisy tests record every change
  to a manifest and revert it immediately (verifiable `cleaned=true`).
- Native Windows APIs — no shell-out dependency.
- HTML report (Turkish) with severity levels: Bilgi / Düşük / Orta / Yüksek /
  Kritik / Acil, per-device timestamped output folders.

## Build

Requires Go 1.26+ (Windows target).

```sh
go build ./cmd/chtester     # main scanner
go build ./cmd/runfull      # one-click full-run launcher
```

Or produce a full multi-architecture (x64/x86/arm64) package:

```powershell
./build-package.ps1
```

## Usage

- **Safe passive scan:** run `ClientDeviceTester.exe` (double-click or CLI). No
  changes are made.
- **Full assessment** (passive + active + noisy): run `Run-Full-Noisy.exe` and
  confirm the prompt.
- **CLI flags:** `-PassiveOnly=false -EnableNoisy -ScopePath scope.json -Out DIR -OpenReport`

Output is written to `Results/<hostname>_<YYYYMMDD_HHMMSS>/`:
`report.html` (visual report), `report.txt`, `results.json`, `manifest.json`.

## ⚠️ Authorized use only

This tool performs active security tests, including credential-access and
persistence *capability* probes. Run it **only** on devices you own or are
explicitly authorized to assess, and notify the relevant SOC beforehand — noisy
tests intentionally trigger EDR/AV alerts. You are responsible for how you use
it; the authors accept no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
