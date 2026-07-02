# build-package.ps1 — builds the "Client Device Tester" distribution package.
# Cross-compiles the three tools for x64/x86/arm64 with product names, lays out a tidy
# folder (main app at root, helper tools under Tools\), and copies the English docs.
# Plan, Phase 5: a package distributable via the customer management channel (USB / Intune / GPO).
#
# Code signing (optional): pass -CertPath <your.pfx> (and -CertPass) or set the env vars
# CDT_SIGN_PFX / CDT_SIGN_PASS. When a certificate is provided, every built .exe is
# Authenticode-signed + RFC3161 timestamped, which removes the SmartScreen/"unknown
# publisher" prompt. Without a certificate the build proceeds UNSIGNED and warns.
param(
    [string]$OutDir = "Client Device Tester",
    [string]$CertPath = $env:CDT_SIGN_PFX,
    [string]$CertPass = $env:CDT_SIGN_PASS,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

# Resolve signtool.exe (PATH or newest Windows SDK).
function Get-SignTool {
    $st = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
    if ($st) { return $st }
    $cand = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    return $cand
}

# Sign every .exe under $OutDir if a certificate was supplied; otherwise warn and skip.
function Invoke-Signing {
    param([string]$Dir)
    $exes = Get-ChildItem $Dir -Recurse -Filter *.exe
    if (-not $CertPath) {
        Write-Host "UYARI: kod imzalama atlandi (sertifika yok). UNSIGNED ikililer SmartScreen uyarisi verir." -ForegroundColor Yellow
        Write-Host "       Imzalamak icin: -CertPath <kurumsal.pfx> [-CertPass ...] veya CDT_SIGN_PFX ortam degiskeni."
        return
    }
    if (-not (Test-Path $CertPath)) { throw "Sertifika bulunamadi: $CertPath" }
    $signtool = Get-SignTool
    if (-not $signtool) { throw "signtool.exe bulunamadi (Windows SDK gerekir)." }
    Write-Host "Imzalaniyor ($($exes.Count) ikili) - $signtool"
    foreach ($e in $exes) {
        $signArgs = @("sign", "/fd", "SHA256", "/f", $CertPath)
        if ($CertPass) { $signArgs += @("/p", $CertPass) }
        $signArgs += @("/tr", $TimestampUrl, "/td", "SHA256", $e.FullName)
        & $signtool @signArgs
        if ($LASTEXITCODE -ne 0) { throw "Imzalama basarisiz: $($e.Name)" }
    }
    Write-Host "Tum ikililer imzalandi + zaman damgalandi." -ForegroundColor Green
}

$ErrorActionPreference = "Stop"
$env:GOOS = "windows"
$arches = [ordered]@{ "amd64" = "x64"; "386" = "x86"; "arm64" = "arm64" }

if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path "$OutDir\Tools" | Out-Null

foreach ($a in $arches.Keys) {
    $env:GOARCH = $a
    $s = $arches[$a]
    Write-Host "Building $s..."
    go build -o "$OutDir\ClientDeviceTester-$s.exe" .\cmd\chtester
    go build -o "$OutDir\Run-Full-Noisy-$s.exe"     .\cmd\runfull
    go build -o "$OutDir\Tools\FleetReport-$s.exe"  .\cmd\aggregate
}
Remove-Item Env:\GOARCH

# Code signing (optional; removes SmartScreen prompt when a cert is provided).
Invoke-Signing -Dir $OutDir

# --- Assemble the field package layout (USB-ready), all from packaging\ ---
# Root: staged launchers (Run-0..3, Run-9-Cleanup) + START HERE.txt

# Staged launchers + entry point at root (the simple, in-order field flow).
foreach ($f in @(
        "Run-0-Preflight.bat", "Run-1-Passive.bat", "Run-2-Active.bat",
        "Run-3-Noisy.bat", "Run-9-Cleanup.bat", "START HERE.txt")) {
    Copy-Item "packaging\$f" "$OutDir\$f" -Force
}

Write-Host ""
Write-Host "Package ready: $OutDir"
Get-ChildItem $OutDir -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring((Resolve-Path $OutDir).Path.Length + 1)
    "{0,8:N0} KB  {1}" -f ($_.Length / 1KB), $rel
}
