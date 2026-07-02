@echo off
rem ============================================================
rem  Client Device Tester - 0) PREFLIGHT (device posture check)
rem  Read-only. Runs NO security tests. Tells you whether the
rem  device will even let the harness run, and writes the result
rem  to a file so a locked-down box still yields an artifact.
rem ============================================================
setlocal
set OUTDIR=%TEMP%\ClientDeviceTester-Results
if not exist "%OUTDIR%" mkdir "%OUTDIR%" 2>nul
set PF=%OUTDIR%\preflight.txt
if not exist "%OUTDIR%" set PF=%TEMP%\preflight.txt

set ARCH=%PROCESSOR_ARCHITECTURE%
if /I "%PROCESSOR_ARCHITEW6432%"=="ARM64" set ARCH=ARM64
if /I "%ARCH%"=="ARM64" ( set EXE=ClientDeviceTester-arm64.exe ) else if /I "%ARCH%"=="x86" ( set EXE=ClientDeviceTester-x86.exe ) else ( set EXE=ClientDeviceTester-x64.exe )

echo ============================================================ > "%PF%"
echo  Client Device Tester - PREFLIGHT >> "%PF%"
echo  When: %DATE% %TIME% >> "%PF%"
echo  Host: %COMPUTERNAME%   User: %USERDOMAIN%\%USERNAME% >> "%PF%"
echo  CPU arch: %ARCH%   ->  binary: %EXE% >> "%PF%"
echo ------------------------------------------------------------ >> "%PF%"

rem --- admin? ---
net session >nul 2>&1
if "%ERRORLEVEL%"=="0" ( echo  Admin rights      : YES ^(local admin^) >> "%PF%" ) else ( echo  Admin rights      : no ^(standard user - Tier 3 tests will be NotApplicable^) >> "%PF%" )

rem --- PowerShell present? ---
where powershell >nul 2>&1
if "%ERRORLEVEL%"=="0" ( echo  PowerShell present: YES >> "%PF%" ) else ( echo  PowerShell present: no >> "%PF%" )

rem --- temp writable? ---
echo test> "%TEMP%\cdt_w.tmp" 2>nul
if exist "%TEMP%\cdt_w.tmp" ( echo  Temp writable     : YES ^(%TEMP%^) >> "%PF%" & del "%TEMP%\cdt_w.tmp" >nul 2>&1 ) else ( echo  Temp writable     : NO - output may fail >> "%PF%" )

rem --- USB writable? ---
echo test> "%~dp0cdt_w.tmp" 2>nul
if exist "%~dp0cdt_w.tmp" ( echo  USB writable      : yes >> "%PF%" & del "%~dp0cdt_w.tmp" >nul 2>&1 ) else ( echo  USB writable      : NO ^(read-only/GPO - expected; output goes to Temp^) >> "%PF%" )

rem --- can we copy the binary off the USB? ---
set STAGE=%TEMP%\cdt
if not exist "%STAGE%" mkdir "%STAGE%" 2>nul
copy /Y "%~dp0%EXE%" "%STAGE%\%EXE%" >nul 2>&1
if exist "%STAGE%\%EXE%" ( echo  Stage to local    : YES ^(copied to %STAGE%, MoTW stripped^) >> "%PF%" ) else ( echo  Stage to local    : NO - cannot copy binary off USB >> "%PF%" )

rem --- can the binary actually EXECUTE from local disk? (read-only, bounded test) ---
if exist "%STAGE%\%EXE%" (
  "%STAGE%\%EXE%" -WhatIf -PassiveOnly=true -BudgetSec 15 -Out "%OUTDIR%" >nul 2>&1
  set RC=%ERRORLEVEL%
  echo  Execute from local: launched, exit code %ERRORLEVEL% ^(non-fatal=allowed; blocked=AppLocker/WDAC finding^) >> "%PF%"
) else (
  echo  Execute from local: SKIPPED ^(no staged binary^) >> "%PF%"
)

echo ------------------------------------------------------------ >> "%PF%"
echo  Next: Run-1-Passive.bat ^(safe^) -^> Run-2-Active.bat -^> Run-3-Noisy.bat >> "%PF%"
echo ============================================================ >> "%PF%"

type "%PF%"
echo.
echo Saved: %PF%
pause
