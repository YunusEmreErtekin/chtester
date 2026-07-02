@echo off
rem ============================================================
rem  Client Device Tester - 3) NOISY [N] (-EnableNoisy)
rem  Enables persistence / credential / egress / EICAR vectors.
rem  The scope artifact is written to a writable Temp folder at
rem  runtime and passed via -ScopePath (USB stays read-only).
rem  Staged-and-run from a local writable folder (see Run-1 notes).
rem
rem  >>> EDIT THESE FIELDS ONCE PER ENGAGEMENT (before copying to USB) <<<
rem ============================================================
setlocal
set TICKET=CHT-2026-0001
set CUSTOMER=Example Customer Inc.
set SOCCONTACT=soc@example.com
set VALIDFROM=2026-01-01T00:00:00Z
set VALIDUNTIL=2026-12-31T23:59:59Z
set BUDGET=1800
rem ------------------------------------------------------------

set ARCH=%PROCESSOR_ARCHITECTURE%
if /I "%PROCESSOR_ARCHITEW6432%"=="ARM64" set ARCH=ARM64
if /I "%ARCH%"=="ARM64" ( set EXE=ClientDeviceTester-arm64.exe ) else if /I "%ARCH%"=="x86" ( set EXE=ClientDeviceTester-x86.exe ) else ( set EXE=ClientDeviceTester-x64.exe )

set OUTDIR=%TEMP%\ClientDeviceTester-Results
if not exist "%OUTDIR%" mkdir "%OUTDIR%" 2>nul
set LOG=%OUTDIR%\launcher.log

set STAGE=%TEMP%\cdt
if not exist "%STAGE%" mkdir "%STAGE%" 2>nul
copy /Y "%~dp0%EXE%" "%STAGE%\%EXE%" >nul 2>&1
if exist "%STAGE%\%EXE%" ( set RUNEXE=%STAGE%\%EXE% ) else ( set RUNEXE=%~dp0%EXE% )

rem --- write the scope artifact to a writable location (not the USB) ---
set SCOPE=%OUTDIR%\scope.json
(
  echo {
  echo   "ticket": "%TICKET%",
  echo   "customer": "%CUSTOMER%",
  echo   "validFrom": "%VALIDFROM%",
  echo   "validUntil": "%VALIDUNTIL%",
  echo   "allowedTestClasses": ["passive", "active-safe", "noisy"],
  echo   "socContact": "%SOCCONTACT%",
  echo   "doubleBlindAuthorized": false
  echo }
) > "%SCOPE%"

echo ============================================================
echo  Client Device Tester  -  chtester
echo  MODE     : 3) NOISY [N]  (persistence/credential/egress)
echo  Run from : %RUNEXE%
echo  Output   : %OUTDIR%
echo  Scope    : %SCOPE%  (ticket %TICKET%)
echo ============================================================
echo.
echo  WARNING: Noisy tests are intentionally loud and may alert the SOC.
echo  Confirm SOC was notified and authorization is valid for %CUSTOMER%.
echo.
choice /C YN /M "Proceed with NOISY tests"
if errorlevel 2 goto :cancel
echo [%DATE% %TIME%] START noisy  exe=%EXE%  runfrom=%RUNEXE%  ticket=%TICKET%>> "%LOG%"
"%RUNEXE%" -Out "%OUTDIR%" -ScopePath "%SCOPE%" -PassiveOnly=false -EnableNoisy -BudgetSec %BUDGET% -OpenReport %*
set RC=%ERRORLEVEL%
echo [%DATE% %TIME%] EXIT noisy  code=%RC%>> "%LOG%"
echo.
rem --- gercek cikti klasoru: OUTDIR icindeki en yeni <host>_<tarih> alt-klasoru ---
set "RUNDIR=%OUTDIR%"
for /f "delims=" %%d in ('dir /b /ad /o-d "%OUTDIR%" 2^>nul') do ( set "RUNDIR=%OUTDIR%\%%d" & goto :rd )
:rd
if exist "%RUNDIR%\report.html" (
  echo Done. Report: %RUNDIR%\report.html  ^(opens automatically^)
  echo Verify manifest.json shows cleaned=true ^(changes are auto-reverted^).
) else (
  echo NO REPORT PRODUCED  ^(exit code %RC%^). Binary likely blocked - see %LOG%
)
pause
goto :eof
:cancel
echo Cancelled. Nothing was run.
pause
