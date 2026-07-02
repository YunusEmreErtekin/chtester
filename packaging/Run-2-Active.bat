@echo off
rem ============================================================
rem  Client Device Tester - 2) ACTIVE-SAFE (-PassiveOnly=false)
rem  Actually attempts each action, then reverts every change
rem  immediately (recorded in manifest.json). Requires written
rem  authorization. Does NOT run noisy [N] tests.
rem  Staged-and-run from a local writable folder (see Run-1 notes).
rem ============================================================
setlocal
set BUDGET=900
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

echo ============================================================
echo  Client Device Tester  -  chtester
echo  MODE     : 2) ACTIVE-SAFE  (attempts + auto-reverts)
echo  Run from : %RUNEXE%
echo  Output   : %OUTDIR%
echo ============================================================
echo.
echo  WARNING: Active tests make temporary changes (reverted at once).
echo  Run only with written authorization and SOC notified.
echo.
choice /C YN /M "Proceed with ACTIVE tests"
if errorlevel 2 goto :cancel
echo [%DATE% %TIME%] START active  exe=%EXE%  runfrom=%RUNEXE%>> "%LOG%"
"%RUNEXE%" -Out "%OUTDIR%" -PassiveOnly=false -BudgetSec %BUDGET% -OpenReport %*
set RC=%ERRORLEVEL%
echo [%DATE% %TIME%] EXIT active  code=%RC%>> "%LOG%"
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
