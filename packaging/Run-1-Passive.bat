@echo off
rem ============================================================
rem  Client Device Tester - 1) PASSIVE (safe, read-only)
rem  No changes are made to the device. This is the safe default.
rem  Strategy for strict devices:
rem   - copy the binary to a writable local folder and run it from
rem     there (defeats "deny execute on removable media" GPO; the
rem     copy also drops the Mark-of-the-Web / SmartScreen prompt)
rem   - write output + a launcher log to a writable Temp folder
rem   - if the binary cannot run, the log records why (a finding)
rem ============================================================
setlocal
set BUDGET=900
set ARCH=%PROCESSOR_ARCHITECTURE%
if /I "%PROCESSOR_ARCHITEW6432%"=="ARM64" set ARCH=ARM64
if /I "%ARCH%"=="ARM64" ( set EXE=ClientDeviceTester-arm64.exe ) else if /I "%ARCH%"=="x86" ( set EXE=ClientDeviceTester-x86.exe ) else ( set EXE=ClientDeviceTester-x64.exe )

set OUTDIR=%TEMP%\ClientDeviceTester-Results
if not exist "%OUTDIR%" mkdir "%OUTDIR%" 2>nul
set LOG=%OUTDIR%\launcher.log

rem --- stage the binary locally (strips MoTW, bypasses USB-execute policy) ---
set STAGE=%TEMP%\cdt
if not exist "%STAGE%" mkdir "%STAGE%" 2>nul
copy /Y "%~dp0%EXE%" "%STAGE%\%EXE%" >nul 2>&1
if exist "%STAGE%\%EXE%" ( set RUNEXE=%STAGE%\%EXE% ) else ( set RUNEXE=%~dp0%EXE% )

echo ============================================================
echo  Client Device Tester  -  chtester
echo  MODE     : 1) PASSIVE  (safe, read-only, no changes)
echo  Run from : %RUNEXE%
echo  Output   : %OUTDIR%
echo ============================================================
echo [%DATE% %TIME%] START passive  exe=%EXE%  runfrom=%RUNEXE%>> "%LOG%"
"%RUNEXE%" -Out "%OUTDIR%" -BudgetSec %BUDGET% -OpenReport %*
set RC=%ERRORLEVEL%
echo [%DATE% %TIME%] EXIT passive  code=%RC%>> "%LOG%"
echo.
rem --- gercek cikti klasoru: OUTDIR icindeki en yeni <host>_<tarih> alt-klasoru ---
set "RUNDIR=%OUTDIR%"
for /f "delims=" %%d in ('dir /b /ad /o-d "%OUTDIR%" 2^>nul') do ( set "RUNDIR=%OUTDIR%\%%d" & goto :rd )
:rd
if exist "%RUNDIR%\report.html" (
  echo Done. Report: %RUNDIR%\report.html  ^(opens automatically^)
) else (
  echo NO REPORT PRODUCED  ^(exit code %RC%^).
  echo The binary was likely blocked ^(AppLocker/WDAC/EDR^) - that is itself a finding.
  echo See launcher log: %LOG%
)
pause
