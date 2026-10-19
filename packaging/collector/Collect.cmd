@echo off
rem Author: Shunji Ogawa; SPDX-License-Identifier: Apache-2.0
if "%~1"=="--monitor-once" goto monitorOnce
if not "%~1"=="" exit /b 2
"%~dp0DriverCrateCollectorSetup.exe" --check-installed
if errorlevel 1 goto finished
pushd "%~dp0"
if errorlevel 1 goto finished
"%~dp0bin\DriverCrateCollector.exe" --validate "%~dp0config\targets.json" "%~dp0work\state\collector"
if errorlevel 1 goto validationFailed
"%SystemRoot%\System32\choice.exe" /C YN /N /M "Collect official metadata once? No driver download or installation. [Y/N] "
if errorlevel 2 goto cancelled
if not errorlevel 1 goto cancelled
"%~dp0bin\DriverCrateCollector.exe" --once "%~dp0config\targets.json" "%~dp0work\state\collector"
set "collectorExit=%ERRORLEVEL%"
popd
goto done
:validationFailed
set "collectorExit=%ERRORLEVEL%"
popd
goto done
:cancelled
set "collectorExit=3"
popd
goto done
:finished
set "collectorExit=%ERRORLEVEL%"
:done
pause
exit /b %collectorExit%
:monitorOnce
if "%~2"=="" exit /b 2
if not "%~3"=="--confirm-monitor-once" exit /b 2
if not "%~4"=="" exit /b 2
"%~dp0DriverCrateCollectorSetup.exe" --workspace-run-once "%~2" --confirm-monitor-once
exit /b %ERRORLEVEL%
