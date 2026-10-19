@echo off
rem Author: Shunji Ogawa; SPDX-License-Identifier: Apache-2.0
"%~dp0DriverCrateCollectorSetup.exe" --check-installed
if errorlevel 1 goto finished
pushd "%~dp0"
if errorlevel 1 goto finished
"%~dp0bin\DriverCrateCollector.exe" --validate "%~dp0config\targets.json" "%~dp0work\state\collector"
set "collectorExit=%ERRORLEVEL%"
popd
goto done
:finished
set "collectorExit=%ERRORLEVEL%"
:done
pause
exit /b %collectorExit%
