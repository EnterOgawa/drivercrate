@echo off
rem Author: Shunji Ogawa; SPDX-License-Identifier: Apache-2.0
"%~dp0DriverCrateCollectorSetup.exe" --uninstall
set "collectorExit=%ERRORLEVEL%"
pause
exit /b %collectorExit%
