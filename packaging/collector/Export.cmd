@echo off
setlocal
if not "%~4"=="" exit /b 2
if "%~2"=="" exit /b 2
"%~dp0DriverCrateCollectorSetup.exe" --workspace-export "%~1" "%~2" "%~3"
exit /b %errorlevel%
