@echo off
setlocal
if not "%~3"=="" exit /b 2
if "%~1"=="" exit /b 2
"%~dp0DriverCrateCollectorSetup.exe" --workspace-initialize "%~1" "%~2"
exit /b %errorlevel%
