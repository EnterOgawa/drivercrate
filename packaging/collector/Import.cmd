@echo off
setlocal
if not "%~5"=="" exit /b 2
if "%~3"=="" exit /b 2
if "%~1"=="import" goto import
if "%~1"=="resume" goto resume
exit /b 2
:import
"%~dp0DriverCrateCollectorSetup.exe" --workspace-import "%~2" "%~3" "%~4"
exit /b %errorlevel%
:resume
"%~dp0DriverCrateCollectorSetup.exe" --workspace-resume "%~2" "%~3" "%~4"
exit /b %errorlevel%
