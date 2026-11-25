@echo off
setlocal
set "PS_SCRIPT=%~dp0Update_Cybernova_Safe.ps1"
if not exist "%PS_SCRIPT%" (
  echo [ERROR] Safe updater PowerShell script not found: "%PS_SCRIPT%"
  exit /b 90
)
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%PS_SCRIPT%"
exit /b %ERRORLEVEL%
