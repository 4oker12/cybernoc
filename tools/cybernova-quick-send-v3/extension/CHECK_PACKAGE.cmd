@echo off
setlocal
cd /d "%~dp0"
echo === CYBERNOVA QUICK SEND V3 ===
echo Checking manifest...
powershell.exe -NoProfile -Command "Get-Content '.\manifest.json' -Raw | ConvertFrom-Json | Out-Null; Write-Host 'MANIFEST_JSON_OK'"
if errorlevel 1 exit /b 1
where node >nul 2>nul
if not errorlevel 1 (
  echo Checking JavaScript syntax...
  node --check service-worker.js || exit /b 1
  node --check content.js || exit /b 1
  echo JAVASCRIPT_SYNTAX_OK
) else (
  echo Node.js not found; skipped JS syntax check.
)
echo Checking required files...
for %%F in (manifest.json service-worker.js content.js content.css) do (
  if not exist "%%F" (
    echo MISSING: %%F
    exit /b 1
  )
)
echo PACKAGE_CHECK_OK
exit /b 0
