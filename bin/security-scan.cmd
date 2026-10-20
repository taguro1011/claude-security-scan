@echo off
rem Run scan.py next to this folder (Windows). Prefers the py launcher.
setlocal
set "SCAN=%~dp0..\scan.py"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 "%SCAN%" %*
) else (
  python "%SCAN%" %*
)
exit /b %errorlevel%
