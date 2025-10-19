@echo off
echo ============================================================
echo   Restarting Domain Reconnaissance Tool (Clean)
echo ============================================================
echo.

echo Stopping any running instances...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq Domain Reconnaissance Tool" 2>nul
timeout /t 2 /nobreak >nul

echo Cleaning old databases...
if exist vulnerabilities.db del /Q vulnerabilities.db
if exist monitoring.db del /Q monitoring.db
if exist api_management.db del /Q api_management.db
if exist domain_recon.db del /Q domain_recon.db
echo.

echo Starting application...
echo Server will start on: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo.
echo ============================================================
echo.

python app.py
