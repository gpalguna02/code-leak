@echo off
echo ===================================================
echo   AirGap Sentinel: Zero-Exfiltration Code Defense
echo ===================================================
echo Starting FastAPI Backend on http://127.0.0.1:8001 ...
start "AirGap Sentinel Backend" cmd /k "cd /d %~dp0backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload"

echo Starting Frontend on http://127.0.0.1:8080 ...
start "AirGap Sentinel Frontend" cmd /k "cd /d %~dp0 && python -m http.server 8080 --directory frontend"

timeout /t 2 >nul
echo Opening AirGap Sentinel in browser...
start http://127.0.0.1:8080
echo ===================================================
echo System active. Keep this window or close when done.
pause
