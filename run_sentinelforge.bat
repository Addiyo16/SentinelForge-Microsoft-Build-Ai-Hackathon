@echo off
title SentinelForge Launcher
echo Starting SentinelForge...

:: Add portable Node to Path if it exists, otherwise fall back to system Node.js
if exist "%~dp0..\node-portable\node-v22.11.0-win-x64" (
    echo [INFO] Found portable Node.js. Adding to PATH...
    set PATH=%~dp0..\node-portable\node-v22.11.0-win-x64;%PATH%
) else (
    echo [INFO] Portable Node.js not found. Using system Node.js...
)

:: Navigate to repository root directory
cd /d "%~dp0"

:: Activate virtual environment
call ".\.venv\Scripts\activate.bat"

:: Go to v2 directory
cd sentinelforge-v2

:: Check if node_modules or tailwindcss is missing
if not exist "frontend\node_modules\tailwindcss" (
    echo ===================================================
    echo [INFO] Node packages not fully installed. Installing now...
    echo ===================================================
    call npm run setup
)

:: Wait a brief moment and open the browser
start "" http://localhost:3000

:: Run the backend and frontend concurrently
npm run dev
