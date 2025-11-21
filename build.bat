@echo off
title Build PathsParser EXE
cd /d "%~dp0"

echo =====================================
echo        Building PathsParser Executable
echo =====================================
echo.

echo Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH!
    pause
    exit /b 1
)

echo Installing dependencies...
pip install pyinstaller pywebview >nul 2>&1

echo Cleaning previous builds...
if exist build rmdir /s /q build >nul 2>&1
if exist dist rmdir /s /q dist >nul 2>&1
if exist __pycache__ rmdir /s /q __pycache__ >nul 2>&1
if exist PathsParser.spec del PathsParser.spec >nul 2>&1

echo.
echo =====================================
echo     Building Executable...
echo =====================================

echo Checking for paths.ico...
if not exist "paths.ico" (
    echo ERROR: paths.ico not found in root directory!
    echo Please ensure paths.ico exists in: %~dp0
    pause
    exit /b 1
)

echo Found paths.ico - applying to executable (Method 1: PyInstaller)...
python -m PyInstaller --onefile --windowed ^
    --name "PathsParser" ^
    --icon "paths.ico" ^
    --add-data "web;web" ^
    --hidden-import="webview" ^
    --hidden-import="webview.platforms.win32" ^
    --hidden-import="webview.platforms.wince" ^
    --hidden-import="json" ^
    --hidden-import="threading" ^
    --hidden-import="datetime" ^
    --hidden-import="pathlib" ^
    --hidden-import="re" ^
    --collect-all="webview" ^
    PathsParser.py

if errorlevel 1 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)

if exist dist\PathsParser.exe (
    echo.
    echo SUCCESS! Built: dist\PathsParser.exe
    
    REM Method 2: Apply icon again using Resource Hacker if available
    echo Applying icon second time for verification...
    
    set ICON_APPLIED=false
    
    REM Try using Resource Hacker if available
    where ResourceHacker.exe >nul 2>&1
    if not errorlevel 1 (
        echo Applying icon with Resource Hacker...
        ResourceHacker.exe -open "dist\PathsParser.exe" -save "dist\PathsParser.exe" -action addoverwrite -res "paths.ico" -mask ICONGROUP,MAINICON,
        set ICON_APPLIED=true
    )
    
    REM Try using rcedit if available
    if "%ICON_APPLIED%"=="false" (
        where rcedit >nul 2>&1
        if not errorlevel 1 (
            echo Applying icon with rcedit...
            rcedit "dist\PathsParser.exe" --set-icon "paths.ico"
            set ICON_APPLIED=true
        )
    )
    
    if "%ICON_APPLIED%"=="true" (
        echo Icon applied second time successfully!
    ) else (
        echo Note: Only PyInstaller icon application used (no secondary tool available).
        echo Install ResourceHacker or rcedit for double icon application.
    )
    
    echo.
    echo The executable is now completely standalone!
    echo Custom icon applied to the executable.
    echo No external YARA rules file needed - everything is built in.
) else (
    echo ERROR: EXE not created!
)

echo.
pause