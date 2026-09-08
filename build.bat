@echo off
rem ============================================================
rem  Local build script: package single-file trojan_client.exe
rem
rem  Usage:
rem    build.bat          build with the venv PyInstaller
rem    build.bat --dev    create venv + install deps first, then build
rem
rem  NOTE: keep this file ASCII-only and CRLF, otherwise cmd.exe
rem        may fail to parse it on non-UTF8 codepages (e.g. GBK).
rem ============================================================
setlocal
cd /d "%~dp0"

if "%~1"=="--dev" (
    if not exist venv (
        python -m venv venv || goto :error
    )
    venv\Scripts\pip install -r requirements.txt pyinstaller || goto :error
)

if not exist venv\Scripts\pyinstaller.exe (
    echo [ERROR] PyInstaller not found in venv. Run first: build.bat --dev
    goto :error
)

echo [1/2] Building trojan_client.exe with PyInstaller ...
venv\Scripts\pyinstaller --onefile --console --name trojan_client --clean --noconfirm run.py || goto :error

echo.
echo [2/2] Build OK: dist\trojan_client.exe
echo       Put config.json in the same folder as the exe before running it.
endlocal & exit /b 0

:error
echo.
echo [ERROR] Build failed. Check the log above.
endlocal & exit /b 1
