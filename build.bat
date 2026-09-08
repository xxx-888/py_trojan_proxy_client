@echo off
rem ============================================================
rem  Windows 本地构建脚本：打包单文件 trojan_client.exe
rem  用法: build.bat          (使用 venv 中的 PyInstaller)
rem        build.bat --dev    (先安装依赖与 PyInstaller 再构建)
rem ============================================================
setlocal
cd /d "%~dp0"

if "%1"=="--dev" (
    if not exist venv (
        python -m venv venv || goto :error
    )
    venv\Scripts\pip install -r requirements.txt pyinstaller || goto :error
)

if not exist venv\Scripts\pyinstaller.exe (
    echo [错误] 未找到 PyInstaller，请先执行: build.bat --dev
    goto :error
)

venv\Scripts\pyinstaller --onefile --console --name trojan_client --clean --noconfirm run.py || goto :error

echo.
echo [成功] 构建完成: dist\trojan_client.exe
echo        请将 config.json 放到 exe 同目录后运行。
endlocal & exit /b 0

:error
echo [失败] 构建出错，请检查上方日志。
endlocal & exit /b 1
