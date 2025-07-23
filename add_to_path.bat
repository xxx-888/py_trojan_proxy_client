@echo off
setlocal EnableDelayedExpansion

:: 获取当前脚本目录
set "CURRENT_DIR=%~dp0"
set "CURRENT_DIR=%CURRENT_DIR:~0,-1%"

:: 打印当前工作目录
echo 当前工作目录: %CURRENT_DIR%

:: 获取当前系统 PATH
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path') do set "CURRENT_PATH=%%b"

:: 检查是否已包含
echo %CURRENT_PATH% | findstr /C:"%CURRENT_DIR%" >nul
if %ERRORLEVEL% equ 0 (
    echo 该路径已存在于系统 PATH 环境变量中
    goto :end
)

:: 添加到系统 PATH
wmic ENVIRONMENT where "name='Path' and username='<system>'" set VariableValue="%CURRENT_PATH%;%CURRENT_DIR%"

:: 检查是否成功
if %ERRORLEVEL% equ 0 (
    echo 已成功将 %CURRENT_DIR% 添加到系统 PATH 环境变量
) else (
    echo 添加失败
)

:end
pause