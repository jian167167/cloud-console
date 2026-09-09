@echo off
title Cloud Console - 安装依赖
cd /d "%~dp0"

rem ---- 优先用同目录 node.exe，否则用系统 node ----
set "NODE_CMD=node"
if exist "%~dp0node.exe" set "NODE_CMD=%~dp0node.exe"

"%NODE_CMD%" --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 Node.js
    echo 请先安装 Node.js 18+ ：https://nodejs.org
    echo 或把便携版 node.exe 放到本目录
    pause
    exit /b 1
)

echo 正在安装依赖（首次约 1-2 分钟）...
call npm install
if errorlevel 1 (
    echo [错误] 依赖安装失败，请检查网络后重试
    pause
    exit /b 1
)
echo.
echo 安装完成！双击「启动面板.bat」即可启动。
pause