@echo off
title Cloud Console 云服务器控制台
cd /d "%~dp0"

rem ---- 如果 8080 已在运行，直接打开浏览器 ----
netstat -ano | findstr /c:":8080" | findstr /c:"LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo 面板已在运行，正在打开浏览器 ...
    start http://localhost:8080
    echo.
    pause
    exit /b 0
)

rem ---- 优先用同目录 node.exe，否则用系统 node ----
set "NODE_CMD=node"
if exist "%~dp0node.exe" set "NODE_CMD=%~dp0node.exe"

"%NODE_CMD%" --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 Node.js，请先运行 安装依赖.bat 或到 https://nodejs.org 安装
    pause
    exit /b 1
)

if not exist "%~dp0node_modules\ws" (
    echo [提示] 依赖未安装，先执行 npm install ...
    call npm install
    if errorlevel 1 (
        echo [错误] 依赖安装失败，请检查网络后重试
        pause
        exit /b 1
    )
)

echo ==============================================
echo    Cloud Console 云服务器控制台
echo    正在启动本地服务 ...
echo    关闭本窗口即停止服务
echo ==============================================
echo.

start "" /b "%NODE_CMD%" server.js

set /a wait=0
:wait
timeout /t 1 /nobreak >nul
set /a wait+=1
netstat -ano | findstr /c:":8080" | findstr /c:"LISTENING" >nul 2>&1
if not errorlevel 1 goto opened
if %wait% geq 20 (
    echo [警告] 服务启动超时，请检查上方错误信息
    goto done
)
goto wait

:opened
echo 服务已就绪，正在打开浏览器 ...
start "" http://localhost:8080

:done
echo.
echo 服务已停止。
pause