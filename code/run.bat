@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1

:: ============================================================
::  run.bat - 一键编译 + 启动主节点 + 启动子节点
::  会先杀掉已有的 btc-cuda-scanner 进程，确保始终运行最新版本
:: ============================================================

set "ROOT=%~dp0"
set "DIST=%ROOT%dist"
set "EXE=btc-cuda-scanner.exe"
set "EXE_PATH=%DIST%\%EXE%"

:: ---------- 可配置参数 ----------
set "TOKEN=changeme"
set "MASTER_PORT=8877"
set "MASTER_USER=admin"
set "MASTER_PASSWD=admin"
set "DEPTH=3"
:: --------------------------------

echo.
echo ============================================
echo   easyWallet - Auto Build ^& Run
echo ============================================
echo.

:: ========== Step 1: 杀掉已有进程 ==========
echo [1/4] 清理旧进程...
tasklist /FI "IMAGENAME eq %EXE%" 2>nul | find /I "%EXE%" >nul
if %ERRORLEVEL% equ 0 (
    echo       发现已运行的 %EXE%，正在终止...
    taskkill /F /IM %EXE% >nul 2>&1
    :: 等待进程完全退出
    timeout /t 2 /nobreak >nul
    echo       [OK] 旧进程已终止
) else (
    echo       无旧进程需要清理
)
echo.

:: ========== Step 2: 编译 ==========
echo [2/4] 开始编译...
echo.
call "%ROOT%build.bat"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] 编译失败，无法继续
    goto :fail
)

:: 检查编译产物
if not exist "%EXE_PATH%" (
    echo [ERROR] 编译产物不存在: %EXE_PATH%
    goto :fail
)
echo.

:: ========== Step 3: 启动主节点 ==========
echo [3/4] 启动主节点 (Master)...
echo       监听端口: %MASTER_PORT% (集群API + Dashboard)
echo       Token:    %TOKEN%
echo.

pushd "%DIST%"
start "[Master] easyWallet" cmd /c "title [Master] easyWallet && "%EXE_PATH%" --role master --listenon %MASTER_PORT% --token %TOKEN% --user %MASTER_USER% --passwd %MASTER_PASSWD% --depth %DEPTH% && pause"
popd

:: 等待主节点启动就绪
echo       等待主节点启动 (3秒)...
timeout /t 3 /nobreak >nul
echo       [OK] 主节点已启动
echo.

:: ========== Step 4: 启动子节点 ==========
echo [4/4] 启动子节点 (Node)...
echo       连接到: 0.0.0.0:%MASTER_PORT%
echo       Token:  %TOKEN%
echo.

pushd "%DIST%"
start "[Node-1] easyWallet" cmd /c "title [Node-1] easyWallet && "%EXE_PATH%" --role node --server 0.0.0.0:%MASTER_PORT% --token %TOKEN% --depth %DEPTH% && pause"
popd

echo       [OK] 子节点已启动
echo.

:: ========== 完成 ==========
echo ============================================
echo   全部启动完成!
echo ============================================
echo.
echo   Master:    PID 窗口标题 [Master] easyWallet
echo   Node-1:    PID 窗口标题 [Node-1] easyWallet
echo   Dashboard: http://localhost:%MASTER_PORT%/
echo.
echo   如需停止，运行: taskkill /F /IM %EXE%
echo ============================================
goto :end

:fail
echo.
echo ============================================
echo   启动失败!
echo ============================================
pause
exit /b 1

:end
endlocal
