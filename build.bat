@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1

set "ROOT=%~dp0"
set "DIST=%ROOT%dist"
set "CUDA_SRC=%ROOT%cuda"
set "ARCH=sm_75"

echo ============================================
echo   BTC Scanner - Full Build Script
echo   CUDA kernel + Rust release + package
echo ============================================
echo.

:: ========== Load MSVC environment (required by nvcc) ==========
where cl.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [INFO] cl.exe not in PATH, searching for Visual Studio...
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if exist "!VSWHERE!" (
        for /f "usebackq delims=" %%i in (`"!VSWHERE!" -latest -property installationPath`) do set "VSDIR=%%i"
    )
    if defined VSDIR (
        if exist "!VSDIR!\VC\Auxiliary\Build\vcvars64.bat" (
            echo [INFO] Loading VS environment: !VSDIR!
            call "!VSDIR!\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
        )
    ) else (
        :: Fallback: try common paths
        if exist "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
            call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
        ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
            call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
        ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
            call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
        ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
            call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
        ) else (
            echo [ERROR] Cannot find Visual Studio or Build Tools
            echo         Install: https://visualstudio.microsoft.com/visual-cpp-build-tools/
            echo         Select "Desktop development with C++"
            goto :fail
        )
    )
)
echo.

:: ========== Step 1: CUDA Kernel ==========
echo [1/3] Compiling CUDA kernel...
echo       Source: cuda\scanner.cu
echo       Arch:   %ARCH% (RTX 2060 Super)
echo.

where nvcc >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] nvcc not found in PATH
    echo         Install CUDA Toolkit: https://developer.nvidia.com/cuda-downloads
    echo         Then add to PATH: C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.x\bin
    goto :fail
)

pushd "%CUDA_SRC%"
nvcc -O3 -arch=%ARCH% --ptx scanner.cu -o scanner.ptx ^
    --use_fast_math ^
    -Xptxas -v ^
    -DNDEBUG 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CUDA kernel compilation failed
    popd
    goto :fail
)
echo [OK] scanner.ptx generated
popd
echo.

:: ========== Step 2: Rust Release Build ==========
echo [2/3] Building Rust project (release)...
echo.

where cargo >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] cargo not found in PATH
    echo         Install Rust: https://rustup.rs
    goto :fail
)

pushd "%ROOT%"
cargo build --release 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Rust build failed
    popd
    goto :fail
)
echo [OK] Rust build succeeded
popd
echo.

:: ========== Step 3: Package to dist/ ==========
echo [3/3] Packaging to dist\ ...

:: Only clean exe and cuda, preserve files/
if exist "%DIST%\btc-cuda-scanner.exe" del "%DIST%\btc-cuda-scanner.exe"
if exist "%DIST%\cuda\scanner.ptx" del "%DIST%\cuda\scanner.ptx"

if not exist "%DIST%" mkdir "%DIST%"
if not exist "%DIST%\cuda" mkdir "%DIST%\cuda"
if not exist "%DIST%\files" mkdir "%DIST%\files"
if not exist "%DIST%\files\waittocheck" mkdir "%DIST%\files\waittocheck"

:: Copy exe
copy "%ROOT%target\release\btc-cuda-scanner.exe" "%DIST%\" >nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to copy exe
    goto :fail
)

:: Copy PTX
copy "%CUDA_SRC%\scanner.ptx" "%DIST%\cuda\" >nul

:: Copy any pending task files
if exist "%ROOT%files\waittocheck\*.txt" (
    copy "%ROOT%files\waittocheck\*.txt" "%DIST%\files\waittocheck\" >nul
    echo       Copied: waittocheck\*.txt
)

echo.
echo ============================================
echo   Build Complete!
echo ============================================
echo.
echo   Output:  %DIST%\
echo   EXE:     dist\btc-cuda-scanner.exe
echo   Kernel:  dist\cuda\scanner.ptx
echo.
echo   Runtime layout:
echo     dist\btc-cuda-scanner.exe
echo     dist\cuda\scanner.ptx
echo     dist\files\waittocheck\      (task files)
echo     ..\humanaction\addr\          (utxo_addresses.set)
echo     ..\humanaction\pocs\          (POC generators)
echo.
echo   Usage (master):
echo     btc-cuda-scanner.exe --role master --listenon 8877 --token SECRET
echo.
echo   Usage (node):
echo     btc-cuda-scanner.exe --role node --server IP:8877 --token SECRET
echo ============================================
goto :end

:fail
echo.
echo ============================================
echo   BUILD FAILED
echo ============================================
pause
exit /b 1

:end
endlocal
