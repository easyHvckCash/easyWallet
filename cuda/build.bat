@echo off
echo [Build] Compiling CUDA kernel (full pipeline)...
echo [Build] Target: scanner.ptx

:: Adjust -arch= to match your GPU:
::   sm_75 = RTX 2060/2070/2080 (Turing)
::   sm_86 = RTX 3060/3070/3080 (Ampere)
::   sm_89 = RTX 4060/4070/4080 (Ada Lovelace)

nvcc -O3 -arch=sm_89 --ptx scanner.cu -o scanner.ptx ^
  --use_fast_math ^
  -Xptxas -v ^
  -DNDEBUG

if %ERRORLEVEL% == 0 (
    echo [Build] Success: scanner.ptx generated
    echo [Build] Register/shared memory usage printed above
) else (
    echo [Build] FAILED - check CUDA Toolkit installation
    echo [Build] Install: https://developer.nvidia.com/cuda-downloads
    pause
)
