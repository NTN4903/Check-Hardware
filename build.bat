@echo off
chcp 65001 >nul
title Bien dich Cong Cu Kiem Tra Phan Cung
echo ================================================================
echo    DANG BIEN DICH CONG CU KIEM TRA PHAN CUNG...
echo ================================================================
echo.

set CSC="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist %CSC% (
    set CSC="C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)

if not exist %CSC% (
    echo [LOI] Khong tim thay trinh bien dich csc.exe!
    pause
    exit /b 1
)

%CSC% /optimize+ /codepage:65001 /r:System.Management.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.IO.Compression.FileSystem.dll /out:"check_hard.exe" "Program.cs"
copy /y "check_hard.exe" "kiem-tra-phan-cung.exe" >nul

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================================
    echo [OK] BIEN DICH THANH CONG!
    echo Da tao: check_hard.exe va kiem-tra-phan-cung.exe
    echo ================================================================
) else (
    echo.
    echo [LOI] Bien dich that bai!
)
echo.
pause
