@echo off
chcp 65001 >nul
title Biên dịch Công Cụ Kiểm Tra Phần Cứng
echo ================================================================
echo        ĐANG BIÊN DỊCH CÔNG CỤ KIỂM TRA PHẦN CỨNG...
echo ================================================================
echo.

set CSC="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist %CSC% (
    set CSC="C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)

if not exist %CSC% (
    echo [❌ LỖI] Không tìm thấy trình biên dịch csc.exe trên máy!
    echo Vui lòng đảm bảo máy tính đã cài đặt .NET Framework.
    pause
    exit /b 1
)

%CSC% /optimize+ /codepage:65001 /r:System.Management.dll /r:System.Windows.Forms.dll /out:"kiem-tra-phan-cung.exe" "Program.cs"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================================
    echo [✔] BIÊN DỊCH THÀNH CÔNG RỰC RỠ!
    echo Đã tạo file: kiem-tra-phan-cung.exe
    echo Bạn có thể nhấp đúp vào file exe vừa tạo để chạy ngay!
    echo ================================================================
) else (
    echo.
    echo ================================================================
    echo [❌] BIÊN DỊCH THẤT BẠI!
    echo Vui lòng kiểm tra lại cú pháp trong file Program.cs theo thông báo ở trên.
    echo ================================================================
)

echo.
pause
