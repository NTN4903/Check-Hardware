# 🔍 CÔNG CỤ KIỂM TRA PHẦN CỨNG & CHỐNG FAKE MÁY TÍNH (46 KB)

Công cụ Portable siêu nhẹ dành cho kỹ thuật viên và người đi mua máy cũ (Laptop / PC cũ) để phát hiện linh kiện bị làm giả hoặc bị tráo đổi thông số.

## 🚀 Tính năng nổi bật

* **🛡️ Chống Fake CPU (Silicon CPUID):** Dùng trực tiếp mã máy ASM (`CPUID`) truy vấn thẳng vào đế chip bán dẫn của CPU, bóc mẽ ngay lập tức nếu máy bị sửa Registry đổi tên CPU giả.
* **⚡ Benchmark CPU 500ms:** Đo điểm hiệu năng thực tế để kiểm tra CPU có bị bóp xung / nghẽn cổ chai hay không.
* **🔋 Soi Pin & Chu kỳ sạc:** Đọc dung lượng gốc, dung lượng sạc đầy hiện tại, tính chính xác **% chai pin** và **Số lần cắm sạc (Cycle Count)**.
* **💾 Sức khỏe Ổ cứng (S.M.A.R.T.):** Quét tình trạng SSD/HDD (Tốt / Cảnh báo / Nguy hiểm).
* **🎮 Xác thực Card đồ họa (GPU):** Quét mã phần cứng **PCI Hardware ID (`VEN_xxxx & DEV_xxxx`)** chống card trâu cày hoặc card flash BIOS lừa đảo.
* **🧠 Kiểm tra RAM:** Nhận diện loại RAM (DDR2 - DDR5), Bus, hãng chip nhớ và số khe cắm thực tế còn trống.
* **🏷️ Đối chiếu Serial / Service Tag:** Soi mã Serial mainboard để đối chiếu với vỏ máy tránh mua phải máy ráp vỏ.
* **📋 Tự động sao chép Clipboard & Xuất file báo cáo:** Hỗ trợ lưu trữ kết quả để làm bằng chứng bảo hành.

---

## ⚡ Cách chạy nhanh không cần cắm USB (1 Dòng lệnh duy nhất)

Khi đi test máy tại cửa hàng hoặc tiệm net, bạn chỉ cần bấm `Windows + R` -> gõ `powershell` -> dán dòng lệnh sau và nhấn **Enter**:

```powershell
irm https://raw.githubusercontent.com/NTN493/Check-Hardware/main/check_hard.exe -OutFile $env:TEMP\c.exe; &$env:TEMP\c.exe
```

Tool sẽ tải thẳng vào bộ nhớ tạm (46 KB tải trong 1 giây) và khởi chạy ngay lập tức! Khi đóng cửa sổ, hệ thống sẽ tự dọn sạch không để lại dấu vết.

---

## 🛠️ Hướng dẫn biên dịch lại từ mã nguồn (Build from source)

Chạy file `build.bat` hoặc mở CMD gõ:
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /optimize+ /codepage:65001 /r:System.Management.dll /r:System.Windows.Forms.dll /out:"check_hard.exe" "Program.cs"
```

---
*Phát triển và đóng gói bởi NTN493 - PITVN Community.*