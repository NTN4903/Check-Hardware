# 🔍 Công Cụ Kiểm Tra Phần Cứng & Test Máy Cũ Chuyên Sâu (All-in-One Used PC Suite)

> **Tác giả:** TanNhut (nhutcode) - PITVN Community  
> **Nền tảng:** Windows 7 / 8 / 10 / 11 (32-bit & 64-bit)  
> **Dung lượng:** ~68 KB (Độc lập 100%, không cần cài đặt, không cần phụ thuộc)

---

## 🚀 Chạy Ngay Trên Mọi Máy Tính (Không Cần Cắm USB)

Khi đi mua máy cũ tại cửa hàng hoặc tiệm cầm đồ mà không được phép cắm USB lạ, bạn chỉ cần mở **PowerShell** và dán 1 dòng lệnh duy nhất:

```powershell
irm tinyurl.com/nhutcode-check -OutFile $env:TEMP\c.exe; &$env:TEMP\c.exe
```

---

## 🛠️ Bộ Tính Năng Kiểm Tra Phần Cứng & Chống Fake

1. **Kiểm tra & Soi CPU Thật / Giả (Anti-Spoof CPU):**
   - Đọc trực tiếp vi mã phần cứng qua lệnh Assembly **CPUID** cấp thấp.
   - So sánh với tên hiển thị trong Windows Registry để phát hiện 100% chiêu trò sửa Registry đổi tên CPU fake (ví dụ: đổi Core 2 Duo thành Core i7).
   - Đo điểm tính toán benchmark nhanh (500ms).

2. **Kiểm tra Card Đồ Họa (GPU Anti-Fake):**
   - Đọc trực tiếp **PCI Hardware ID (Vendor ID & Device ID)**.
   - Đối chiếu danh mục GPU chính hãng (NVIDIA, AMD, Intel) để phát hiện card mod BIOS, card trâu cày flash lại ROM.
   - Đọc dung lượng VRAM thực tế và công suất tiêu thụ TDP ước tính.

3. **Kiểm tra Khóa Quản Lý Doanh Nghiệp (MDM / Autopilot / Computrace):**
   - **Windows Autopilot:** Soi `AutopilotPolicyCache`, `CloudAssignedTenantDomain`, `ForcedEnrollment = 1`.
   - **Microsoft Intune & MDM:** Quét `SOFTWARE\Microsoft\Enrollments` và cổng quản lý từ xa.
   - **Azure AD / Domain Join:** Quét trạng thái tham gia máy chủ công ty (`dsregcmd /status`).
   - **Computrace / Absolute Persistence BIOS:** Phát hiện chip gián điệp ngầm khóa máy từ xa (`rpcnet.exe`, `rpcnetp.exe`).

4. **Kiểm tra RAM & Khả năng Nâng cấp:**
   - Dung lượng thực, chuẩn RAM (DDR3, DDR4, DDR5), tốc độ Bus MHz, hãng sản xuất chip nhớ (Samsung, SK Hynix, Micron...).
   - Số khe cắm còn trống, dung lượng tối đa mainboard hỗ trợ.

5. **Kiểm tra Ổ Cứng & Sức khỏe S.M.A.R.T:**
   - Chuẩn giao tiếp (NVMe, SATA, USB), trạng thái sức khỏe ổ đĩa.

6. **Kiểm tra Pin & Số Chu Kỳ Sạc:**
   - Dung lượng thiết kế gốc, dung lượng sạc đầy hiện tại, tỷ lệ chai pin (Wear Level), số lần sạc (Cycle Count).

7. **Kiểm tra Màn hình, Wi-Fi, Camera, Âm thanh & Bản quyền:**
   - Tần số quét màn hình (Hz), độ phân giải, webcam, card Wi-Fi, địa chỉ MAC, ngày cài đặt Windows, Uptime.
   - Tự động sao chép tóm tắt cấu hình vào Clipboard và xuất file báo cáo `ThongSo_PhanCung.txt`.

---

## 🧰 Bộ Công Cụ Test Máy Cũ & Thử Tải Chuyên Sâu (Menu Tương Tác)

Sau khi quét cấu hình, chương trình cung cấp menu tương tác trực tiếp:

* **[1] 📺 Kiểm tra Màn hình (Dead Pixel & Backlight Bleed Test):**
  - Chuyển màn hình sang toàn màn hình các màu thuần khiết: Trắng (soi điểm chết đen, đốm ố lót, bụi phản quang), Đen (soi hở sáng IPS bleed, điểm kẹt sáng), Đỏ, Xanh lá, Xanh dương, Vàng, Xám.
  - Thao tác: Click chuột hoặc phím Space để đổi màu, phím ESC để thoát.

* **[2] ⌨️ Kiểm tra Bàn phím trực quan (Interactive Keyboard Tester):**
  - Giao diện trực quan ma trận phím. Người dùng chỉ cần lướt ngón tay qua từng hàng phím, phím nhận diện tốt sẽ sáng xanh dạ quang (Lime Green). Phát hiện tức thì phím bị liệt hoặc kẹt!

* **[3] 🔥 Thử tải CPU Stress Test & Kiểm tra Tản nhiệt (Thermal Throttling):**
  - Ép tải 100% toàn bộ các nhân luồng CPU trong 15s hoặc 30s.
  - So sánh tốc độ tính toán lúc máy mát vs lúc máy nóng để tính toán chính xác % sụt giảm hiệu năng (Throttling do khô keo tản nhiệt hoặc quạt chết).

* **[4] 🚀 Đo tốc độ Đọc/Ghi thực tế Ổ cứng (Sequential Read/Write Speed Benchmark):**
  - Ghi & Đọc trực tiếp 128 MB dữ liệu ngẫu nhiên xuống ổ đĩa, đo tốc độ MB/s thực tế. Phân loại chuẩn xác NVMe PCIe Gen 3/4/5, SSD SATA 3 hoặc phát hiện SSD kém chất lượng.

* **[5] 🔊 Kiểm tra Loa Trái / Phải (Stereo Speaker Channel Isolation):**
  - Tạo sóng âm thanh stereo 16-bit độc lập: Phát âm thanh chỉ ra Loa Trái (440Hz), chỉ ra Loa Phải (880Hz), và cả hai loa. Phát hiện loa bị tịt một bên hoặc rè màng loa.

* **[6] 🔋 Kiểm tra Tốc độ Nạp/Xả Pin & Nguồn sạc (Battery Charge Monitor):**
  - Theo dõi trạng thái cắm sạc, dòng nạp xả, cảnh báo củ sạc không đủ công suất hoặc lỏng chân sạc.

* **[7] 📥 Trình Tải & Khởi Chạy Phần Mềm Chuyên Dụng (FurMark, HWMonitor, CrystalDiskInfo, CPU-Z, Cinebench):**
  - Tải trực tiếp các công cụ chẩn đoán Portable với thanh tiến trình trực quan (% hoàn thành, MB/MB, tốc độ MB/s).
  - Tự động giải nén và hỏi người dùng có muốn khởi chạy ngay không.
  - Hỗ trợ tải trọn bộ chỉ với 1 click!

---

## 🔨 Cách Tự Biên Dịch (Compile từ mã nguồn)

Mở Command Prompt hoặc chạy trực tiếp `build.bat`:

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /optimize+ /codepage:65001 /r:System.Management.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.IO.Compression.FileSystem.dll /out:"check_hard.exe" "Program.cs"
```

---
*Phát triển và đóng gói bởi TanNhut (nhutcode) - PITVN Community.*
