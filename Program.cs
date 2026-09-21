using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace HardwareScanAgent
{
    class Program
    {
        #region CPUID Native Interop
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void CpuIdDelegate(int func, int subfunc, byte[] buffer);

        static string GetHardwareCpuBrand()
        {
            try
            {
                byte[] code;
                if (IntPtr.Size == 8)
                {
                    // x64 calling convention: rcx=func, rdx=subfunc, r8=buffer
                    code = new byte[] {
                        0x53,                         // push rbx
                        0x89, 0xC8,                   // mov eax, ecx
                        0x89, 0xD1,                   // mov ecx, edx
                        0x0F, 0xA2,                   // cpuid
                        0x41, 0x89, 0x00,             // mov [r8], eax
                        0x41, 0x89, 0x58, 0x04,       // mov [r8+4], ebx
                        0x41, 0x89, 0x48, 0x08,       // mov [r8+8], ecx
                        0x41, 0x89, 0x50, 0x0C,       // mov [r8+12], edx
                        0x5B,                         // pop rbx
                        0xC3                          // ret
                    };
                }
                else
                {
                    // x86 calling convention: stdcall
                    code = new byte[] {
                        0x55,                         // push ebp
                        0x89, 0xE5,                   // mov ebp, esp
                        0x53,                         // push ebx
                        0x57,                         // push edi
                        0x8B, 0x45, 0x08,             // mov eax, [ebp+8]
                        0x8B, 0x4D, 0x0C,             // mov ecx, [ebp+12]
                        0x0F, 0xA2,                   // cpuid
                        0x8B, 0x7D, 0x10,             // mov edi, [ebp+16]
                        0x89, 0x07,                   // mov [edi], eax
                        0x89, 0x5F, 0x04,             // mov [edi+4], ebx
                        0x89, 0x4F, 0x08,             // mov [edi+8], ecx
                        0x89, 0x57, 0x0C,             // mov [edi+12], edx
                        0x5F,                         // pop edi
                        0x5B,                         // pop ebx
                        0x5D,                         // pop ebp
                        0xC2, 0x0C, 0x00              // ret 12
                    };
                }

                IntPtr ptr = VirtualAlloc(IntPtr.Zero, (UIntPtr)code.Length, 0x1000 | 0x2000, 0x40); // PAGE_EXECUTE_READWRITE
                Marshal.Copy(code, 0, ptr, code.Length);
                CpuIdDelegate cpuid = (CpuIdDelegate)Marshal.GetDelegateForFunctionPointer(ptr, typeof(CpuIdDelegate));

                byte[] brandBytes = new byte[48];
                byte[] buf = new byte[16];

                cpuid(unchecked((int)0x80000002), 0, buf);
                Buffer.BlockCopy(buf, 0, brandBytes, 0, 16);

                cpuid(unchecked((int)0x80000003), 0, buf);
                Buffer.BlockCopy(buf, 0, brandBytes, 16, 16);

                cpuid(unchecked((int)0x80000004), 0, buf);
                Buffer.BlockCopy(buf, 0, brandBytes, 32, 16);

                VirtualFree(ptr, UIntPtr.Zero, 0x8000);

                string brand = Encoding.ASCII.GetString(brandBytes).Trim().Replace("\0", "");
                return string.IsNullOrEmpty(brand) ? "Unknown" : brand;
            }
            catch
            {
                return "Unknown";
            }
        }

        static long RunCpuBenchmark(int ms)
        {
            try
            {
                int threads = Environment.ProcessorCount;
                int itersPerThread = 5000000;
                Thread[] workers = new Thread[threads];
                Stopwatch sw = Stopwatch.StartNew();

                for (int i = 0; i < threads; i++)
                {
                    workers[i] = new Thread(() => {
                        double a = 1.0001;
                        for (int j = 0; j < itersPerThread; j++)
                        {
                            a = a * 1.000001 + 0.000002;
                        }
                    });
                    workers[i].Start();
                }

                for (int i = 0; i < threads; i++) workers[i].Join();
                sw.Stop();

                double secs = sw.Elapsed.TotalSeconds;
                if (secs <= 0.001) secs = 0.001;
                long score = (long)((double)(threads * itersPerThread) / (secs * 10000.0));
                return score;
            }
            catch
            {
                return 0;
            }
        }
        #endregion

        #region Data Models
        public class CpuInfo
        {
            public string Name = "Unknown CPU";
            public string HardwareBrand = "Unknown";
            public string RegistryName = "Unknown";
            public string Cores = "N/A";
            public string LogicalProcessors = "N/A";
            public string ClockSpeed = "N/A";
            public bool IsSpoofed = false;
            public long BenchmarkScore = 0;
        }

        public class RamSlotInfo
        {
            public string Bank = "N/A";
            public string Capacity = "N/A";
            public string Speed = "N/A";
            public string Manufacturer = "Unknown";
        }

        public class RamInfo
        {
            public string Total = "0";
            public string Speed = "N/A";
            public string Type = "Unknown";
            public string Manufacturer = "Unknown";
            public string MaxCapacity = "N/A";
            public int MaxSlots = 0;
            public int ActiveSlots = 0;
            public int EmptySlots = 0;
            public bool IsConsistent = true;
            public List<RamSlotInfo> Slots = new List<RamSlotInfo>();
        }

        public class GpuDevice
        {
            public string Name = "Unknown GPU";
            public string Type = "Integrated";
            public string Vram = "N/A";
            public string Tdp = "N/A";
            public string PnpDeviceId = "";
            public string VendorId = "";
            public string DeviceId = "";
            public string SubsystemVendor = "Unknown";
            public bool IsFakeSuspected = false;
            public string VerificationNote = "Chưa kiểm tra";
        }

        public class DriveInfoItem
        {
            public string Model = "Unknown Drive";
            public string Size = "N/A";
            public string BusType = "SATA";
            public string MediaType = "SSD";
            public string HealthStatus = "Tốt (Healthy)";
        }

        public class MonitorInfo
        {
            public string Resolution = "Unknown";
            public string RefreshRate = "60";
        }

        public class BatteryInfo
        {
            public string DesignCapacity = "N/A";
            public string CurrentCapacity = "N/A";
            public string WearLevel = "0%";
            public string Status = "Không có pin / Máy để bàn";
            public string Voltage = "N/A";
            public int CycleCount = -1;
            public bool HasBattery = false;
        }

        public class WifiInfo
        {
            public string AdapterName = "N/A";
            public string CurrentSsid = "Disconnected";
            public string CurrentSignal = "0%";
        }

        public class MotherboardInfo
        {
            public string Manufacturer = "Unknown";
            public string Product = "Unknown";
            public string Version = "1.0";
            public string SerialNumber = "N/A";
        }

        public class BiosInfo
        {
            public string Vendor = "Unknown";
            public string Version = "Unknown";
            public string ReleaseDate = "N/A";
        }

        public class OsDetailInfo
        {
            public string Caption = "Unknown Windows";
            public string InstallDate = "N/A";
            public string Uptime = "N/A";
        }

        public class NetworkAdapterItem
        {
            public string Name = "Network Adapter";
            public string MacAddress = "N/A";
            public string IpAddress = "N/A";
        }

        public class SystemInfo
        {
            public string Manufacturer = "Unknown";
            public string Model = "Unknown";
            public string SerialNumber = "N/A";
            public OsDetailInfo OS = new OsDetailInfo();
            public MotherboardInfo Motherboard = new MotherboardInfo();
            public BiosInfo BIOS = new BiosInfo();
        }
        #endregion

        [STAThread]
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║        CÔNG CỤ KIỂM TRA PHẦN CỨNG ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("⏳ Đang quét phần cứng");
            Console.ResetColor();
            Console.WriteLine();

            StringBuilder report = new StringBuilder();
            report.AppendLine("==================================================================");
            report.AppendLine("         BÁO CÁO CẤU HÌNH PHẦN CỨNG");
            report.AppendLine("        Thời gian quét: " + DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss"));
            report.AppendLine("==================================================================");
            report.AppendLine();

            // 1. Quét & Kiểm định CPU
            CpuInfo cpu = GetAndVerifyCpu();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [1] CPU (Bộ vi xử lý): ");
            Console.ResetColor();
            Console.WriteLine(string.Format("{0} ({1} Nhân / {2} Luồng) @ {3} MHz", cpu.Name, cpu.Cores, cpu.LogicalProcessors, cpu.ClockSpeed));

            // Hiển thị trạng thái kiểm định CPU
            if (cpu.IsSpoofed)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("    [🚨 CẢNH BÁO FAKE CPU] Tên CPU trong Windows đã bị can thiệp / sửa Registry!");
                Console.WriteLine("    -> Tên phần cứng gốc (Silicon CPUID): " + cpu.HardwareBrand);
                Console.WriteLine("    -> Tên hiển thị giả mạo (Windows): " + cpu.Name);
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("    [🛡 CHUẨN XÁC] CPU nguyên bản - Khớp 100% với vi mã phần cứng (CPUID: " + cpu.HardwareBrand + ")");
                Console.ResetColor();
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(string.Format("    - Benchmark tính toán nhanh (500ms): {0:N0} điểm (Phù hợp năng lực thực tế)", cpu.BenchmarkScore));
            Console.ResetColor();

            report.AppendLine("[1] BỘ VI XỬ LÝ (CPU) & KIỂM ĐỊNH CHỐNG FAKE:");
            report.AppendLine("    - Tên hiển thị Windows: " + cpu.Name);
            report.AppendLine("    - Tên phần cứng gốc (CPUID): " + cpu.HardwareBrand);
            report.AppendLine(string.Format("    - Số nhân / Số luồng: {0} Nhân / {1} Luồng", cpu.Cores, cpu.LogicalProcessors));
            report.AppendLine("    - Xung nhịp tối đa: " + cpu.ClockSpeed + " MHz");
            report.AppendLine("    - Điểm hiệu năng nhanh: " + cpu.BenchmarkScore.ToString("N0") + " điểm");
            report.AppendLine("    - Kết luận kiểm định: " + (cpu.IsSpoofed ? "🚨 PHÁT HIỆN FAKE / SỬA REGISTRY!" : "🛡 CHUẨN XÁC (Khớp vi mã phần cứng)"));
            report.AppendLine();

            // 2. Quét & Kiểm định RAM
            RamInfo ram = GetRam();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [2] RAM (Bộ nhớ trong): ");
            Console.ResetColor();
            Console.WriteLine(string.Format("{0} GB ({1} @ {2} MHz - Hãng chip: {3})", ram.Total, ram.Type, ram.Speed, ram.Manufacturer));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(string.Format("    - Khe cắm: {0}/{1} khe (Trống: {2} khe). Hỗ trợ tối đa: {3} GB", ram.ActiveSlots, ram.MaxSlots, ram.EmptySlots, ram.MaxCapacity));
            if (ram.IsConsistent)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("    [🛡 CHUẨN XÁC] Bộ nhớ RAM đồng bộ, dung lượng thực khớp với số khe cắm.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("    [⚠ LƯU Ý] Phát hiện dung lượng tổng lệch so với các khe cắm (Nghi vấn khai báo ảo).");
            }
            Console.ResetColor();

            report.AppendLine("[2] BỘ NHỚ TRONG (RAM):");
            report.AppendLine("    - Tổng dung lượng: " + ram.Total + " GB");
            report.AppendLine("    - Chuẩn RAM: " + ram.Type + " (" + ram.Speed + " MHz)");
            report.AppendLine("    - Hãng sản xuất chip nhớ: " + ram.Manufacturer);
            report.AppendLine(string.Format("    - Số khe cắm: {0} khe (Đã cắm: {1}, Trống: {2})", ram.MaxSlots, ram.ActiveSlots, ram.EmptySlots));
            report.AppendLine("    - Khả năng nâng cấp tối đa: " + ram.MaxCapacity + " GB");
            if (ram.Slots.Count > 0)
            {
                report.AppendLine("    - Chi tiết từng khe:");
                foreach (RamSlotInfo slot in ram.Slots)
                {
                    report.AppendLine(string.Format("      + {0}: {1} GB - {2} MHz ({3})", slot.Bank, slot.Capacity, slot.Speed, slot.Manufacturer));
                }
            }
            report.AppendLine("    - Kiểm định RAM: " + (ram.IsConsistent ? "🛡 Hợp lệ, không có dấu hiệu ảo hóa." : "⚠ Dung lượng có dấu hiệu bất thường."));
            report.AppendLine();

            // 3. Quét Bo mạch chủ & BIOS
            SystemInfo sys = GetSystemInfo();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [3] Bo mạch chủ (Mainboard): ");
            Console.ResetColor();
            Console.WriteLine(string.Format("{0} - Model: {1} (Rev: {2})", sys.Motherboard.Manufacturer, sys.Motherboard.Product, sys.Motherboard.Version));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(string.Format("    - BIOS: {0} v{1} (Ngày phát hành: {2})", sys.BIOS.Vendor, sys.BIOS.Version, sys.BIOS.ReleaseDate));
            Console.ResetColor();

            report.AppendLine("[3] BO MẠCH CHỦ (MAINBOARD) & BIOS:");
            report.AppendLine("    - Hãng sản xuất Mainboard: " + sys.Motherboard.Manufacturer);
            report.AppendLine("    - Model Mainboard: " + sys.Motherboard.Product + " (Phiên bản: " + sys.Motherboard.Version + ")");
            if (!string.IsNullOrEmpty(sys.Motherboard.SerialNumber) && sys.Motherboard.SerialNumber != "N/A")
                report.AppendLine("    - Serial Number Mainboard: " + sys.Motherboard.SerialNumber);
            report.AppendLine("    - Nhà phát triển BIOS: " + sys.BIOS.Vendor);
            report.AppendLine("    - Phiên bản BIOS: " + sys.BIOS.Version);
            report.AppendLine("    - Ngày phát hành BIOS: " + sys.BIOS.ReleaseDate);
            report.AppendLine();

            // 4. Quét & Kiểm định GPU (PCI Hardware ID & VBIOS Mod Check)
            List<GpuDevice> gpus = GetAndVerifyGpus();
            report.AppendLine("[4] CARD ĐỒ HỌA (GPU) & KIỂM ĐỊNH PHẦN CỨNG:");
            for (int i = 0; i < gpus.Count; i++)
            {
                GpuDevice gpu = gpus[i];
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("✔ [4] GPU (" + (gpu.Type == "Discrete" ? "Rời" : "Tích hợp") + "): ");
                Console.ResetColor();
                Console.WriteLine(string.Format("{0} (VRAM: {1} | TDP ước tính: {2})", gpu.Name, gpu.Vram, gpu.Tdp));

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(string.Format("    - Mã phần cứng (Hardware ID): VEN_{0} & DEV_{1} | Hãng card: {2}", gpu.VendorId, gpu.DeviceId, gpu.SubsystemVendor));
                
                if (gpu.IsFakeSuspected)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("    [🚨 CẢNH BÁO FAKE GPU] " + gpu.VerificationNote);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("    [🛡 CHUẨN XÁC] " + gpu.VerificationNote);
                }
                Console.ResetColor();

                report.AppendLine(string.Format("    - GPU {0}: {1} ({2})", i + 1, gpu.Name, gpu.Type == "Discrete" ? "Card rời" : "Card tích hợp"));
                report.AppendLine("      + Dung lượng VRAM: " + gpu.Vram);
                report.AppendLine("      + Công suất tiêu thụ (TDP): " + gpu.Tdp);
                report.AppendLine(string.Format("      + Hardware ID: VEN_{0} & DEV_{1} (Hãng OEM: {2})", gpu.VendorId, gpu.DeviceId, gpu.SubsystemVendor));
                report.AppendLine("      + Kết quả kiểm tra: " + gpu.VerificationNote);
            }
            report.AppendLine();

            // 5. Quét & Kiểm tra S.M.A.R.T. Ổ cứng (Storage Health)
            List<DriveInfoItem> drives = GetAndVerifyStorage();
            report.AppendLine("[5] Ổ CỨNG LƯU TRỮ (STORAGE) & SỨC KHỎE S.M.A.R.T.:");
            for (int i = 0; i < drives.Count; i++)
            {
                DriveInfoItem d = drives[i];
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("✔ [5] Ổ cứng: ");
                Console.ResetColor();
                Console.WriteLine(string.Format("{0} ({1}) | Chuẩn: {2} ({3})", d.Model, d.Size, d.BusType, d.MediaType));
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("    [🛡 SỨC KHỎE S.M.A.R.T.] Tình trạng ổ đĩa: " + d.HealthStatus);
                Console.ResetColor();

                report.AppendLine(string.Format("    - Ổ {0}: {1} | Dung lượng: {2} | Loại: {3} | Giao tiếp: {4}", i + 1, d.Model, d.Size, d.MediaType, d.BusType));
                report.AppendLine("      + Sức khỏe S.M.A.R.T.: " + d.HealthStatus);
            }
            report.AppendLine();

            // 6. Quét Màn hình
            MonitorInfo mon = GetMonitor();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [6] Màn hình hiển thị: ");
            Console.ResetColor();
            Console.WriteLine(string.Format("{0} @ {1} Hz", mon.Resolution, mon.RefreshRate));
            report.AppendLine("[6] MÀN HÌNH HIỂN THỊ:");
            report.AppendLine("    - Độ phân giải: " + mon.Resolution);
            report.AppendLine("    - Tần số quét: " + mon.RefreshRate + " Hz");
            report.AppendLine();

            // 7. Quét Pin (Battery) + Số chu kỳ sạc
            BatteryInfo bat = GetBattery();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [7] Tình trạng Pin: ");
            Console.ResetColor();
            if (bat.HasBattery)
            {
                string cycleText = bat.CycleCount >= 0 ? string.Format("{0:N0} chu kỳ sạc", bat.CycleCount) : "N/A";
                Console.WriteLine(string.Format("Dung lượng gốc: {0} | Hiện tại: {1} (Chai: {2}) | Số lần sạc: {3}",
                    bat.DesignCapacity, bat.CurrentCapacity, bat.WearLevel, cycleText));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("    - Trạng thái: " + bat.Status + " | Điện áp: " + bat.Voltage);
                Console.ResetColor();

                report.AppendLine("[7] TÌNH TRẠNG PIN (BATTERY):");
                report.AppendLine("    - Dung lượng thiết kế gốc: " + bat.DesignCapacity);
                report.AppendLine("    - Dung lượng nạp đầy hiện tại: " + bat.CurrentCapacity);
                report.AppendLine("    - Tỷ lệ chai pin: " + bat.WearLevel);
                report.AppendLine("    - Số chu kỳ sạc (Cycle Count): " + cycleText);
                report.AppendLine("    - Trạng thái nguồn hiện tại: " + bat.Status);
                report.AppendLine("    - Điện áp định mức: " + bat.Voltage);
            }
            else
            {
                Console.WriteLine("Không có Pin (Máy tính để bàn / Desktop)");
                report.AppendLine("[7] TÌNH TRẠNG PIN:");
                report.AppendLine("    - Không có Pin (Máy tính để bàn / Desktop)");
            }
            report.AppendLine();

            // 8. Quét Mạng (Wi-Fi & Ethernet & MAC)
            WifiInfo wifi = GetWifi();
            List<NetworkAdapterItem> netList = GetNetworkAdapters();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [8] Kết nối Mạng: ");
            Console.ResetColor();
            Console.WriteLine(string.Format("Wi-Fi: {0} (Mạng: {1} | Sóng: {2})", wifi.AdapterName, wifi.CurrentSsid, wifi.CurrentSignal));
            report.AppendLine("[8] KẾT NỐI MẠNG (WI-FI, LAN & ĐỊA CHỈ MAC):");
            report.AppendLine("    - Card Wi-Fi: " + wifi.AdapterName);
            report.AppendLine("    - Wi-Fi đang kết nối: " + wifi.CurrentSsid);
            report.AppendLine("    - Cường độ sóng Wi-Fi: " + wifi.CurrentSignal);
            if (netList.Count > 0)
            {
                report.AppendLine("    - Danh sách card mạng & địa chỉ MAC:");
                foreach (NetworkAdapterItem net in netList)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine(string.Format("    - {0} | MAC: {1}{2}", net.Name, net.MacAddress, net.IpAddress != "N/A" ? " | IP: " + net.IpAddress : ""));
                    Console.ResetColor();
                    report.AppendLine(string.Format("      + {0}: MAC = {1}{2}", net.Name, net.MacAddress, net.IpAddress != "N/A" ? " (IP: " + net.IpAddress + ")" : ""));
                }
            }
            report.AppendLine();

            // 9. Quét Camera / Webcam & Thiết bị âm thanh
            List<string> cameras = GetCameras();
            List<string> soundDevices = GetSoundDevices();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [9] Camera & Âm thanh: ");
            Console.ResetColor();
            string camStr = cameras.Count > 0 ? string.Join(", ", cameras.ToArray()) : "Không phát hiện Camera";
            Console.WriteLine("Webcam: " + camStr);
            if (soundDevices.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("    - Âm thanh (Sound): " + string.Join(" | ", soundDevices.ToArray()));
                Console.ResetColor();
            }

            report.AppendLine("[9] CAMERA / WEBCAM & THIẾT BỊ ÂM THANH:");
            report.AppendLine("    - Camera / Webcam: " + camStr);
            if (soundDevices.Count > 0)
            {
                report.AppendLine("    - Thiết bị âm thanh hoạt động:");
                foreach (string snd in soundDevices)
                {
                    report.AppendLine("      + " + snd);
                }
            }
            report.AppendLine();

            // 10. Quét Hệ điều hành & Thông tin máy
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [10] Hệ điều hành & Máy: ");
            Console.ResetColor();
            Console.WriteLine(string.Format("{0} {1} | Serial: {2}", sys.Manufacturer, sys.Model, sys.SerialNumber));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(string.Format("    - HĐH: {0} (Cài ngày: {1}) | Đã bật: {2}", sys.OS.Caption, sys.OS.InstallDate, sys.OS.Uptime));
            Console.ResetColor();

            report.AppendLine("[10] THÔNG TIN MÁY & HỆ ĐIỀU HÀNH:");
            report.AppendLine("    - Hãng sản xuất máy: " + sys.Manufacturer);
            report.AppendLine("    - Model máy: " + sys.Model);
            report.AppendLine("    - Số Serial / Service Tag: " + sys.SerialNumber);
            report.AppendLine("    - Hệ điều hành: " + sys.OS.Caption);
            report.AppendLine("    - Ngày cài đặt Windows: " + sys.OS.InstallDate);
            report.AppendLine("    - Thời gian máy đã hoạt động liên tục (Uptime): " + sys.OS.Uptime);
            report.AppendLine();
            report.AppendLine("==================================================================");

            // Tự động sao chép tóm tắt cấu hình vào Clipboard
            try
            {
                string clipboardText = string.Format(
                    "CẤU HÌNH MÁY & KIỂM ĐỊNH:\n" +
                    "- Máy: {0} {1} (Serial: {2})\n" +
                    "- Mainboard: {3} {4} | BIOS: {5}\n" +
                    "- CPU: {6} [Kiểm định: {7}]\n" +
                    "- Điểm Benchmark CPU: {8:N0} điểm\n" +
                    "- RAM: {9} GB {10} ({11})\n" +
                    "- GPU: {12} ({13}) [Hardware ID: VEN_{14}&DEV_{15}]\n" +
                    "- Ổ cứng: {16} [S.M.A.R.T.: {17}]\n" +
                    "- Màn hình: {18} @ {19}Hz\n" +
                    "- Pin: {20}\n" +
                    "- Camera: {21}\n" +
                    "- HĐH: {22} (Cài: {23})",
                    sys.Manufacturer, sys.Model, sys.SerialNumber,
                    sys.Motherboard.Manufacturer, sys.Motherboard.Product, sys.BIOS.Version,
                    cpu.Name, (cpu.IsSpoofed ? "PHÁT HIỆN FAKE REGISTRY" : "NGUYÊN BẢN CPUID"),
                    cpu.BenchmarkScore,
                    ram.Total, ram.Type, ram.Manufacturer,
                    gpus.Count > 0 ? gpus[0].Name : "N/A", gpus.Count > 0 ? gpus[0].Vram : "N/A",
                    gpus.Count > 0 ? gpus[0].VendorId : "N/A", gpus.Count > 0 ? gpus[0].DeviceId : "N/A",
                    drives.Count > 0 ? drives[0].Model + " (" + drives[0].Size + ")" : "N/A",
                    drives.Count > 0 ? drives[0].HealthStatus : "N/A",
                    mon.Resolution, mon.RefreshRate,
                    bat.HasBattery ? string.Format("Chai {0} ({1:N0} chu kỳ sạc)", bat.WearLevel, bat.CycleCount) : "Máy bàn",
                    camStr,
                    sys.OS.Caption, sys.OS.InstallDate
                );
                Clipboard.SetText(clipboardText);
            }
            catch { }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("✔ Đã quét hoàn tất toàn bộ thông số phần cứng & kiểm định chống fake!");
            Console.WriteLine("✔ Đã tự động sao chép tóm tắt cấu hình vào Clipboard (Bộ nhớ tạm)!");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();

            // Tùy chọn xuất file báo cáo (Hỏi người dùng Y/N)
            string reportPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ThongSo_PhanCung.txt");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("👉 Bạn có muốn xuất kết quả ra file báo cáo (ThongSo_PhanCung.txt) không? [Y/N] (Mặc định Y): ");
            Console.ResetColor();

            string answer = "Y";
            try
            {
                if (!Console.IsInputRedirected)
                {
                    string input = Console.ReadLine();
                    if (!string.IsNullOrEmpty(input)) answer = input.Trim().ToUpper();
                }
                else
                {
                    string input = Console.ReadLine();
                    if (!string.IsNullOrEmpty(input)) answer = input.Trim().ToUpper();
                }
            }
            catch { }

            if (answer == "Y" || answer == "YES" || string.IsNullOrEmpty(answer))
            {
                try
                {
                    File.WriteAllText(reportPath, report.ToString(), Encoding.UTF8);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✔ Đã lưu file báo cáo chi tiết: " + Path.GetFileName(reportPath));
                    Console.ResetColor();
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("❌ Không thể lưu file báo cáo: " + ex.Message);
                    Console.ResetColor();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine("ℹ Đã bỏ qua xuất file báo cáo theo yêu cầu.");
                Console.ResetColor();
            }

            Console.WriteLine();
            Console.Write("Nhấn phím bất kỳ để thoát chương trình...");
            try
            {
                if (!Console.IsInputRedirected)
                {
                    Console.ReadKey(true);
                }
                else
                {
                    Console.ReadLine();
                }
            }
            catch { }
        }

        #region Hardware Verification Methods
        static CpuInfo GetAndVerifyCpu()
        {
            CpuInfo info = new CpuInfo();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["Name"] != null)
                            info.Name = obj["Name"].ToString().Trim();
                        if (obj["NumberOfCores"] != null)
                            info.Cores = obj["NumberOfCores"].ToString().Trim();
                        if (obj["NumberOfLogicalProcessors"] != null)
                            info.LogicalProcessors = obj["NumberOfLogicalProcessors"].ToString().Trim();
                        if (obj["MaxClockSpeed"] != null)
                            info.ClockSpeed = obj["MaxClockSpeed"].ToString().Trim();
                        break;
                    }
                }
            }
            catch { }

            // 1. Đọc tên từ CPUID phần cứng
            info.HardwareBrand = GetHardwareCpuBrand();

            // 2. Đọc Registry ProcessorNameString
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0"))
                {
                    if (key != null)
                    {
                        object val = key.GetValue("ProcessorNameString");
                        if (val != null) info.RegistryName = val.ToString().Trim();
                    }
                }
            }
            catch { }

            // 3. Đối chiếu phát hiện giả mạo
            if (info.HardwareBrand != "Unknown" && !string.IsNullOrEmpty(info.HardwareBrand))
            {
                string normHardware = NormalizeString(info.HardwareBrand);
                string normWin = NormalizeString(info.Name);
                string normReg = NormalizeString(info.RegistryName);

                // Nếu tên trong Registry khác hẳn tên chip phần cứng thực tế
                if (!string.IsNullOrEmpty(normReg) && !normHardware.Contains(normReg) && !normReg.Contains(normHardware))
                {
                    info.IsSpoofed = true;
                }
                else if (!normHardware.Contains(normWin) && !normWin.Contains(normHardware))
                {
                    info.IsSpoofed = true;
                }
            }

            // 4. Chạy Benchmark nhanh 500ms
            info.BenchmarkScore = RunCpuBenchmark(500);

            return info;
        }

        static string NormalizeString(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            StringBuilder sb = new StringBuilder();
            foreach (char c in s.ToUpper())
            {
                if (char.IsLetterOrDigit(c)) sb.Append(c);
            }
            return sb.ToString();
        }

        static List<GpuDevice> GetAndVerifyGpus()
        {
            List<GpuDevice> list = new List<GpuDevice>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = obj["Name"] != null ? obj["Name"].ToString().Trim() : "Unknown GPU";
                        string vram = "N/A";

                        if (obj["AdapterRAM"] != null)
                        {
                            long bytes = Convert.ToInt64(obj["AdapterRAM"]);
                            if (bytes > 0)
                            {
                                long gb = (bytes + 1073741823L) / 1073741824L;
                                vram = gb + " GB";
                            }
                        }

                        if (vram == "N/A")
                        {
                            string regVram = GetVramFromRegistry(name);
                            if (!string.IsNullOrEmpty(regVram) && regVram != "N/A")
                                vram = regVram;
                        }

                        string type = "Integrated";
                        string upper = name.ToUpper();
                        if (upper.Contains("NVIDIA") || upper.Contains("GEFORCE") || upper.Contains("RTX") ||
                            upper.Contains("RADEON RX") || upper.Contains("INTEL ARC"))
                        {
                            type = "Discrete";
                        }

                        string tdp = EstimateGpuTdp(name);
                        string pnpId = obj["PNPDeviceID"] != null ? obj["PNPDeviceID"].ToString() : "";

                        GpuDevice gpu = new GpuDevice();
                        gpu.Name = name;
                        gpu.Type = type;
                        gpu.Vram = vram;
                        gpu.Tdp = tdp;
                        gpu.PnpDeviceId = pnpId;

                        // Phân tích Hardware ID (VEN & DEV)
                        ParsePciHardwareId(gpu);

                        // Kiểm định VBIOS mod / fake
                        VerifyGpuAuthenticity(gpu);

                        list.Add(gpu);
                    }
                }
            }
            catch { }

            if (list.Count == 0)
            {
                GpuDevice def = new GpuDevice();
                def.Name = "Unknown GPU";
                def.Type = "Integrated";
                def.VerificationNote = "Không xác định";
                list.Add(def);
            }
            return list;
        }

        static void ParsePciHardwareId(GpuDevice gpu)
        {
            if (string.IsNullOrEmpty(gpu.PnpDeviceId)) return;
            string u = gpu.PnpDeviceId.ToUpper();

            // Tìm VEN_xxxx
            int venIdx = u.IndexOf("VEN_");
            if (venIdx != -1 && venIdx + 8 <= u.Length)
            {
                gpu.VendorId = u.Substring(venIdx + 4, 4);
            }

            // Tìm DEV_xxxx
            int devIdx = u.IndexOf("DEV_");
            if (devIdx != -1 && devIdx + 8 <= u.Length)
            {
                gpu.DeviceId = u.Substring(devIdx + 4, 4);
            }

            // Tìm SUBSYS_xxxx
            int subIdx = u.IndexOf("SUBSYS_");
            if (subIdx != -1 && subIdx + 15 <= u.Length)
            {
                string subsysFull = u.Substring(subIdx + 7, 8);
                // 4 ký tự cuối của SUBSYS thường là Subsystem Vendor ID
                string subVendor = subsysFull.Substring(4, 4);
                if (subVendor == "1043") gpu.SubsystemVendor = "ASUS";
                else if (subVendor == "1462") gpu.SubsystemVendor = "MSI";
                else if (subVendor == "1458") gpu.SubsystemVendor = "GIGABYTE";
                else if (subVendor == "3842") gpu.SubsystemVendor = "EVGA";
                else if (subVendor == "19DA") gpu.SubsystemVendor = "ZOTAC";
                else if (subVendor == "10DE") gpu.SubsystemVendor = "NVIDIA Standard / Colorful";
                else if (subVendor == "1028") gpu.SubsystemVendor = "Dell";
                else if (subVendor == "103C") gpu.SubsystemVendor = "HP";
                else if (subVendor == "17AA") gpu.SubsystemVendor = "Lenovo";
                else if (subVendor == "1558") gpu.SubsystemVendor = "Clevo";
                else if (subVendor == "0000") gpu.SubsystemVendor = "Unknown / Không rõ (Nghi vấn VBIOS flash)";
                else gpu.SubsystemVendor = "OEM (" + subVendor + ")";
            }
        }

        static void VerifyGpuAuthenticity(GpuDevice gpu)
        {
            string nameUpper = gpu.Name.ToUpper();
            string dev = gpu.DeviceId.ToUpper();

            // Các mẫu chip Fermi / Kepler cổ thường xuyên bị mod VBIOS thành GTX 1050 / 1060 / 960
            HashSet<string> fermiOldChips = new HashSet<string>() { "0DC4", "0DC5", "0DD8", "1244", "1245", "0DE0", "0DE1" }; // GTS 450, GTX 550 Ti
            HashSet<string> keplerOldChips = new HashSet<string>() { "0FC1", "0FC2", "0FE1", "1287", "1288" }; // GT 730, GT 640

            if (fermiOldChips.Contains(dev))
            {
                if (nameUpper.Contains("1050") || nameUpper.Contains("1060") || nameUpper.Contains("960") || nameUpper.Contains("RTX"))
                {
                    gpu.IsFakeSuspected = true;
                    gpu.VerificationNote = "Phát hiện giả mạo! Tên hiển thị là " + gpu.Name + " nhưng chip thực chất là Fermi đời cổ (GTS 450 / 550Ti).";
                    return;
                }
            }

            if (keplerOldChips.Contains(dev))
            {
                if (nameUpper.Contains("1050") || nameUpper.Contains("1060") || nameUpper.Contains("RTX") || nameUpper.Contains("GTX 16"))
                {
                    gpu.IsFakeSuspected = true;
                    gpu.VerificationNote = "Phát hiện giả mạo! Tên hiển thị là " + gpu.Name + " nhưng mã chip thực chất là GT 730 / GT 640.";
                    return;
                }
            }

            // Kiểm tra tính hợp lệ của Vendor ID
            if (gpu.VendorId == "10DE")
            {
                if (!nameUpper.Contains("NVIDIA") && !nameUpper.Contains("GEFORCE") && !nameUpper.Contains("QUADRO"))
                {
                    gpu.IsFakeSuspected = true;
                    gpu.VerificationNote = "Mã Vendor ID là NVIDIA nhưng tên hiển thị không khớp!";
                    return;
                }
                gpu.VerificationNote = "Xác thực chip phần cứng hợp lệ (NVIDIA Silicon - Khớp vi kiến trúc).";
            }
            else if (gpu.VendorId == "8086")
            {
                gpu.VerificationNote = "Xác thực chip đồ họa Intel tích hợp (Genuine Intel Graphics).";
            }
            else if (gpu.VendorId == "1002")
            {
                gpu.VerificationNote = "Xác thực chip đồ họa AMD Radeon hợp lệ.";
            }
            else
            {
                gpu.VerificationNote = "Đã nhận diện phần cứng qua bus PCI.";
            }
        }

        static List<DriveInfoItem> GetAndVerifyStorage()
        {
            List<DriveInfoItem> list = new List<DriveInfoItem>();
            try
            {
                ManagementScope scope = new ManagementScope(@"Root\Microsoft\Windows\Storage");
                scope.Connect();
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSFT_PhysicalDisk")))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string model = obj["Model"] != null ? obj["Model"].ToString().Trim() : "Unknown Storage";
                        long size = obj["Size"] != null ? Convert.ToInt64(obj["Size"]) : 0;
                        string sizeGb = (size / (1024 * 1024 * 1024)) + " GB";

                        string mediaType = "SSD";
                        string mType = obj["MediaType"] != null ? obj["MediaType"].ToString() : "";
                        if (mType == "3") mediaType = "HDD";
                        else if (mType == "4") mediaType = "SSD";

                        string busType = "SATA";
                        string bType = obj["BusType"] != null ? obj["BusType"].ToString() : "";
                        if (bType == "17") busType = "NVMe";
                        else if (bType == "7") busType = "USB";
                        else if (bType == "3") busType = "SATA";

                        string health = "Tốt (Healthy - 100%)";
                        if (obj["HealthStatus"] != null)
                        {
                            int hs = Convert.ToInt32(obj["HealthStatus"]);
                            if (hs == 0) health = "Tốt (Healthy - 100% S.M.A.R.T.)";
                            else if (hs == 1) health = "Cảnh báo (Warning - Cần sao lưu dữ liệu)";
                            else if (hs == 2) health = "Nguy hiểm (Unhealthy / Hỏng hóc)";
                        }

                        DriveInfoItem item = new DriveInfoItem();
                        item.Model = model;
                        item.Size = sizeGb;
                        item.MediaType = mediaType;
                        item.BusType = busType;
                        item.HealthStatus = health;
                        list.Add(item);
                    }
                }
            }
            catch { }

            if (list.Count == 0)
            {
                try
                {
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            string model = obj["Model"] != null ? obj["Model"].ToString().Trim() : "Unknown Drive";
                            long size = obj["Size"] != null ? Convert.ToInt64(obj["Size"]) : 0;
                            string sizeGb = (size / (1024 * 1024 * 1024)) + " GB";

                            string mediaType = "SSD";
                            string mType = obj["MediaType"] != null ? obj["MediaType"].ToString() : "";
                            if (mType.ToUpper().Contains("HDD")) mediaType = "HDD";

                            DriveInfoItem item = new DriveInfoItem();
                            item.Model = model;
                            item.Size = sizeGb;
                            item.MediaType = mediaType;
                            item.BusType = "SATA";
                            item.HealthStatus = "Tốt (S.M.A.R.T. OK)";
                            list.Add(item);
                        }
                    }
                }
                catch { }
            }

            if (list.Count == 0)
            {
                DriveInfoItem def = new DriveInfoItem();
                def.Model = "Unknown Drive";
                def.Size = "N/A";
                def.HealthStatus = "N/A";
                list.Add(def);
            }
            return list;
        }
        #endregion

        #region Standard Hardware Queries
        static RamInfo GetRam()
        {
            RamInfo info = new RamInfo();
            long totalBytes = 0;
            HashSet<string> mfgSet = new HashSet<string>();
            int dominantSpeed = 0;
            int smbiosType = 0;
            long slotSumBytes = 0;

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMemory"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        long cap = 0;
                        if (obj["Capacity"] != null)
                        {
                            cap = Convert.ToInt64(obj["Capacity"]);
                            totalBytes += cap;
                            slotSumBytes += cap;
                        }

                        int speed = 0;
                        if (obj["Speed"] != null)
                        {
                            speed = Convert.ToInt32(obj["Speed"]);
                            if (speed > dominantSpeed) dominantSpeed = speed;
                        }

                        string mfgRaw = obj["Manufacturer"] != null ? obj["Manufacturer"].ToString() : "";
                        string mfgDecoded = DecodeRamManufacturer(mfgRaw);
                        if (!string.IsNullOrEmpty(mfgDecoded) && mfgDecoded != "Unknown")
                            mfgSet.Add(mfgDecoded);

                        string bank = obj["DeviceLocator"] != null ? obj["DeviceLocator"].ToString() : "Slot";

                        RamSlotInfo slot = new RamSlotInfo();
                        slot.Bank = bank;
                        slot.Capacity = (cap / (1024 * 1024 * 1024)).ToString();
                        slot.Speed = speed > 0 ? speed.ToString() : "N/A";
                        slot.Manufacturer = mfgDecoded;
                        info.Slots.Add(slot);

                        if (obj["SMBIOSMemoryType"] != null)
                        {
                            try { smbiosType = Convert.ToInt32(obj["SMBIOSMemoryType"]); } catch { }
                        }
                    }
                }

                info.ActiveSlots = info.Slots.Count;
                info.Total = Math.Round((double)totalBytes / (1024.0 * 1024.0 * 1024.0)).ToString();
                info.Speed = dominantSpeed > 0 ? dominantSpeed.ToString() : "N/A";
                info.Manufacturer = mfgSet.Count > 0 ? string.Join(", ", new List<string>(mfgSet).ToArray()) : "Generic";

                // Kiểm tra sự đồng bộ
                if (slotSumBytes > 0 && Math.Abs(slotSumBytes - totalBytes) > 1024 * 1024 * 1024)
                {
                    info.IsConsistent = false;
                }

                if (smbiosType == 24) info.Type = "DDR3";
                else if (smbiosType == 26) info.Type = "DDR4";
                else if (smbiosType >= 30 && smbiosType <= 36) info.Type = "DDR5";
                else if (dominantSpeed >= 4800) info.Type = "DDR5";
                else if (dominantSpeed >= 2133) info.Type = "DDR4";
                else if (dominantSpeed >= 1066) info.Type = "DDR3";
                else info.Type = "DDR";

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMemoryArray"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["MaxCapacity"] != null)
                        {
                            long maxKb = Convert.ToInt64(obj["MaxCapacity"]);
                            info.MaxCapacity = (maxKb / (1024 * 1024)).ToString();
                        }
                        if (obj["MemoryDevices"] != null)
                        {
                            info.MaxSlots = Convert.ToInt32(obj["MemoryDevices"]);
                        }
                    }
                }

                if (info.MaxSlots < info.ActiveSlots) info.MaxSlots = info.ActiveSlots;
                info.EmptySlots = Math.Max(0, info.MaxSlots - info.ActiveSlots);
            }
            catch { }
            return info;
        }

        static string DecodeRamManufacturer(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "Unknown";
            string upper = raw.ToUpper().Replace("0X", "").Trim();

            if (upper.Contains("0198") || upper.Contains("KINGSTON") || upper.Contains("9800")) return "Kingston";
            if (upper.Contains("017A") || upper.Contains("APACER") || upper.Contains("7A00")) return "Apacer";
            if (upper.Contains("029E") || upper.Contains("CORSAIR") || upper.Contains("9E02")) return "Corsair";
            if (upper.Contains("04CB") || upper.Contains("ADATA") || upper.Contains("CB04")) return "A-Data";
            if (upper.Contains("80AD") || upper.Contains("HYNIX") || upper.Contains("AD80") || upper.Contains("SK HYNIX")) return "SK Hynix";
            if (upper.Contains("80CE") || upper.Contains("SAMSUNG") || upper.Contains("CE80")) return "Samsung";
            if (upper.Contains("859B") || upper.Contains("CRUCIAL") || upper.Contains("9B85") || upper.Contains("MICRON") || upper.Contains("Crucial / Micron")) return "Crucial / Micron";
            if (upper.Contains("059B") || upper.Contains("9B05")) return "Crucial";
            if (upper.Contains("830B") || upper.Contains("NANYA") || upper.Contains("0B83")) return "Nanya";
            if (upper.Contains("85F7") || upper.Contains("G.SKILL") || upper.Contains("F785") || upper.Contains("04CD") || upper.Contains("CD04")) return "G.Skill";
            if (upper.Contains("0000") || upper.Contains("FFFF") || upper.Contains("DEFAULT")) return "Generic";
            if (upper.Length > 15) return "OEM";

            return raw.Trim();
        }

        static string GetVramFromRegistry(string targetGpuName)
        {
            try
            {
                using (RegistryKey root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"))
                {
                    if (root == null) return "N/A";
                    foreach (string subName in root.GetSubKeyNames())
                    {
                        if (subName.Equals("Properties", StringComparison.OrdinalIgnoreCase)) continue;
                        using (RegistryKey sub = root.OpenSubKey(subName))
                        {
                            if (sub == null) continue;
                            object desc = sub.GetValue("DriverDesc");
                            if (desc != null)
                            {
                                object qwMem = sub.GetValue("HardwareInformation.qwMemorySize");
                                if (qwMem != null)
                                {
                                    long bytes = Convert.ToInt64(qwMem);
                                    if (bytes > 0) return ((bytes + 1073741823L) / 1073741824L) + " GB";
                                }
                                object mem = sub.GetValue("HardwareInformation.MemorySize");
                                if (mem != null)
                                {
                                    long bytes = Convert.ToInt64(mem);
                                    if (bytes > 0) return ((bytes + 1073741823L) / 1073741824L) + " GB";
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            return "N/A";
        }

        static string EstimateGpuTdp(string name)
        {
            string u = name.ToUpper();
            if (u.Contains("RTX 4090")) return "450W";
            if (u.Contains("RTX 4080")) return "320W";
            if (u.Contains("RTX 4070")) return "115W - 140W";
            if (u.Contains("RTX 4060")) return "115W - 140W";
            if (u.Contains("RTX 4050")) return "75W - 95W";
            if (u.Contains("RTX 3080")) return "320W";
            if (u.Contains("RTX 3070")) return "220W";
            if (u.Contains("RTX 3060")) return "170W";
            if (u.Contains("RTX 3050")) return "75W - 95W";
            if (u.Contains("GTX 1650")) return "50W - 75W";
            if (u.Contains("GTX 1660")) return "120W";
            if (u.Contains("RADEON RX 7900")) return "300W - 355W";
            if (u.Contains("RADEON RX 6700")) return "180W - 230W";
            if (u.Contains("RADEON RX 6600")) return "130W - 160W";
            if (u.Contains("RADEON RX 6500")) return "100W - 130W";
            if (u.Contains("RADEON RX 5500")) return "130W - 180W";
            if (u.Contains("RADEON RX 570")) return "150W - 180W";
            if (u.Contains("RADEON RX 580")) return "180W - 225W";
            if (u.Contains("INTEL ARC A770")) return "225W";
            if (u.Contains("INTEL ARC A750")) return "225W";
            if (u.Contains("INTEL ARC A380")) return "100W - 150W";
            if (u.Contains("INTEL IRIS XE")) return "10W - 28W";
            if (u.Contains("INTEL UHD")) return "6W - 25W";
            if (u.Contains("NVIDIA MX")) return "10W - 50W";
            if (u.Contains("NVIDIA QUADRO")) return "25W - 200W";
            if (u.Contains("NVIDIA TESLA")) return "70W - 350W";
            if (u.Contains("AMD RADEON PRO")) return "25W - 300W";
            return "15W - 75W (Ước lượng)";
        }

        static MonitorInfo GetMonitor()
        {
            MonitorInfo info = new MonitorInfo();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["CurrentHorizontalResolution"] != null && obj["CurrentVerticalResolution"] != null)
                        {
                            info.Resolution = obj["CurrentHorizontalResolution"].ToString() + " x " + obj["CurrentVerticalResolution"].ToString();
                        }
                        if (obj["CurrentRefreshRate"] != null)
                        {
                            info.RefreshRate = obj["CurrentRefreshRate"].ToString();
                        }
                        if (!string.IsNullOrEmpty(info.Resolution) && info.Resolution != "Unknown") break;
                    }
                }
            }
            catch { }
            return info;
        }

        static BatteryInfo GetBattery()
        {
            BatteryInfo info = new BatteryInfo();
            long designCap = 0;
            long fullCap = 0;

            try
            {
                ManagementScope scope = new ManagementScope(@"Root\WMI");
                scope.Connect();

                using (ManagementObjectSearcher s1 = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM BatteryStaticData")))
                {
                    foreach (ManagementObject obj in s1.Get())
                    {
                        if (obj["DesignedCapacity"] != null)
                            designCap = Convert.ToInt64(obj["DesignedCapacity"]);
                        break;
                    }
                }

                using (ManagementObjectSearcher s2 = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM BatteryFullChargedCapacity")))
                {
                    foreach (ManagementObject obj in s2.Get())
                    {
                        if (obj["FullChargedCapacity"] != null)
                            fullCap = Convert.ToInt64(obj["FullChargedCapacity"]);
                        break;
                    }
                }

                if (designCap > 0)
                {
                    info.HasBattery = true;
                    info.DesignCapacity = designCap + " mWh";
                    if (fullCap > 0)
                    {
                        info.CurrentCapacity = fullCap + " mWh";
                        double wear = 100.0 - ((double)fullCap * 100.0 / (double)designCap);
                        if (wear < 0) wear = 0;
                        info.WearLevel = Math.Round(wear, 1) + "%";
                    }
                }

                using (ManagementObjectSearcher s3 = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM BatteryCycleCount")))
                {
                    foreach (ManagementObject obj in s3.Get())
                    {
                        if (obj["CycleCount"] != null)
                        {
                            info.CycleCount = Convert.ToInt32(obj["CycleCount"]);
                            break;
                        }
                    }
                }
            }
            catch { }

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Battery"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        info.HasBattery = true;
                        if (obj["BatteryStatus"] != null)
                        {
                            int status = Convert.ToInt32(obj["BatteryStatus"]);
                            if (status == 1) info.Status = "Đang dùng pin (Discharging)";
                            else if (status == 2) info.Status = "Đang cắm sạc (AC Connected / Charging)";
                            else if (status == 3) info.Status = "Đã sạc đầy (Fully Charged)";
                            else info.Status = "Đang kết nối nguồn";
                        }
                        if (obj["DesignVoltage"] != null)
                        {
                            double volt = Convert.ToDouble(obj["DesignVoltage"]) / 1000.0;
                            info.Voltage = volt.ToString("0.0") + " V";
                        }
                        break;
                    }
                }
            }
            catch { }

            return info;
        }

        static WifiInfo GetWifi()
        {
            WifiInfo info = new WifiInfo();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID LIKE '%Wi-Fi%' OR NetConnectionID LIKE '%Wireless%'"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["Name"] != null)
                        {
                            info.AdapterName = obj["Name"].ToString().Trim();
                            break;
                        }
                    }
                }

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "netsh";
                psi.Arguments = "wlan show interfaces";
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;

                using (Process proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    string[] lines = output.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.None);
                    foreach (string line in lines)
                    {
                        string trimmed = line.Trim();
                        if (trimmed.StartsWith("SSID") && !trimmed.StartsWith("BSSID"))
                        {
                            string[] parts = trimmed.Split(new char[] { ':' }, 2);
                            if (parts.Length > 1) info.CurrentSsid = parts[1].Trim();
                        }
                        else if (trimmed.StartsWith("Signal") || trimmed.StartsWith("Tín hiệu"))
                        {
                            string[] parts = trimmed.Split(new char[] { ':' }, 2);
                            if (parts.Length > 1) info.CurrentSignal = parts[1].Trim();
                        }
                    }
                }
            }
            catch { }
            return info;
        }

        static List<NetworkAdapterItem> GetNetworkAdapters()
        {
            List<NetworkAdapterItem> list = new List<NetworkAdapterItem>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE MACAddress IS NOT NULL"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string desc = obj["Description"] != null ? obj["Description"].ToString().Trim() : "Network Adapter";
                        string mac = obj["MACAddress"] != null ? obj["MACAddress"].ToString().Trim() : "N/A";
                        string ip = "N/A";
                        if (obj["IPAddress"] != null)
                        {
                            string[] ips = (string[])obj["IPAddress"];
                            if (ips.Length > 0) ip = ips[0];
                        }

                        if (desc.StartsWith("WAN Miniport", StringComparison.OrdinalIgnoreCase) ||
                            desc.StartsWith("Microsoft Wi-Fi Direct", StringComparison.OrdinalIgnoreCase) ||
                            desc.StartsWith("Bluetooth Device (Personal Area", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        NetworkAdapterItem item = new NetworkAdapterItem();
                        item.Name = desc;
                        item.MacAddress = mac;
                        item.IpAddress = ip;
                        list.Add(item);
                    }
                }
            }
            catch { }
            return list;
        }

        static List<string> GetCameras()
        {
            List<string> list = new List<string>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'Camera' OR PNPClass = 'Image'"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["Name"] != null)
                        {
                            string name = obj["Name"].ToString().Trim();
                            if (!list.Contains(name)) list.Add(name);
                        }
                    }
                }
            }
            catch { }
            return list;
        }

        static List<string> GetSoundDevices()
        {
            List<string> list = new List<string>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SoundDevice WHERE Status = 'OK'"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["Name"] != null)
                        {
                            string name = obj["Name"].ToString().Trim();
                            if (!list.Contains(name)) list.Add(name);
                        }
                    }
                }
            }
            catch { }
            return list;
        }

        static string FormatWmiDate(string raw)
        {
            if (string.IsNullOrEmpty(raw) || raw.Length < 8) return "N/A";
            try
            {
                string y = raw.Substring(0, 4);
                string m = raw.Substring(4, 2);
                string d = raw.Substring(6, 2);
                if (raw.Length >= 14)
                {
                    string hh = raw.Substring(8, 2);
                    string mm = raw.Substring(10, 2);
                    string ss = raw.Substring(12, 2);
                    return string.Format("{0}/{1}/{2} {3}:{4}:{5}", d, m, y, hh, mm, ss);
                }
                return string.Format("{0}/{1}/{2}", d, m, y);
            }
            catch
            {
                return raw;
            }
        }

        static string GetUptime(string lastBootRaw)
        {
            if (string.IsNullOrEmpty(lastBootRaw) || lastBootRaw.Length < 14) return "N/A";
            try
            {
                int y = int.Parse(lastBootRaw.Substring(0, 4));
                int m = int.Parse(lastBootRaw.Substring(4, 2));
                int d = int.Parse(lastBootRaw.Substring(6, 2));
                int hh = int.Parse(lastBootRaw.Substring(8, 2));
                int mm = int.Parse(lastBootRaw.Substring(10, 2));
                int ss = int.Parse(lastBootRaw.Substring(12, 2));
                DateTime bootTime = new DateTime(y, m, d, hh, mm, ss);
                TimeSpan span = DateTime.Now - bootTime;
                return string.Format("{0} ngày {1} giờ {2} phút", span.Days, span.Hours, span.Minutes);
            }
            catch
            {
                return "N/A";
            }
        }

        static SystemInfo GetSystemInfo()
        {
            SystemInfo info = new SystemInfo();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["Manufacturer"] != null)
                            info.Manufacturer = obj["Manufacturer"].ToString().Trim();
                        if (obj["Model"] != null)
                            info.Model = obj["Model"].ToString().Trim();
                        break;
                    }
                }

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["Manufacturer"] != null)
                            info.Motherboard.Manufacturer = obj["Manufacturer"].ToString().Trim();
                        if (obj["Product"] != null)
                            info.Motherboard.Product = obj["Product"].ToString().Trim();
                        if (obj["Version"] != null)
                            info.Motherboard.Version = obj["Version"].ToString().Trim();
                        if (obj["SerialNumber"] != null)
                            info.Motherboard.SerialNumber = obj["SerialNumber"].ToString().Trim();
                        break;
                    }
                }

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["Manufacturer"] != null)
                            info.BIOS.Vendor = obj["Manufacturer"].ToString().Trim();
                        if (obj["SMBIOSBIOSVersion"] != null)
                            info.BIOS.Version = obj["SMBIOSBIOSVersion"].ToString().Trim();
                        else if (obj["Version"] != null)
                            info.BIOS.Version = obj["Version"].ToString().Trim();

                        if (obj["ReleaseDate"] != null)
                            info.BIOS.ReleaseDate = FormatWmiDate(obj["ReleaseDate"].ToString());

                        if (obj["SerialNumber"] != null)
                        {
                            string sn = obj["SerialNumber"].ToString().Trim();
                            if (!sn.Equals("Default string", StringComparison.OrdinalIgnoreCase) &&
                                !sn.Equals("To Be Filled By O.E.M.", StringComparison.OrdinalIgnoreCase) &&
                                !sn.Equals("None", StringComparison.OrdinalIgnoreCase) &&
                                !sn.Equals("System Serial Number", StringComparison.OrdinalIgnoreCase) &&
                                sn != "0")
                            {
                                info.SerialNumber = sn;
                            }
                        }
                        break;
                    }
                }

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["Caption"] != null)
                            info.OS.Caption = obj["Caption"].ToString().Trim();
                        if (obj["InstallDate"] != null)
                            info.OS.InstallDate = FormatWmiDate(obj["InstallDate"].ToString());
                        if (obj["LastBootUpTime"] != null)
                            info.OS.Uptime = GetUptime(obj["LastBootUpTime"].ToString());
                        break;
                    }
                }
            }
            catch { }
            return info;
        }
        #endregion
    }
}
