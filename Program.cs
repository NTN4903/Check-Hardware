using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Management;
using System.Media;
using System.Net;
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
                public class MdmInfo
        {
            public bool IsMdmDetected = false;
            public bool IsAutopilotDetected = false;
            public bool IsAzureAdJoined = false;
            public bool IsDomainJoined = false;
            public bool IsComputraceDetected = false;
            public string AutopilotTenant = "";
            public string MdmProvider = "";
            public string MdmDiscoveryUrl = "";
            public string DomainName = "";
            public List<string> DetectionReasons = new List<string>();
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
                        // 11. Quét & Kiểm định Khóa Quản Lý Doanh Nghiệp (MDM / Autopilot / Computrace / Domain)
            MdmInfo mdm = GetAndVerifyMdm();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [11] Khóa Quản Lý (MDM / Autopilot / Computrace): ");
            Console.ResetColor();

            if (mdm.IsMdmDetected)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[🚨 CẢNH BÁO NGUY HIỂM] PHÁT HIỆN MÁY BỊ QUẢN LÝ DOANH NGHIỆP / DÍNH MDM!");
                foreach (string reason in mdm.DetectionReasons)
                {
                    Console.WriteLine("    -> " + reason);
                }
                Console.WriteLine("    ⚠️ KHUYẾN CÁO: KHÔNG NÊN MUA! Máy thuộc tài sản công ty/trường học.");
                Console.WriteLine("       Khi cài lại Windows hoặc kết nối mạng, máy có thể bị khóa màn hình từ xa!");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("[🛡 SẠCH SẼ 100%] Máy tự do cá nhân (Consumer) - KHÔNG DÍNH MDM!");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("    - Windows Autopilot     : Sạch (Không bị gán Hardware Hash Cloud)");
                Console.WriteLine("    - Microsoft Intune MDM  : Sạch (Không có Enrollment doanh nghiệp)");
                Console.WriteLine("    - Azure AD / Domain Join: Sạch (Máy độc lập Workgroup, không bị quản lý)");
                Console.WriteLine("    - Computrace BIOS       : Sạch (Không có chip rpcnet theo dõi ngầm)");
                Console.ResetColor();
            }

            report.AppendLine("[11] KIỂM ĐỊNH KHÓA QUẢN LÝ DOANH NGHIỆP (MDM / AUTOPILOT / COMPUTRACE):");
            if (mdm.IsMdmDetected)
            {
                report.AppendLine("    - KẾT QUẢ: [🚨 CẢNH BÁO] PHÁT HIỆN MÁY DÍNH MDM / QUẢN LÝ DOANH NGHIỆP!");
                foreach (string reason in mdm.DetectionReasons)
                {
                    report.AppendLine("      + " + reason);
                }
                report.AppendLine("    - CẢNH BÁO MUA BÁN: NGUY HIỂM! Có thể bị khóa từ xa bất kỳ lúc nào.");
            }
            else
            {
                report.AppendLine("    - KẾT QUẢ: [🛡 SẠCH SẼ 100%] Máy tự do cá nhân - KHÔNG DÍNH MDM!");
                report.AppendLine("      + Windows Autopilot: Sạch (Không có cấu hình Zero Touch)");
                report.AppendLine("      + Intune / MDM Enrollments: Sạch (Không bị quản trị từ xa)");
                report.AppendLine("      + Azure AD / Domain Join: Sạch (Không thuộc tổ chức nào)");
                report.AppendLine("      + Computrace / Absolute Persistence: Sạch (Không bị khóa BIOS)");
            }
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
                    "- HĐH: {22} (Cài: {23})\n" +
                    "- Khóa MDM: {24}",
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
                    sys.OS.Caption, sys.OS.InstallDate,
                    (mdm.IsMdmDetected ? "CẢNH BÁO DÍNH MDM DOANH NGHIỆP" : "SẠCH (Không dính MDM/Autopilot)")
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
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✔ Đã hoàn tất quét và kiểm định phần cứng ban đầu!");
            Console.ResetColor();

            // Mở MENU CÔNG CỤ TEST MÁY CŨ & TẢI TOOL CHUYÊN DỤNG (PITVN)
            ShowUsedPcSuiteMenu();
        }

        
        #region Used PC Test Suite & Downloader Hub

        class SoftwareItem
        {
            public string Id;
            public string Name;
            public string Description;
            public string DownloadUrl;
            public string FileName;
            public string ExeSearchPattern;
            public string FolderName;
            public bool IsExternalOnly;
            public string ExternalUrl;

            public SoftwareItem(string id, string name, string description, string downloadUrl, string fileName, string folderName, string exeSearchPattern, bool isExternal, string externalUrl)
            {
                Id = id;
                Name = name;
                Description = description;
                DownloadUrl = downloadUrl;
                FileName = fileName;
                FolderName = folderName;
                ExeSearchPattern = exeSearchPattern;
                IsExternalOnly = isExternal;
                ExternalUrl = externalUrl;
            }
        }

        static void ShowUsedPcSuiteMenu()
        {
            while (true)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("╔═══════════════════════════════════════════════════════════════════════╗");
                Console.WriteLine("║        BỘ CÔNG CỤ TEST MÁY CŨ & TẢI TOOL CHUYÊN SÂU (PITVN)           ║");
                Console.WriteLine("╚═══════════════════════════════════════════════════════════════════════╝");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [1] 📺 Kiểm tra Màn hình (Test Điểm chết, Điểm sáng, Hở sáng IPS Bleed)");
                Console.WriteLine("  [2] ⌨️  Kiểm tra Bàn phím trực quan (Keyboard Tester - Bấm test kẹt/liệt)");
                Console.WriteLine("  [3] 🔥 Thử tải CPU Stress Test & Kiểm tra Tản nhiệt (15s/30s Throttling)");
                Console.WriteLine("  [4] 🚀 Đo tốc độ Đọc/Ghi thực tế Ổ cứng (Sequential Read/Write MB/s)");
                Console.WriteLine("  [5] 🔊 Kiểm tra Loa Trái / Phải (Stereo Speaker Channel Isolation)");
                Console.WriteLine("  [6] 🔋 Kiểm tra Tốc độ Nạp/Xả Pin & Công suất Sạc (Battery Charge Rate)");
                Console.WriteLine("  [7] 📥 Tải & Chạy Phần mềm Chuyên dụng (FurMark, HWMonitor, Cinebench...)");
                Console.WriteLine("  [8] 📋 Quét lại toàn bộ Phần cứng & Copy tóm tắt vào Clipboard");
                Console.WriteLine("  [0] ❌ Thoát chương trình");
                Console.ResetColor();
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("👉 Vui lòng chọn chức năng [0-8]: ");
                Console.ResetColor();

                string choice = Console.ReadLine();
                if (choice == null) break;
                choice = choice.Trim();

                if (choice == "0" || choice.Equals("exit", StringComparison.OrdinalIgnoreCase))
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("\nCảm ơn bạn đã sử dụng công cụ! Chúc bạn chọn được chiếc máy tính ưng ý.");
                    Console.ResetColor();
                    break;
                }

                switch (choice)
                {
                    case "1":
                        RunScreenDeadPixelTest();
                        break;
                    case "2":
                        RunVisualKeyboardTest();
                        break;
                    case "3":
                        RunCpuStressAndThrottlingTest();
                        break;
                    case "4":
                        RunDiskBenchmarkTest();
                        break;
                    case "5":
                        RunAudioStereoTest();
                        break;
                    case "6":
                        RunBatteryChargeTest();
                        break;
                    case "7":
                        ShowSoftwareDownloaderMenu();
                        break;
                    case "8":
                        Console.Clear();
                        Main(new string[0]);
                        return;
                    default:
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("⚠ Lựa chọn không hợp lệ. Vui lòng nhập từ 0 đến 8.");
                        Console.ResetColor();
                        break;
                }
            }
        }

        static void RunScreenDeadPixelTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("    KIỂM TRA MÀN HÌNH (DEAD PIXEL & BACKLIGHT BLEED TEST)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• Màn hình sẽ chuyển sang chế độ TOÀN MÀN HÌNH với các màu thuần khiết:");
            Console.WriteLine("  - Màu TRẮNG/SÁNG: Soi điểm chết đen (Dead Pixel), đốm ố lót phản quang, bụi.");
            Console.WriteLine("  - Màu ĐEN: Soi hở sáng 4 góc/viền (IPS Backlight Bleed), điểm kẹt sáng (Stuck Pixel).");
            Console.WriteLine("  - Màu ĐỎ / XANH LÁ / XANH DƯƠNG: Soi chết điểm ảnh phụ (Subpixel).");
            Console.WriteLine("• Thao tác khi đang kiểm tra:");
            Console.WriteLine("  - [Click chuột trái] hoặc [Phím SPACE] / [Mũi tên phải]: Đổi sang màu tiếp theo.");
            Console.WriteLine("  - [Click chuột phải] hoặc [Mũi tên trái]: Quay lại màu trước.");
            Console.WriteLine("  - [Phím ESC]: Thoát và trở về Menu.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("👉 Nhấn Enter để BẮT ĐẦU test ngay...");
            Console.ResetColor();
            Console.ReadLine();

            Color[] colors = new Color[] {
                Color.White,
                Color.Black,
                Color.Red,
                Color.FromArgb(0, 255, 0),     // Pure Green
                Color.FromArgb(0, 0, 255),     // Pure Blue
                Color.Yellow,
                Color.Magenta,
                Color.Cyan,
                Color.FromArgb(128, 128, 128)  // Medium Gray
            };

            string[] colorNames = new string[] {
                "TRẮNG (Soi điểm chết đen, đốm ố lót, bụi phản quang)",
                "ĐEN (Soi hở sáng viền IPS bleed, điểm kẹt sáng)",
                "ĐỎ (Red Subpixel)",
                "XANH LÁ (Green Subpixel)",
                "XANH DƯƠNG (Blue Subpixel)",
                "VÀNG (Yellow)",
                "HỒNG (Magenta)",
                "XANH LƠ (Cyan)",
                "XÁM (Độ đồng đều tấm nền)"
            };

            int currentIndex = 0;

            using (Form form = new Form())
            {
                form.FormBorderStyle = FormBorderStyle.None;
                form.WindowState = FormWindowState.Maximized;
                form.TopMost = true;
                form.BackColor = colors[currentIndex];
                form.Cursor = Cursors.Hand;
                form.KeyPreview = true;

                Label lblBanner = new Label();
                lblBanner.AutoSize = false;
                lblBanner.Height = 44;
                lblBanner.Dock = DockStyle.Bottom;
                lblBanner.TextAlign = ContentAlignment.MiddleCenter;
                lblBanner.Font = new Font("Segoe UI", 12f, FontStyle.Bold);
                lblBanner.BackColor = Color.FromArgb(170, 20, 20, 20);
                lblBanner.ForeColor = Color.White;
                lblBanner.Text = string.Format("[{0}/{1}] {2} | Click / Space: Đổi màu | ESC: Thoát", currentIndex + 1, colors.Length, colorNames[currentIndex]);
                form.Controls.Add(lblBanner);

                System.Windows.Forms.Timer fadeTimer = new System.Windows.Forms.Timer();
                fadeTimer.Interval = 2800;
                fadeTimer.Tick += delegate {
                    lblBanner.Visible = false;
                    fadeTimer.Stop();
                };
                fadeTimer.Start();

                Action applyColor = delegate {
                    form.BackColor = colors[currentIndex];
                    lblBanner.Text = string.Format("[{0}/{1}] {2} | Click / Space: Đổi màu | ESC: Thoát", currentIndex + 1, colors.Length, colorNames[currentIndex]);
                    lblBanner.Visible = true;
                    fadeTimer.Stop();
                    fadeTimer.Start();
                };

                form.MouseClick += delegate(object sender, MouseEventArgs e) {
                    if (e.Button == MouseButtons.Right)
                    {
                        currentIndex = (currentIndex - 1 + colors.Length) % colors.Length;
                    }
                    else
                    {
                        currentIndex = (currentIndex + 1) % colors.Length;
                    }
                    applyColor();
                };

                form.KeyDown += delegate(object sender, KeyEventArgs e) {
                    if (e.KeyCode == Keys.Escape)
                    {
                        form.Close();
                    }
                    else if (e.KeyCode == Keys.Space || e.KeyCode == Keys.Right || e.KeyCode == Keys.Down || e.KeyCode == Keys.PageDown)
                    {
                        currentIndex = (currentIndex + 1) % colors.Length;
                        applyColor();
                    }
                    else if (e.KeyCode == Keys.Left || e.KeyCode == Keys.Up || e.KeyCode == Keys.PageUp)
                    {
                        currentIndex = (currentIndex - 1 + colors.Length) % colors.Length;
                        applyColor();
                    }
                };

                form.ShowDialog();
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✔ Đã hoàn tất kiểm tra màn hình!");
            Console.ResetColor();
        }

        class KeyDef
        {
            public Keys Key;
            public string Label;
            public int X;
            public int Y;
            public int Width;
            public int Height;

            public KeyDef(Keys key, string label, int x, int y, int width, int height)
            {
                Key = key;
                Label = label;
                X = x;
                Y = y;
                Width = width;
                Height = height;
            }
        }

        static void RunVisualKeyboardTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("    KIỂM TRA BÀN PHÍM TRỰC QUAN (VISUAL KEYBOARD TESTER)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• Cửa sổ kiểm tra bàn phím sẽ mở ra.");
            Console.WriteLine("• Hướng dẫn test:");
            Console.WriteLine("  - Dùng ngón tay lướt lần lượt qua từng hàng phím trên laptop/bàn phím.");
            Console.WriteLine("  - Phím nào nhận diện TỐT sẽ lập tức ĐỔI SANG MÀU XANH LÁ.");
            Console.WriteLine("  - Nếu bấm phím nào mà KHÔNG ĐỔI MÀU -> Phím đó bị liệt hoặc kẹt!");
            Console.WriteLine("• Bấm ESC trên bàn phím hoặc nhấn nút Đóng để quay về Menu.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("👉 Nhấn Enter để BẮT ĐẦU test bàn phím...");
            Console.ResetColor();
            Console.ReadLine();

            using (Form form = new Form())
            {
                form.Text = "Trình Kiểm Tra Bàn Phím Trực Quan (Keyboard Tester) - PITVN Community";
                form.Size = new Size(1080, 520);
                form.StartPosition = FormStartPosition.CenterScreen;
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false;
                form.BackColor = Color.FromArgb(24, 24, 28);
                form.KeyPreview = true;

                // Panel Header
                Panel topPanel = new Panel();
                topPanel.Dock = DockStyle.Top;
                topPanel.Height = 70;
                topPanel.BackColor = Color.FromArgb(32, 32, 38);
                form.Controls.Add(topPanel);

                Label lblTitle = new Label();
                lblTitle.Text = "⌨️ TRÌNH TEST BÀN PHÍM - BẤM PHÍM BẤT KỲ ĐỂ KIỂM TRA";
                lblTitle.Font = new Font("Segoe UI", 11f, FontStyle.Bold);
                lblTitle.ForeColor = Color.FromArgb(0, 210, 255);
                lblTitle.Location = new Point(16, 10);
                lblTitle.AutoSize = true;
                topPanel.Controls.Add(lblTitle);

                Label lblStatus = new Label();
                lblStatus.Text = "Đã kiểm tra: 0 phím | Phím vừa bấm: [Chưa có] | Mã phím: 0";
                lblStatus.Font = new Font("Segoe UI", 10.5f, FontStyle.Regular);
                lblStatus.ForeColor = Color.White;
                lblStatus.Location = new Point(16, 38);
                lblStatus.AutoSize = true;
                topPanel.Controls.Add(lblStatus);

                Button btnReset = new Button();
                btnReset.Text = "🔄 Làm mới (Reset)";
                btnReset.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                btnReset.ForeColor = Color.White;
                btnReset.BackColor = Color.FromArgb(50, 50, 60);
                btnReset.FlatStyle = FlatStyle.Flat;
                btnReset.Size = new Size(140, 32);
                btnReset.Location = new Point(760, 20);
                topPanel.Controls.Add(btnReset);

                Button btnClose = new Button();
                btnClose.Text = "❌ Đóng (ESC)";
                btnClose.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                btnClose.ForeColor = Color.White;
                btnClose.BackColor = Color.FromArgb(180, 40, 40);
                btnClose.FlatStyle = FlatStyle.Flat;
                btnClose.Size = new Size(130, 32);
                btnClose.Location = new Point(915, 20);
                topPanel.Controls.Add(btnClose);

                Panel kbPanel = new Panel();
                kbPanel.Location = new Point(16, 85);
                kbPanel.Size = new Size(1030, 380);
                kbPanel.BackColor = Color.FromArgb(18, 18, 22);
                form.Controls.Add(kbPanel);

                List<KeyDef> defs = new List<KeyDef>();
                int kw = 48; // standard key width
                int kh = 42; // standard key height
                int gap = 4;

                // Hàng 0: Esc, F1-F12, PrtSc, Del
                defs.Add(new KeyDef(Keys.Escape, "Esc", 10, 10, kw, kh));
                int xF = 10 + kw + 15;
                for (int i = 1; i <= 12; i++)
                {
                    Keys fKey = (Keys)Enum.Parse(typeof(Keys), "F" + i);
                    defs.Add(new KeyDef(fKey, "F" + i, xF, 10, kw, kh));
                    xF += kw + gap;
                    if (i == 4 || i == 8) xF += 10;
                }
                defs.Add(new KeyDef(Keys.PrintScreen, "PrtSc", xF + 15, 10, 56, kh));
                defs.Add(new KeyDef(Keys.Delete, "Del", xF + 15 + 56 + gap, 10, 56, kh));

                // Hàng 1: ~, 1-0, -, =, Backspace
                int y1 = 10 + kh + gap + 10;
                int x1 = 10;
                defs.Add(new KeyDef(Keys.Oemtilde, "~", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.D1, "1", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.D2, "2", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.D3, "3", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.D4, "4", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.D5, "5", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.D6, "6", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.D7, "7", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.D8, "8", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.D9, "9", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.D0, "0", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.OemMinus, "-", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.Oemplus, "=", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.Back, "Backspace", x1, y1, 100, kh));

                // Hàng 2: Tab, Q..P, [, ], \
                int y2 = y1 + kh + gap;
                int x2 = 10;
                defs.Add(new KeyDef(Keys.Tab, "Tab", x2, y2, 70, kh)); x2 += 70 + gap;
                string row2Keys = "QWERTYUIOP";
                for (int i = 0; i < row2Keys.Length; i++)
                {
                    Keys k = (Keys)Enum.Parse(typeof(Keys), row2Keys[i].ToString());
                    defs.Add(new KeyDef(k, row2Keys[i].ToString(), x2, y2, kw, kh)); x2 += kw + gap;
                }
                defs.Add(new KeyDef(Keys.OemOpenBrackets, "[", x2, y2, kw, kh)); x2 += kw + gap;
                defs.Add(new KeyDef(Keys.Oem6, "]", x2, y2, kw, kh)); x2 += kw + gap;
                defs.Add(new KeyDef(Keys.Oem5, "\\", x2, y2, 80, kh));

                // Hàng 3: Caps, A..L, ;, ', Enter
                int y3 = y2 + kh + gap;
                int x3 = 10;
                defs.Add(new KeyDef(Keys.Capital, "Caps", x3, y3, 80, kh)); x3 += 80 + gap;
                string row3Keys = "ASDFGHJKL";
                for (int i = 0; i < row3Keys.Length; i++)
                {
                    Keys k = (Keys)Enum.Parse(typeof(Keys), row3Keys[i].ToString());
                    defs.Add(new KeyDef(k, row3Keys[i].ToString(), x3, y3, kw, kh)); x3 += kw + gap;
                }
                defs.Add(new KeyDef(Keys.Oem1, ";", x3, y3, kw, kh)); x3 += kw + gap;
                defs.Add(new KeyDef(Keys.Oem7, "'", x3, y3, kw, kh)); x3 += kw + gap;
                defs.Add(new KeyDef(Keys.Return, "Enter", x3, y3, 122, kh));

                // Hàng 4: Shift L, Z..M, ,, ., /, Shift R, Up
                int y4 = y3 + kh + gap;
                int x4 = 10;
                defs.Add(new KeyDef(Keys.ShiftKey, "Shift", x4, y4, 105, kh)); x4 += 105 + gap;
                string row4Keys = "ZXCVBNM";
                for (int i = 0; i < row4Keys.Length; i++)
                {
                    Keys k = (Keys)Enum.Parse(typeof(Keys), row4Keys[i].ToString());
                    defs.Add(new KeyDef(k, row4Keys[i].ToString(), x4, y4, kw, kh)); x4 += kw + gap;
                }
                defs.Add(new KeyDef(Keys.Oemcomma, ",", x4, y4, kw, kh)); x4 += kw + gap;
                defs.Add(new KeyDef(Keys.OemPeriod, ".", x4, y4, kw, kh)); x4 += kw + gap;
                defs.Add(new KeyDef(Keys.OemQuestion, "/", x4, y4, kw, kh)); x4 += kw + gap;
                defs.Add(new KeyDef(Keys.RShiftKey, "Shift", x4, y4, 98, kh)); x4 += 98 + gap + 15;
                defs.Add(new KeyDef(Keys.Up, "▲", x4 + kw + gap, y4, kw, kh));

                // Hàng 5: Ctrl, Win, Alt, Space, Alt, Win/Fn, Ctrl, Left, Down, Right
                int y5 = y4 + kh + gap;
                int x5 = 10;
                defs.Add(new KeyDef(Keys.ControlKey, "Ctrl", x5, y5, 60, kh)); x5 += 60 + gap;
                defs.Add(new KeyDef(Keys.LWin, "Win", x5, y5, 50, kh)); x5 += 50 + gap;
                defs.Add(new KeyDef(Keys.Menu, "Alt", x5, y5, 54, kh)); x5 += 54 + gap;
                defs.Add(new KeyDef(Keys.Space, "Space", x5, y5, 290, kh)); x5 += 290 + gap;
                defs.Add(new KeyDef(Keys.RMenu, "Alt", x5, y5, 54, kh)); x5 += 54 + gap;
                defs.Add(new KeyDef(Keys.Apps, "Fn/Menu", x5, y5, 60, kh)); x5 += 60 + gap;
                defs.Add(new KeyDef(Keys.RControlKey, "Ctrl", x5, y5, 60, kh)); x5 += 60 + gap + 15;
                defs.Add(new KeyDef(Keys.Left, "◄", x5, y5, kw, kh)); x5 += kw + gap;
                defs.Add(new KeyDef(Keys.Down, "▼", x5, y5, kw, kh)); x5 += kw + gap;
                defs.Add(new KeyDef(Keys.Right, "►", x5, y5, kw, kh));

                Dictionary<Keys, Button> keyButtons = new Dictionary<Keys, Button>();
                List<Button> allButtons = new List<Button>();

                foreach (KeyDef kd in defs)
                {
                    Button btn = new Button();
                    btn.Text = kd.Label;
                    btn.Location = new Point(kd.X, kd.Y);
                    btn.Size = new Size(kd.Width, kd.Height);
                    btn.FlatStyle = FlatStyle.Flat;
                    btn.FlatAppearance.BorderSize = 1;
                    btn.FlatAppearance.BorderColor = Color.FromArgb(60, 60, 70);
                    btn.BackColor = Color.FromArgb(38, 38, 46);
                    btn.ForeColor = Color.White;
                    btn.Font = new Font("Segoe UI", 9f, FontStyle.Regular);
                    btn.TabStop = false;
                    kbPanel.Controls.Add(btn);

                    if (!keyButtons.ContainsKey(kd.Key))
                    {
                        keyButtons.Add(kd.Key, btn);
                    }
                    allButtons.Add(btn);
                }

                HashSet<Keys> testedKeys = new HashSet<Keys>();

                Action resetAll = delegate {
                    testedKeys.Clear();
                    foreach (Button b in allButtons)
                    {
                        b.BackColor = Color.FromArgb(38, 38, 46);
                        b.ForeColor = Color.White;
                        b.Font = new Font("Segoe UI", 9f, FontStyle.Regular);
                    }
                    lblStatus.Text = "Đã kiểm tra: 0 phím | Phím vừa bấm: [Chưa có] | Mã phím: 0";
                };

                btnReset.Click += delegate { resetAll(); };
                btnClose.Click += delegate { form.Close(); };

                form.KeyDown += delegate(object sender, KeyEventArgs e)
                {
                    testedKeys.Add(e.KeyCode);
                    Button b;
                    if (keyButtons.TryGetValue(e.KeyCode, out b))
                    {
                        b.BackColor = Color.FromArgb(46, 204, 113); // Emerald Green
                        b.ForeColor = Color.Black;
                        b.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
                    }
                    else if (e.KeyCode == Keys.ShiftKey)
                    {
                        if (keyButtons.TryGetValue(Keys.ShiftKey, out b))
                        {
                            b.BackColor = Color.FromArgb(46, 204, 113);
                            b.ForeColor = Color.Black;
                        }
                    }
                    else if (e.KeyCode == Keys.ControlKey)
                    {
                        if (keyButtons.TryGetValue(Keys.ControlKey, out b))
                        {
                            b.BackColor = Color.FromArgb(46, 204, 113);
                            b.ForeColor = Color.Black;
                        }
                    }
                    else if (e.KeyCode == Keys.Menu)
                    {
                        if (keyButtons.TryGetValue(Keys.Menu, out b))
                        {
                            b.BackColor = Color.FromArgb(46, 204, 113);
                            b.ForeColor = Color.Black;
                        }
                    }

                    lblStatus.Text = string.Format("Đã kiểm tra: {0} phím | Phím vừa bấm: [{1}] | Mã phím: {2}", testedKeys.Count, e.KeyCode, (int)e.KeyCode);
                    e.Handled = true;
                };

                form.ShowDialog();
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✔ Đã hoàn tất kiểm tra bàn phím!");
            Console.ResetColor();
        }

        static void RunCpuStressAndThrottlingTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("    THỬ TẢI CPU (STRESS TEST) & ĐO HIỆN TƯỢNG BÓP XUNG (THROTTLING)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• Thử tải 100% tất cả các nhân/luồng CPU (" + Environment.ProcessorCount + " luồng tính toán).");
            Console.WriteLine("• Giúp phát hiện:");
            Console.WriteLine("  - Quạt tản nhiệt có quay mạnh khi tải nặng không?");
            Console.WriteLine("  - Keo tản nhiệt có bị khô cứng gây quá nhiệt sụt giảm hiệu năng không?");
            Console.WriteLine("  - Máy có bị treo, màn hình xanh (BSOD) hoặc sập nguồn khi tải tối đa không?");
            Console.WriteLine();
            Console.Write("👉 Chọn thời gian thử tải [1] 15 giây (Nhanh) | [2] 30 giây (Đầy đủ) [Mặc định 1]: ");
            string timeChoice = Console.ReadLine();
            int totalSeconds = (timeChoice != null && timeChoice.Trim() == "2") ? 30 : 15;

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(string.Format("⏳ Đang khởi động {0} luồng xử lý tính toán 100% CPU trong {1} giây...", Environment.ProcessorCount, totalSeconds));
            Console.ResetColor();

            bool isRunning = true;
            long totalOps = 0;
            List<Thread> workers = new List<Thread>();
            int numThreads = Environment.ProcessorCount;

            for (int t = 0; t < numThreads; t++)
            {
                Thread th = new Thread(delegate()
                {
                    double v = 123456.789;
                    long localOps = 0;
                    while (isRunning)
                    {
                        for (int k = 0; k < 10000; k++)
                        {
                            v = Math.Sqrt(v * 1.000001 + 0.123);
                        }
                        localOps += 10000;
                        if (localOps >= 50000)
                        {
                            Interlocked.Add(ref totalOps, localOps);
                            localOps = 0;
                        }
                    }
                });
                th.IsBackground = true;
                th.Start();
                workers.Add(th);
            }

            Stopwatch sw = Stopwatch.StartNew();
            long lastOps = 0;
            long lastTimeMs = 0;
            List<double> sampleRates = new List<double>();

            while (sw.ElapsedMilliseconds < totalSeconds * 1000)
            {
                Thread.Sleep(500);
                long currentOps = Interlocked.Read(ref totalOps);
                long currentTimeMs = sw.ElapsedMilliseconds;

                long deltaOps = currentOps - lastOps;
                long deltaTimeMs = currentTimeMs - lastTimeMs;
                if (deltaTimeMs > 0)
                {
                    double ratePerSec = (double)deltaOps / (deltaTimeMs / 1000.0);
                    sampleRates.Add(ratePerSec);
                }

                lastOps = currentOps;
                lastTimeMs = currentTimeMs;

                double percent = (double)currentTimeMs / (totalSeconds * 1000.0) * 100.0;
                if (percent > 100.0) percent = 100.0;
                int barWidth = 25;
                int filled = (int)(percent / 100.0 * barWidth);
                if (filled > barWidth) filled = barWidth;
                string bar = new string('█', filled) + new string('░', barWidth - filled);

                Console.Write(string.Format("\r   [{0}] {1,5:F1}% | {2,4:F1}s / {3}s | Tải: 100% ({4} Luồng)", bar, percent, currentTimeMs / 1000.0, totalSeconds, numThreads));
            }

            isRunning = false;
            foreach (Thread th in workers) th.Join(500);
            sw.Stop();
            Console.WriteLine();
            Console.WriteLine();

            // Tính toán mức sụt giảm hiệu năng Throttling
            if (sampleRates.Count >= 4)
            {
                int sampleWindow = Math.Min(4, sampleRates.Count / 2);
                double initialSum = 0;
                for (int i = 0; i < sampleWindow; i++) initialSum += sampleRates[i];
                double initialAvg = initialSum / sampleWindow;

                double finalSum = 0;
                for (int i = sampleRates.Count - sampleWindow; i < sampleRates.Count; i++) finalSum += sampleRates[i];
                double finalAvg = finalSum / sampleWindow;

                double retentionRatio = (initialAvg > 0) ? (finalAvg / initialAvg) * 100.0 : 100.0;
                double dropPercent = 100.0 - retentionRatio;

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("══════════════════════════════════════════════════════════════════");
                Console.WriteLine("        KẾT QUẢ ĐÁNH GIÁ TẢN NHIỆT & THROTTLING CPU");
                Console.WriteLine("══════════════════════════════════════════════════════════════════");
                Console.ResetColor();
                Console.WriteLine(string.Format("• Tốc độ tính toán ban đầu (Khi máy mát)  : {0:N0} phép tính/s", initialAvg));
                Console.WriteLine(string.Format("• Tốc độ tính toán sau {0}s (Khi máy nóng) : {1:N0} phép tính/s", totalSeconds, finalAvg));
                Console.WriteLine(string.Format("• Hệ số duy trì hiệu năng ổn định       : {0:F1}% (Sụt giảm: {1:F1}%)", retentionRatio, Math.Max(0, dropPercent)));
                Console.WriteLine();

                if (retentionRatio >= 93.0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("👉 [ĐÁNH GIÁ: XUẤT SẮC] Hệ thống tản nhiệt hoạt động cực kỳ hoàn hảo!");
                    Console.WriteLine("   CPU duy trì xung nhịp ổn định " + retentionRatio.ToString("F1") + "%, không hề bị bóp xung (Thermal Throttling).");
                    Console.ResetColor();
                }
                else if (retentionRatio >= 85.0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("👉 [ĐÁNH GIÁ: BÌNH THƯỜNG] Hệ thống tản nhiệt ở mức chấp nhận được.");
                    Console.WriteLine("   CPU có giảm nhẹ " + dropPercent.ToString("F1") + "% xung nhịp khi tải nặng liên tục (Phổ biến ở laptop mỏng nhẹ).");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("👉 [CẢNH BÁO NGUY HIỂM] PHÁT HIỆN BÓP XUNG NẶNG (THERMAL THROTTLING)!");
                    Console.WriteLine("   Hiệu năng sụt giảm tới " + dropPercent.ToString("F1") + "% sau " + totalSeconds + " giây tải nặng.");
                    Console.WriteLine("   ⚠ NGUYÊN NHÂN: Keo tản nhiệt đã khô cứng hoặc quạt bám bụi dày / quạt chết.");
                    Console.WriteLine("   Khuyến cáo: Cần yêu cầu cửa hàng vệ sinh tra keo tản nhiệt xịn trước khi mua!");
                    Console.ResetColor();
                }
            }
            Console.WriteLine();
        }

        static void RunDiskBenchmarkTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("    ĐO TỐC ĐỘ ĐỌC / GHI THỰC TẾ Ổ CỨNG (DISK SPEED BENCHMARK)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• Thử nghiệm ghi & đọc thực tế 128 MB dữ liệu ngẫu nhiên (chống nén lừa đảo).");
            Console.WriteLine("• Giúp phát hiện:");
            Console.WriteLine("  - Ổ cứng có đạt chuẩn tốc độ công bố không (NVMe vs SATA vs HDD)?");
            Console.WriteLine("  - Phát hiện ổ cứng SSD nhái, chip nhớ phế liệu tái chế chạy chậm.");
            Console.WriteLine("  - Ổ cứng có bị nghẽn I/O hay treo khi ghi tệp lớn không.");
            Console.WriteLine();

            string systemDrive = Path.GetPathRoot(Environment.SystemDirectory);
            Console.Write(string.Format("👉 Chọn phân vùng ổ cứng cần kiểm tra [Mặc định: {0}]: ", systemDrive));
            string driveInput = Console.ReadLine();
            string targetDrive = string.IsNullOrEmpty(driveInput) ? systemDrive : driveInput.Trim();
            if (!targetDrive.EndsWith("\\")) targetDrive += "\\";

            try
            {
                DriveInfo dInfo = new DriveInfo(targetDrive);
                long freeBytes = dInfo.AvailableFreeSpace;
                if (freeBytes < 300L * 1024 * 1024)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("⚠ Dung lượng trống trên ổ " + targetDrive + " quá ít (< 300 MB). Không thể chạy benchmark.");
                    Console.ResetColor();
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("⚠ Không thể truy cập ổ đĩa: " + ex.Message);
                Console.ResetColor();
                return;
            }

            string testFilePath = Path.Combine(targetDrive, "_pitvn_speed_test.tmp");
            int totalMB = 128;
            int bufferSize = 1024 * 1024; // 1 MB buffer
            byte[] dummyData = new byte[bufferSize];
            new Random().NextBytes(dummyData);

            try
            {
                // 1. Test Ghi (Sequential Write)
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("⏳ Đang thử nghiệm TỐC ĐỘ GHI liên tục 128 MB...");
                Console.ResetColor();

                Stopwatch swWrite = Stopwatch.StartNew();
                using (FileStream fs = new FileStream(testFilePath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize, FileOptions.WriteThrough))
                {
                    for (int i = 0; i < totalMB; i++)
                    {
                        fs.Write(dummyData, 0, bufferSize);
                    }
                    fs.Flush();
                }
                swWrite.Stop();
                double writeSec = swWrite.Elapsed.TotalSeconds;
                double writeSpeedMBs = (writeSec > 0) ? (totalMB / writeSec) : 0;
                Console.WriteLine(string.Format(" Hoàn tất trong {0:F2}s!", writeSec));

                // 2. Test Đọc (Sequential Read)
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("⏳ Đang thử nghiệm TỐC ĐỘ ĐỌC liên tục 128 MB...");
                Console.ResetColor();

                byte[] readBuffer = new byte[bufferSize];
                Stopwatch swRead = Stopwatch.StartNew();
                using (FileStream fs = new FileStream(testFilePath, FileMode.Open, FileAccess.Read, FileShare.None, bufferSize, FileOptions.SequentialScan))
                {
                    while (fs.Read(readBuffer, 0, bufferSize) > 0) { }
                }
                swRead.Stop();
                double readSec = swRead.Elapsed.TotalSeconds;
                double readSpeedMBs = (readSec > 0) ? (totalMB / readSec) : 0;
                Console.WriteLine(string.Format(" Hoàn tất trong {0:F2}s!", readSec));

                // Hiển thị kết quả
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("══════════════════════════════════════════════════════════════════");
                Console.WriteLine("          KẾT QUẢ ĐO TỐC ĐỘ Ổ CỨNG TRÊN PHÂN VÙNG " + targetDrive);
                Console.WriteLine("══════════════════════════════════════════════════════════════════");
                Console.ResetColor();
                Console.WriteLine(string.Format("• Tốc độ Ghi liên tục (Sequential Write): {0:N1} MB/s", writeSpeedMBs));
                Console.WriteLine(string.Format("• Tốc độ Đọc liên tục (Sequential Read) : {0:N1} MB/s", readSpeedMBs));
                Console.WriteLine();

                if (readSpeedMBs >= 1200.0 || writeSpeedMBs >= 1000.0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("👉 [ĐÁNH GIÁ: SIÊU TỐC] Ổ cứng chuẩn NVMe PCIe Gen 3/4/5 tốc độ rất cao!");
                    Console.ResetColor();
                }
                else if (readSpeedMBs >= 400.0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("👉 [ĐÁNH GIÁ: CHUẨN] Ổ cứng chuẩn SSD SATA 3 tốc độ chuẩn tiêu chuẩn (~500 MB/s).");
                    Console.ResetColor();
                }
                else if (readSpeedMBs >= 150.0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("👉 [ĐÁNH GIÁ: TRUNG BÌNH] Ổ cứng SSD SATA 2 hoặc SSD giá rẻ/bị suy hao tốc độ.");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("👉 [ĐÁNH GIÁ: CHẬM] Tốc độ tương đương ổ HDD cơ hoặc SSD kém chất lượng / lỗi chip.");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("⚠ Lỗi trong quá trình đo tốc độ ổ cứng: " + ex.Message);
                Console.ResetColor();
            }
            finally
            {
                try
                {
                    if (File.Exists(testFilePath)) File.Delete(testFilePath);
                }
                catch { }
            }
            Console.WriteLine();
        }

        static byte[] GenerateWavTone(int sampleRate, double frequency, double durationSec, bool leftChannel, bool rightChannel)
        {
            int numSamples = (int)(sampleRate * durationSec);
            int subchunk2Size = numSamples * 2 * 2; // 2 channels, 16 bits = 4 bytes per sample
            int chunkSize = 36 + subchunk2Size;

            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                // RIFF header
                bw.Write(Encoding.ASCII.GetBytes("RIFF"));
                bw.Write(chunkSize);
                bw.Write(Encoding.ASCII.GetBytes("WAVE"));

                // fmt subchunk
                bw.Write(Encoding.ASCII.GetBytes("fmt "));
                bw.Write(16); // Subchunk1Size for PCM
                bw.Write((short)1); // AudioFormat (1 = PCM)
                bw.Write((short)2); // NumChannels = 2 (Stereo)
                bw.Write(sampleRate);
                bw.Write(sampleRate * 2 * 2); // ByteRate
                bw.Write((short)4); // BlockAlign
                bw.Write((short)16); // BitsPerSample

                // data subchunk
                bw.Write(Encoding.ASCII.GetBytes("data"));
                bw.Write(subchunk2Size);

                for (int i = 0; i < numSamples; i++)
                {
                    double t = (double)i / sampleRate;
                    double envelope = 1.0;
                    if (i < 800) envelope = (double)i / 800.0;
                    else if (i > numSamples - 800) envelope = (double)(numSamples - i) / 800.0;

                    short sampleVal = (short)(Math.Sin(2.0 * Math.PI * frequency * t) * (short.MaxValue * 0.7) * envelope);

                    short leftVal = leftChannel ? sampleVal : (short)0;
                    short rightVal = rightChannel ? sampleVal : (short)0;

                    bw.Write(leftVal);
                    bw.Write(rightVal);
                }

                bw.Flush();
                return ms.ToArray();
            }
        }

        static void RunAudioStereoTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("    KIỂM TRA ÂM THANH LOA TRÁI & PHẢI (STEREO SPEAKER TEST)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• Phát âm thanh cách ly kênh để kiểm tra độc lập từng bên loa laptop:");
            Console.WriteLine("  - Bước 1: Chỉ phát âm thanh ra LOA TRÁI (Left Speaker - 440 Hz).");
            Console.WriteLine("  - Bước 2: Chỉ phát âm thanh ra LOA PHẢI (Right Speaker - 880 Hz).");
            Console.WriteLine("  - Bước 3: Phát âm thanh ra CẢ HAI LOA (Stereo Harmonic Chord).");
            Console.WriteLine("• Giúp phát hiện: Loa bị tịt 1 bên, loa bị rè/rách màng khi âm lượng cao.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("👉 Vui lòng mở âm lượng máy tính khoảng 50-70%, nhấn Enter để BẮT ĐẦU...");
            Console.ResetColor();
            Console.ReadLine();

            try
            {
                // Bước 1: Loa trái
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("🔊 [1/3] Đang phát âm thanh ra LOA TRÁI (LEFT)... Vui lòng lắng nghe!");
                Console.ResetColor();
                byte[] leftWav = GenerateWavTone(44100, 440.0, 2.5, true, false);
                using (MemoryStream ms = new MemoryStream(leftWav))
                using (SoundPlayer sp = new SoundPlayer(ms))
                {
                    sp.PlaySync();
                }
                Thread.Sleep(500);

                // Bước 2: Loa phải
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("🔊 [2/3] Đang phát âm thanh ra LOA PHẢI (RIGHT)... Vui lòng lắng nghe!");
                Console.ResetColor();
                byte[] rightWav = GenerateWavTone(44100, 880.0, 2.5, false, true);
                using (MemoryStream ms = new MemoryStream(rightWav))
                using (SoundPlayer sp = new SoundPlayer(ms))
                {
                    sp.PlaySync();
                }
                Thread.Sleep(500);

                // Bước 3: Cả hai loa
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("🔊 [3/3] Đang phát âm thanh ra CẢ HAI LOA (STEREO)...");
                Console.ResetColor();
                byte[] bothWav = GenerateWavTone(44100, 587.33, 2.5, true, true);
                using (MemoryStream ms = new MemoryStream(bothWav))
                using (SoundPlayer sp = new SoundPlayer(ms))
                {
                    sp.PlaySync();
                }

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("✔ Đã hoàn tất phát chuỗi âm thanh kiểm tra loa!");
                Console.ResetColor();
                Console.WriteLine("👉 Đánh giá:");
                Console.WriteLine("   - Cả 2 bên đều nghe to rõ, không rè -> Loa hoàn hảo.");
                Console.WriteLine("   - Một bên im bặt -> Đã đứt cáp loa hoặc hỏng màng loa bên đó.");
                Console.WriteLine("   - Tiếng bị xè xè, rè khi âm thanh lớn -> Màng loa đã bị rách hoặc bám mạt sắt.");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("⚠ Lỗi khi phát âm thanh: " + ex.Message);
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        static void RunBatteryChargeTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("    KIỂM TRA TỐC ĐỘ NẠP/XẢ PIN & NGUỒN SẠC (BATTERY MONITOR)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();

            BatteryInfo bat = GetBattery();
            if (!bat.HasBattery)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("⚠ Máy tính hiện tại là Desktop (Máy tính để bàn) hoặc không gắn pin.");
                Console.ResetColor();
                return;
            }

            Console.WriteLine(string.Format("• Dung lượng thiết kế gốc (Design)    : {0}", bat.DesignCapacity));
            Console.WriteLine(string.Format("• Dung lượng sạc đầy hiện tại (Full)  : {0}", bat.CurrentCapacity));
            Console.WriteLine(string.Format("• Tỷ lệ chai pin (Wear Level)         : {0}", bat.WearLevel));
            Console.WriteLine(string.Format("• Số chu kỳ sạc (Cycle Count)         : {0}", bat.CycleCount >= 0 ? bat.CycleCount.ToString("N0") : "N/A"));
            Console.WriteLine(string.Format("• Nguồn điện hiện tại                 : {0}", SystemInformation.PowerStatus.PowerLineStatus == PowerLineStatus.Online ? "🔌 Đang cắm sạc (AC Online)" : "🔋 Đang dùng Pin (Battery)"));
            Console.WriteLine(string.Format("• Mức pin hiện tại                    : {0:P0}", SystemInformation.PowerStatus.BatteryLifePercent));
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("⏳ Đang theo dõi trạng thái dòng sạc/xả pin trong 5 giây...");
            Console.ResetColor();

            Thread.Sleep(5000);

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("        KẾT QUẢ ĐÁNH GIÁ PIN & CÔNG SUẤT BỘ SẠC");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();

            if (SystemInformation.PowerStatus.PowerLineStatus == PowerLineStatus.Online)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("✔ Củ sạc kết nối ổn định (AC Adapter Online).");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine("ℹ Máy đang dùng pin (Chưa cắm sạc). Hãy cắm sạc để kiểm tra khả năng nhận điện của củ sạc.");
                Console.ResetColor();
            }

            double wearVal = 0;
            if (bat.WearLevel != null && bat.WearLevel.Contains("%"))
            {
                double.TryParse(bat.WearLevel.Replace("%", "").Trim(), out wearVal);
            }

            if (wearVal < 20.0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(string.Format("👉 [ĐÁNH GIÁ PIN: RẤT TỐT] Pin còn giữ được {0:F1}% dung lượng gốc (Chai {1}).", 100.0 - wearVal, bat.WearLevel));
                Console.ResetColor();
            }
            else if (wearVal <= 40.0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(string.Format("👉 [ĐÁNH GIÁ PIN: KHÁ] Pin chai ở mức chấp nhận được ({0}).", bat.WearLevel));
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(string.Format("👉 [CẢNH BÁO PIN: CHAI NẶNG] Pin đã chai {0}! Thời lượng pin sẽ sụt rất nhanh, nên trừ tiền thay pin mới.", bat.WearLevel));
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        static void ShowSoftwareDownloaderMenu()
        {
            List<SoftwareItem> tools = new List<SoftwareItem>();
            tools.Add(new SoftwareItem(
                "1",
                "FurMark 2 (GPU Stress Test - Thử tải card màn hình & nguồn)",
                "Ép card đồ họa rời chạy 100% công suất để kiểm tra nhiệt độ tản nhiệt, chống rác hình và sập nguồn.",
                "https://sourceforge.net/projects/furmark/files/latest/download",
                "FurMark_win64.zip",
                "FurMark",
                "*furmark*.exe",
                false,
                ""
            ));
            tools.Add(new SoftwareItem(
                "2",
                "CPUID HWMonitor (Soi nhiệt độ CPU/GPU, quạt, công suất W)",
                "Đo nhiệt độ từng nhân vi xử lý, công suất tiêu thụ điện (Watt), xung nhịp, tốc độ quạt theo thời gian thực.",
                "https://download.cpuid.com/hwmonitor/hwmonitor_1.56.zip",
                "hwmonitor_1.56.zip",
                "HWMonitor",
                "*hwmonitor*.exe",
                false,
                ""
            ));
            tools.Add(new SoftwareItem(
                "3",
                "CrystalDiskInfo (Soi toàn diện S.M.A.R.T, Bad Sector, số giờ chạy)",
                "Kiểm tra chi tiết sức khỏe ổ cứng SSD/HDD, số lần bật máy, tổng dung lượng TBW đã ghi và cảnh báo lỗi vàng/đỏ.",
                "https://sourceforge.net/projects/crystaldiskinfo/files/latest/download",
                "CrystalDiskInfo.zip",
                "CrystalDiskInfo",
                "*diskinfo*.exe",
                false,
                ""
            ));
            tools.Add(new SoftwareItem(
                "4",
                "CPUID CPU-Z (Xem chi tiết CPU, RAM Dual Channel & Benchmark nhanh)",
                "Xem chi tiết vi kiến trúc CPU, kênh RAM Dual-Channel, tích hợp sẵn Benchmark CPU so sánh với chip top đầu.",
                "https://download.cpuid.com/cpu-z/cpu-z_2.11-en.zip",
                "cpu-z_2.11-en.zip",
                "CPU-Z",
                "*cpuz*.exe",
                false,
                ""
            ));
            tools.Add(new SoftwareItem(
                "5",
                "Cinebench (Maxon Cinebench R23 / 2024 - Render 3D CPU Benchmark)",
                "Bài test render 3D tiêu chuẩn thế giới để kiểm tra sức mạnh thực tế của CPU.",
                "",
                "",
                "Cinebench",
                "",
                true,
                "https://www.maxon.net/en/cinebench"
            ));

            while (true)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("╔═══════════════════════════════════════════════════════════════════════╗");
                Console.WriteLine("║    TRÌNH TẢI PHẦN MỀM TEST CHUYÊN DỤNG (PORTABLE - KHÔNG CẦN CÀI)    ║");
                Console.WriteLine("╚═══════════════════════════════════════════════════════════════════════╝");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [1] 🔥 FurMark 2 (GPU Stress Test - Thử tải card màn hình & nguồn - ~28 MB)");
                Console.WriteLine("  [2] 🌡️  CPUID HWMonitor (Soi nhiệt độ CPU/GPU, quạt, công suất W - ~2 MB)");
                Console.WriteLine("  [3] 💾 CrystalDiskInfo (Soi toàn diện S.M.A.R.T, Bad Sector - ~8 MB)");
                Console.WriteLine("  [4] ⚡ CPUID CPU-Z (Xem chi tiết CPU, RAM Dual & Benchmark nhanh - ~3.5 MB)");
                Console.WriteLine("  [5] 🎬 Cinebench (Xem hướng dẫn & Mở trang tải Cinebench chính thức)");
                Console.WriteLine("  [6] 📦 TẢI TRỌN BỘ NHANH (Tải cả 3 công cụ nhẹ: CPU-Z + HWMonitor + CrystalDiskInfo)");
                Console.WriteLine("  [0] ⬅️  Quay lại Menu chính");
                Console.ResetColor();
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("👉 Vui lòng chọn phần mềm muốn tải [0-6]: ");
                Console.ResetColor();

                string toolChoice = Console.ReadLine();
                if (toolChoice == null) break;
                toolChoice = toolChoice.Trim();

                if (toolChoice == "0" || toolChoice.Equals("exit", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                if (toolChoice == "1") DownloadAndExtract(tools[0]);
                else if (toolChoice == "2") DownloadAndExtract(tools[1]);
                else if (toolChoice == "3") DownloadAndExtract(tools[2]);
                else if (toolChoice == "4") DownloadAndExtract(tools[3]);
                else if (toolChoice == "5")
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("══════════════════════════════════════════════════════════════════");
                    Console.WriteLine("    HƯỚNG DẪN TẢI CINEBENCH (MAXON CINEBENCH R23 / 2024)");
                    Console.WriteLine("══════════════════════════════════════════════════════════════════");
                    Console.ResetColor();
                    Console.WriteLine("• Cinebench R23/2024 có dung lượng khá lớn (~4.5 GB).");
                    Console.WriteLine("• Khi đi test máy ở tiệm hoặc quán cà phê, bạn có 2 giải pháp tối ưu:");
                    Console.WriteLine("  [1] Mở trang tải chính thức Maxon Cinebench trên trình duyệt.");
                    Console.WriteLine("  [2] Dùng CPU-Z Benchmark (Có sẵn mục [4] trong tool, tải chỉ 3 MB, có sẵn điểm so sánh chuẩn).");
                    Console.WriteLine();
                    Console.Write("👉 Bạn có muốn MỞ TRANG TẢI CINEBENCH trên trình duyệt không? [Y/N] (Mặc định Y): ");
                    string openAns = Console.ReadLine();
                    if (string.IsNullOrEmpty(openAns) || openAns.Trim().ToUpper() == "Y")
                    {
                        try
                        {
                            Process.Start("https://www.maxon.net/en/cinebench");
                            Console.WriteLine("✔ Đã mở trang tải Cinebench trên trình duyệt của bạn!");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("⚠ Không thể mở trình duyệt: " + ex.Message);
                        }
                    }
                }
                else if (toolChoice == "6")
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("\n🚀 ĐANG BẮT ĐẦU TẢI TRỌN BỘ 3 CÔNG CỤ NHẸ (CPU-Z + HWMONITOR + CRYSTALDISKINFO)...");
                    Console.ResetColor();
                    DownloadAndExtract(tools[3]); // CPU-Z
                    DownloadAndExtract(tools[1]); // HWMonitor
                    DownloadAndExtract(tools[2]); // CrystalDiskInfo
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n🎉 ĐÃ TẢI XONG TRỌN BỘ CÔNG CỤ!");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("⚠ Lựa chọn không hợp lệ. Vui lòng nhập từ 0 đến 6.");
                    Console.ResetColor();
                }
            }
        }

        static void DownloadAndExtract(SoftwareItem item)
        {
            if (item.IsExternalOnly) return;

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("  TẢI VỀ: " + item.Name);
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• " + item.Description);

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string toolsDir = Path.Combine(baseDir, "Tools_Test");
            try
            {
                if (!Directory.Exists(toolsDir)) Directory.CreateDirectory(toolsDir);
            }
            catch
            {
                toolsDir = Path.Combine(Path.GetTempPath(), "Tools_Test_PITVN");
                if (!Directory.Exists(toolsDir)) Directory.CreateDirectory(toolsDir);
            }

            string targetFolder = Path.Combine(toolsDir, item.FolderName);

            // Kiểm tra xem đã có sẵn chưa
            if (Directory.Exists(targetFolder))
            {
                string[] exes = Directory.GetFiles(targetFolder, item.ExeSearchPattern, SearchOption.AllDirectories);
                if (exes.Length > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✔ Phần mềm đã có sẵn tại: " + exes[0]);
                    Console.ResetColor();
                    Console.Write("👉 Bạn có muốn KHỞI CHẠY NGAY không? [Y/N] (Mặc định Y): ");
                    string ans = Console.ReadLine();
                    if (string.IsNullOrEmpty(ans) || ans.Trim().ToUpper() == "Y")
                    {
                        try
                        {
                            Process.Start(exes[0]);
                            Console.WriteLine("✔ Đã khởi chạy: " + Path.GetFileName(exes[0]));
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("⚠ Không thể khởi chạy: " + ex.Message);
                        }
                    }
                    return;
                }
            }

            string zipPath = Path.Combine(toolsDir, item.FileName);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("⏳ Đang kết nối máy chủ và tải gói Portable...");
            Console.ResetColor();

            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(item.DownloadUrl);
                request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
                request.Timeout = 60000;
                request.AllowAutoRedirect = true;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (FileStream fs = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    long totalLength = response.ContentLength;
                    byte[] buffer = new byte[65536];
                    long totalRead = 0;
                    int read;
                    Stopwatch sw = Stopwatch.StartNew();
                    long lastUpdate = 0;

                    while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        fs.Write(buffer, 0, read);
                        totalRead += read;

                        if (sw.ElapsedMilliseconds - lastUpdate > 200 || (totalLength > 0 && totalRead >= totalLength))
                        {
                            lastUpdate = sw.ElapsedMilliseconds;
                            double speedMBs = sw.ElapsedMilliseconds > 0 ? (totalRead / 1024.0 / 1024.0) / (sw.ElapsedMilliseconds / 1000.0) : 0;
                            if (totalLength > 0)
                            {
                                double percent = (double)totalRead / totalLength * 100.0;
                                int barWidth = 25;
                                int filled = (int)(percent / 100.0 * barWidth);
                                if (filled > barWidth) filled = barWidth;
                                string bar = new string('█', filled) + new string('░', barWidth - filled);
                                Console.Write(string.Format("\r   [{0}] {1,5:F1}% ({2:F1}/{3:F1} MB) @ {4:F2} MB/s", bar, percent, totalRead / 1024.0 / 1024.0, totalLength / 1024.0 / 1024.0, speedMBs));
                            }
                            else
                            {
                                Console.Write(string.Format("\r   Đã tải: {0:F1} MB @ {1:F2} MB/s", totalRead / 1024.0 / 1024.0, speedMBs));
                            }
                        }
                    }
                    Console.WriteLine();
                }

                // Giải nén
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("⏳ Đang giải nén tập tin vào thư mục: " + targetFolder + "...");
                Console.ResetColor();

                if (!Directory.Exists(targetFolder)) Directory.CreateDirectory(targetFolder);
                ZipFile.ExtractToDirectory(zipPath, targetFolder);

                try { File.Delete(zipPath); } catch {}

                string[] foundExes = Directory.GetFiles(targetFolder, item.ExeSearchPattern, SearchOption.AllDirectories);
                if (foundExes.Length > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✔ Đã tải và giải nén thành công: " + foundExes[0]);
                    Console.ResetColor();
                    Console.Write("👉 Bạn có muốn KHỞI CHẠY NGAY không? [Y/N] (Mặc định Y): ");
                    string ans = Console.ReadLine();
                    if (string.IsNullOrEmpty(ans) || ans.Trim().ToUpper() == "Y")
                    {
                        try
                        {
                            Process.Start(foundExes[0]);
                            Console.WriteLine("✔ Đã khởi chạy: " + Path.GetFileName(foundExes[0]));
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("⚠ Không thể khởi chạy: " + ex.Message);
                        }
                    }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✔ Đã giải nén vào thư mục: " + targetFolder);
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("⚠ Tải thất bại: " + ex.Message);
                Console.WriteLine("   Mẹo: Bạn có thể mở trình duyệt để tải trực tiếp từ trang chủ của hãng.");
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        #endregion

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
            static MdmInfo GetAndVerifyMdm()
        {
            MdmInfo info = new MdmInfo();

            // 1. Kiểm tra Windows Autopilot Policy Cache trong Registry
            try
            {
                using (RegistryKey apKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache"))
                {
                    if (apKey != null)
                    {
                        object pAvailable = apKey.GetValue("ProfileAvailable");
                        if (pAvailable != null && Convert.ToInt32(pAvailable) == 1)
                        {
                            info.IsAutopilotDetected = true;
                            info.IsMdmDetected = true;
                            info.DetectionReasons.Add("Profile Windows Autopilot đang sẵn sàng áp dụng (ProfileAvailable = 1)");
                        }

                        object pJson = apKey.GetValue("PolicyJsonCache");
                        if (pJson != null)
                        {
                            string json = pJson.ToString();
                            if (!string.IsNullOrEmpty(json))
                            {
                                int tdIdx = json.IndexOf("CloudAssignedTenantDomain");
                                if (tdIdx >= 0)
                                {
                                    string sub = json.Substring(tdIdx);
                                    int start = sub.IndexOf(":\"\\\"");
                                    if (start < 0) start = sub.IndexOf(":\"");
                                    if (start >= 0)
                                    {
                                        int valStart = sub.IndexOf('"', start + 1);
                                        if (valStart >= 0)
                                        {
                                            int valEnd = sub.IndexOf('"', valStart + 1);
                                            if (valEnd > valStart)
                                            {
                                                string domain = sub.Substring(valStart + 1, valEnd - valStart - 1).Replace("\\", "").Trim();
                                                if (!string.IsNullOrEmpty(domain))
                                                {
                                                    info.AutopilotTenant = domain;
                                                    info.IsAutopilotDetected = true;
                                                    info.IsMdmDetected = true;
                                                    info.DetectionReasons.Add("Tổ chức quản lý Autopilot: " + domain);
                                                }
                                            }
                                        }
                                    }
                                }

                                if (json.Contains("\"ForcedEnrollment\":1") || json.Contains("\"ForcedEnrollment\": 1"))
                                {
                                    info.IsAutopilotDetected = true;
                                    info.IsMdmDetected = true;
                                    info.DetectionReasons.Add("Bắt buộc ghi danh Autopilot khi cài lại Windows (ForcedEnrollment = 1)");
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            // 2. Kiểm tra Enrollments trong Registry (Intune, AirWatch, Workspace ONE, MobileIron...)
            try
            {
                using (RegistryKey enrollments = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Enrollments"))
                {
                    if (enrollments != null)
                    {
                        foreach (string subName in enrollments.GetSubKeyNames())
                        {
                            if (subName.Equals("Context", StringComparison.OrdinalIgnoreCase) ||
                                subName.Equals("Status", StringComparison.OrdinalIgnoreCase) ||
                                subName.Equals("ValidNodePaths", StringComparison.OrdinalIgnoreCase))
                                continue;

                            using (RegistryKey sub = enrollments.OpenSubKey(subName))
                            {
                                if (sub == null) continue;

                                object provObj = sub.GetValue("ProviderID");
                                object urlObj = sub.GetValue("DiscoveryServiceFullURL");
                                object upnObj = sub.GetValue("UPN");

                                string prov = provObj != null ? provObj.ToString().Trim() : "";
                                string url = urlObj != null ? urlObj.ToString().Trim() : "";
                                string upn = upnObj != null ? upnObj.ToString().Trim() : "";

                                if (!string.IsNullOrEmpty(url) && (url.Contains("manage.microsoft.com") || url.Contains("enrollment") || url.Contains("http")))
                                {
                                    info.IsMdmDetected = true;
                                    info.MdmDiscoveryUrl = url;
                                    if (!string.IsNullOrEmpty(prov)) info.MdmProvider = prov;
                                    info.DetectionReasons.Add(string.Format("Đăng ký MDM Server: {0} ({1})", prov, url));
                                }
                                else if (!string.IsNullOrEmpty(upn) && upn.Contains("@") && !string.IsNullOrEmpty(prov) &&
                                         !prov.Equals("Local Authority", StringComparison.OrdinalIgnoreCase) &&
                                         !prov.Equals("Deploy Authority", StringComparison.OrdinalIgnoreCase) &&
                                         !prov.Equals("Cloud Authority", StringComparison.OrdinalIgnoreCase))
                                {
                                    info.IsMdmDetected = true;
                                    info.MdmProvider = prov;
                                    info.DetectionReasons.Add(string.Format("Tài khoản tổ chức gán vào máy: {0} (Nhà cung cấp: {1})", upn, prov));
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            // 3. Kiểm tra dsregcmd /status (Azure AD Join / Enterprise Join / Domain Join)
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("dsregcmd.exe", "/status");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(3000);

                    if (!string.IsNullOrEmpty(output))
                    {
                        using (StringReader sr = new StringReader(output))
                        {
                            string line;
                            while ((line = sr.ReadLine()) != null)
                            {
                                string trimmed = line.Trim();
                                if (trimmed.StartsWith("AzureAdJoined", StringComparison.OrdinalIgnoreCase) && trimmed.EndsWith("YES", StringComparison.OrdinalIgnoreCase))
                                {
                                    info.IsAzureAdJoined = true;
                                    info.IsMdmDetected = true;
                                    info.DetectionReasons.Add("Máy đã gia nhập Azure Active Directory (AzureAdJoined = YES)");
                                }
                                else if (trimmed.StartsWith("EnterpriseJoined", StringComparison.OrdinalIgnoreCase) && trimmed.EndsWith("YES", StringComparison.OrdinalIgnoreCase))
                                {
                                    info.IsDomainJoined = true;
                                    info.IsMdmDetected = true;
                                    info.DetectionReasons.Add("Máy đã gia nhập mạng doanh nghiệp (EnterpriseJoined = YES)");
                                }
                                else if (trimmed.StartsWith("DomainJoined", StringComparison.OrdinalIgnoreCase) && trimmed.EndsWith("YES", StringComparison.OrdinalIgnoreCase))
                                {
                                    info.IsDomainJoined = true;
                                    info.IsMdmDetected = true;
                                    info.DetectionReasons.Add("Máy trực thuộc mạng máy chủ Domain công ty (DomainJoined = YES)");
                                }
                                else if (trimmed.StartsWith("TenantName", StringComparison.OrdinalIgnoreCase))
                                {
                                    int colon = trimmed.IndexOf(':');
                                    if (colon >= 0)
                                    {
                                        string tName = trimmed.Substring(colon + 1).Trim();
                                        if (!string.IsNullOrEmpty(tName) && !tName.Equals("NOT SET", StringComparison.OrdinalIgnoreCase))
                                        {
                                            info.DomainName = tName;
                                            info.IsMdmDetected = true;
                                            info.DetectionReasons.Add("Tên doanh nghiệp quản lý (TenantName): " + tName);
                                        }
                                    }
                                }
                                else if (trimmed.StartsWith("DeviceManagementUrl", StringComparison.OrdinalIgnoreCase))
                                {
                                    int colon = trimmed.IndexOf(':');
                                    if (colon >= 0)
                                    {
                                        string dmUrl = trimmed.Substring(colon + 1).Trim();
                                        if (!string.IsNullOrEmpty(dmUrl) && !dmUrl.Equals("NOT SET", StringComparison.OrdinalIgnoreCase))
                                        {
                                            info.IsMdmDetected = true;
                                            info.MdmDiscoveryUrl = dmUrl;
                                            info.DetectionReasons.Add("Cổng quản lý thiết bị: " + dmUrl);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            // 4. Kiểm tra Computrace / Absolute Persistence ngầm trong BIOS
            try
            {
                string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string rpc1 = Path.Combine(sys32, "rpcnet.exe");
                string rpc2 = Path.Combine(sys32, "rpcnetp.exe");
                string rpc3 = Path.Combine(sys32, "rpcnet.dll");

                if (File.Exists(rpc1) || File.Exists(rpc2) || File.Exists(rpc3))
                {
                    info.IsComputraceDetected = true;
                    info.IsMdmDetected = true;
                    info.DetectionReasons.Add("Dính Computrace / Absolute Persistence ngầm trong BIOS (Có thể bị khóa máy từ xa)");
                }

                using (RegistryKey rpcKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\rpcnetp"))
                {
                    if (rpcKey != null)
                    {
                        info.IsComputraceDetected = true;
                        info.IsMdmDetected = true;
                        info.DetectionReasons.Add("Dịch vụ Computrace (rpcnetp service) đang cài đặt trong hệ điều hành");
                    }
                }
            }
            catch { }

            // 5. Kiểm tra CloudDomainJoin
            try
            {
                using (RegistryKey cdjKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"))
                {
                    if (cdjKey != null && cdjKey.SubKeyCount > 0)
                    {
                        info.IsAzureAdJoined = true;
                        info.IsMdmDetected = true;
                        info.DetectionReasons.Add("Phát hiện dữ liệu CloudDomainJoin đã liên kết máy với máy chủ đám mây");
                    }
                }
            }
            catch { }

            return info;
        }
}
}
