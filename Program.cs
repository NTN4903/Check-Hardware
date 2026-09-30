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

        static CpuIdDelegate BuildCpuid()
        {
            byte[] code;
            if (IntPtr.Size == 8)
            {
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
            IntPtr ptr = VirtualAlloc(IntPtr.Zero, (UIntPtr)code.Length, 0x1000 | 0x2000, 0x40);
            Marshal.Copy(code, 0, ptr, code.Length);
            return (CpuIdDelegate)Marshal.GetDelegateForFunctionPointer(ptr, typeof(CpuIdDelegate));
        }

        static string GetHardwareCpuBrand()
        {
            try
            {
                CpuIdDelegate cpuid = BuildCpuid();
                byte[] brandBytes = new byte[48];
                byte[] buf = new byte[16];
                cpuid(unchecked((int)0x80000002), 0, buf); Buffer.BlockCopy(buf, 0, brandBytes, 0, 16);
                cpuid(unchecked((int)0x80000003), 0, buf); Buffer.BlockCopy(buf, 0, brandBytes, 16, 16);
                cpuid(unchecked((int)0x80000004), 0, buf); Buffer.BlockCopy(buf, 0, brandBytes, 32, 16);
                string brand = Encoding.ASCII.GetString(brandBytes).Trim().Replace("\0", "");
                return string.IsNullOrEmpty(brand) ? "Unknown" : brand;
            }
            catch { return "Unknown"; }
        }

        // NEW: Đọc Family/Model/Stepping thực của CPU từ CPUID(EAX=1)
        static void GetCpuFamilyModelStepping(out int family, out int model, out int stepping)
        {
            family = 0; model = 0; stepping = 0;
            try
            {
                CpuIdDelegate cpuid = BuildCpuid();
                byte[] buf = new byte[16];
                cpuid(1, 0, buf);
                uint eax = BitConverter.ToUInt32(buf, 0);
                stepping     = (int)(eax & 0xF);
                int baseFamily = (int)((eax >> 8) & 0xF);
                int baseModel  = (int)((eax >> 4) & 0xF);
                int extFamily  = (int)((eax >> 20) & 0xFF);
                int extModel   = (int)((eax >> 16) & 0xF);
                family = (baseFamily == 0xF) ? baseFamily + extFamily : baseFamily;
                model  = (baseFamily == 0x6 || baseFamily == 0xF) ? (extModel << 4) | baseModel : baseModel;
            }
            catch { }
        }

        // NEW: Giải mã thế hệ CPU từ Family/Model (Intel & AMD)
        static string DecodeCpuGeneration(int family, int model, string brandName, out string note)
        {
            note = "";
            string brand = brandName.ToUpper();
            if (brand.Contains("INTEL") || brand.Contains("CORE") || brand.Contains("CELERON") || brand.Contains("PENTIUM") || brand.Contains("XEON"))
            {
                // Intel – Family 6 (0x6) = mainstream modern Intel
                if (family == 6)
                {
                    // Alder Lake (gen 12): 0x97, 0x9A
                    if (model == 0x97 || model == 0x9A) return "Intel 12th Gen (Alder Lake)";
                    // Raptor Lake (gen 13): 0xB7, 0xBA, 0xBF
                    if (model == 0xB7 || model == 0xBA || model == 0xBF) return "Intel 13th Gen (Raptor Lake)";
                    // Meteor Lake (gen 14): 0xAA
                    if (model == 0xAA) return "Intel 14th Gen (Meteor Lake)";
                    // Tiger Lake (gen 11): 0x8C, 0x8D
                    if (model == 0x8C || model == 0x8D) return "Intel 11th Gen (Tiger Lake)";
                    // Ice Lake (gen 10): 0x7E, 0x7D
                    if (model == 0x7E || model == 0x7D) return "Intel 10th Gen (Ice Lake)";
                    // Comet Lake (gen 10): 0xA5, 0xA6
                    if (model == 0xA5 || model == 0xA6) return "Intel 10th Gen (Comet Lake)";
                    // Cannon Lake (gen 8): 0x66
                    if (model == 0x66) return "Intel 8th Gen (Cannon Lake)";
                    // Coffee Lake (gen 8/9): 0x9E, 0x8E
                    if (model == 0x9E) return "Intel 8th/9th Gen (Coffee Lake)";
                    if (model == 0x8E) return "Intel 7th/8th Gen (Kaby Lake / Whiskey Lake)";
                    // Kaby Lake (gen 7): 0x9E (low power), 0x8E
                    // Skylake (gen 6): 0x4E, 0x5E
                    if (model == 0x4E || model == 0x5E) return "Intel 6th Gen (Skylake)";
                    // Broadwell (gen 5): 0x3D, 0x47
                    if (model == 0x3D || model == 0x47) return "Intel 5th Gen (Broadwell)";
                    // Haswell (gen 4): 0x3C, 0x3F, 0x45, 0x46
                    if (model == 0x3C || model == 0x3F || model == 0x45 || model == 0x46) return "Intel 4th Gen (Haswell)";
                    // Ivy Bridge (gen 3): 0x3A, 0x3E
                    if (model == 0x3A || model == 0x3E)
                    {
                        note = "Chip Intel 3rd Gen (Ivy Bridge) - Đời cũ 2012";
                        return "Intel 3rd Gen (Ivy Bridge)";
                    }
                    // Sandy Bridge (gen 2): 0x2A, 0x2D
                    if (model == 0x2A || model == 0x2D)
                    {
                        note = "Chip Intel 2nd Gen (Sandy Bridge) - Đời rất cũ 2011!";
                        return "Intel 2nd Gen (Sandy Bridge)";
                    }
                    // Nehalem/Westmere (gen 1 Core i): 0x1E, 0x1F, 0x1A, 0x2E, 0x25, 0x2C
                    if (model == 0x1E || model == 0x1F || model == 0x1A || model == 0x2E || model == 0x25 || model == 0x2C)
                    {
                        note = "Chip Intel 1st Gen (Nehalem/Westmere) - Rất cổ, sản xuất 2008-2010!";
                        return "Intel 1st Gen (Nehalem)";
                    }
                    // Core 2 (Penryn, Wolfdale, Yorkfield): 0x17, 0x1D
                    if (model == 0x17 || model == 0x1D)
                    {
                        note = "Đây là chip Intel Core 2 (2007-2009) - Cực kỳ cổ!";
                        return "Intel Core 2 (Penryn/Yorkfield)";
                    }
                    return string.Format("Intel Family 6 Model 0x{0:X2}", model);
                }
                if (family == 0xF)
                {
                    note = "Chip Pentium 4 / Netburst thế hệ rất cũ (2000-2008)!";
                    return "Intel Pentium 4 (Netburst)";
                }
            }
            else if (brand.Contains("AMD") || brand.Contains("RYZEN") || brand.Contains("ATHLON") || brand.Contains("PHENOM"))
            {
                if (family == 0x19)
                {
                    if (model >= 0x60 && model <= 0x7F) return "AMD Ryzen 7000 (Zen 4 Raphael)";
                    if (model >= 0x40 && model <= 0x5F) return "AMD Ryzen 7045 Mobile (Zen 4 Dragon Range)";
                    return "AMD Ryzen 7000 Series (Zen 4)";
                }
                if (family == 0x17)
                {
                    if (model >= 0x70 && model <= 0x7F) return "AMD Ryzen 3000 / 5000 (Zen 2 / Zen 3)";
                    if (model >= 0x60 && model <= 0x6F) return "AMD Ryzen 4000 Mobile (Zen 2 Renoir)";
                    if (model >= 0x30 && model <= 0x3F) return "AMD Ryzen 3000 (Zen 2 Matisse)";
                    if (model >= 0x10 && model <= 0x2F) return "AMD Ryzen 2000 (Zen+ Pinnacle Ridge / Picasso)";
                    if (model >= 0x01 && model <= 0x0F) return "AMD Ryzen 1000 (Zen Summit Ridge / Raven Ridge)";
                    return "AMD Ryzen 1000-5000 (Zen / Zen+/ Zen 2)";
                }
                if (family == 0x15)
                {
                    note = "AMD FX / A-Series Excavator - Đời cũ!";
                    return "AMD FX / Excavator (2012-2016)";
                }
                if (family == 0x10 || family == 0x12)
                {
                    note = "AMD Phenom / Athlon - Rất cổ!";
                    return "AMD Phenom / Athlon (K10)";
                }
            }
            return string.Format("Family 0x{0:X2} Model 0x{1:X2}", family, model);
        }

        // NEW: Kiểm tra tên CPU có khớp với thế hệ CPUID không
        static string CheckCpuGenerationMismatch(string displayName, string cpuidGeneration)
        {
            string dUpper = displayName.ToUpper();
            string gUpper = cpuidGeneration.ToUpper();

            // Kiểm tra Intel generation mismatch
            if (gUpper.Contains("2ND") || gUpper.Contains("SANDY BRIDGE"))
            {
                if (dUpper.Contains("I7-3") || dUpper.Contains("I7-4") || dUpper.Contains("I7-5") ||
                    dUpper.Contains("I7-6") || dUpper.Contains("I7-7") || dUpper.Contains("I7-8") ||
                    dUpper.Contains("I7-9") || dUpper.Contains("I7-10") || dUpper.Contains("I7-11") ||
                    dUpper.Contains("I7-12") || dUpper.Contains("I7-13"))
                    return "MISMATCH: Chip thực là Sandy Bridge (Gen 2) nhưng tên hiển thị là chip đời cao hơn!";
            }
            if (gUpper.Contains("3RD") || gUpper.Contains("IVY BRIDGE"))
            {
                if (dUpper.Contains("I7-4") || dUpper.Contains("I7-5") || dUpper.Contains("I7-6") ||
                    dUpper.Contains("I7-7") || dUpper.Contains("I7-8") || dUpper.Contains("I7-9") ||
                    dUpper.Contains("I7-10") || dUpper.Contains("I7-11") || dUpper.Contains("I7-12"))
                    return "MISMATCH: Chip thực là Ivy Bridge (Gen 3) nhưng tên hiển thị là chip đời cao hơn!";
            }
            if (gUpper.Contains("CORE 2"))
            {
                if (dUpper.Contains("CORE I"))
                    return "MISMATCH NGHIÊM TRỌNG: Chip thực là Core 2 nhưng tên hiển thị là Core i-series!";
            }
            if (gUpper.Contains("NETBURST") || gUpper.Contains("PENTIUM 4"))
            {
                if (dUpper.Contains("CORE I"))
                    return "MISMATCH NGHIÊM TRỌNG: Chip thực là Pentium 4 nhưng tên hiển thị là Core i-series!";
            }
            if (gUpper.Contains("NEHALEM") || gUpper.Contains("1ST GEN"))
            {
                if (dUpper.Contains("I7-3") || dUpper.Contains("I7-4") || dUpper.Contains("I7-6") ||
                    dUpper.Contains("I7-7") || dUpper.Contains("I7-8") || dUpper.Contains("I7-9") ||
                    dUpper.Contains("I7-10") || dUpper.Contains("I7-11"))
                    return "MISMATCH: Chip thực là Nehalem (Gen 1) nhưng tên hiển thị là chip đời cao hơn!";
            }
            return "";
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
                            a = a * 1.000001 + 0.000002;
                    });
                    workers[i].Start();
                }
                for (int i = 0; i < threads; i++) workers[i].Join();
                sw.Stop();
                double secs = sw.Elapsed.TotalSeconds;
                if (secs <= 0.001) secs = 0.001;
                return (long)((double)(threads * itersPerThread) / (secs * 10000.0));
            }
            catch { return 0; }
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
            // NEW
            public int CpuFamily = 0;
            public int CpuModel = 0;
            public int CpuStepping = 0;
            public string CpuGeneration = "Unknown";
            public string CpuGenerationNote = "";
            public string GenerationMismatch = "";
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
            public bool IsDualChannel = false;   // NEW
            public List<RamSlotInfo> Slots = new List<RamSlotInfo>();
        }

        public class GpuDevice
        {
            public string Name = "Unknown GPU";
            public string Type = "Integrated";
            public string Vram = "N/A";
            public string VramActual = "N/A";    // NEW – VRAM thực tế từ hardware
            public string Tdp = "N/A";
            public string PnpDeviceId = "";
            public string VendorId = "";
            public string DeviceId = "";
            public string SubsystemVendor = "Unknown";
            public bool IsFakeSuspected = false;
            public bool IsVramMismatch = false;  // NEW
            public string VerificationNote = "Chưa kiểm tra";
        }

        public class DriveInfoItem
        {
            public string Model = "Unknown Drive";
            public string Size = "N/A";
            public string BusType = "SATA";
            public string MediaType = "SSD";
            public string HealthStatus = "Tốt (Healthy)";
            // NEW SMART attributes
            public int PowerOnHours = -1;
            public int ReallocatedSectors = -1;
            public int PendingSectors = -1;
            public int UncorrectableErrors = -1;
            public int WearPercent = -1;
            public double TemperatureCelsius = -1;
        }

        public class MonitorInfo
        {
            public string Resolution = "Unknown";
            public string RefreshRate = "60";
            // NEW EDID
            public string EdidManufacturer = "N/A";
            public string EdidProductCode = "N/A";
            public string PanelInfo = "N/A";
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

        // === NEW DATA MODELS ===
        public class TemperatureInfo
        {
            public double CpuTempCelsius = -1;
            public bool IsAvailable = false;
        }

        public class UsbPortInfo
        {
            public string Name = "USB Port";
            public string Standard = "USB 2.0";
            public string DeviceId = "";
        }

        public class SecurityInfo
        {
            public bool SecureBootEnabled = false;
            public bool SecureBootAvailable = false;
            public string TpmVersion = "N/A";
            public bool TpmPresent = false;
            public bool TpmEnabled = false;
            public string WindowsActivationStatus = "Unknown";
            public bool IsGenuineWindows = false;
            public string BitLockerStatus = "Không có thông tin";
        }

        public class HealthScoreResult
        {
            public int TotalScore = 100;
            public string Grade = "A";
            public string Verdict = "Xuất sắc";
            public List<string> Penalties = new List<string>();
            public List<string> Bonuses = new List<string>();
            public string PriceAdvice = "Mua bình thường";
        }
        #endregion

        [STAThread]
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║           HARDWARE INTEGRITY SCANNER by TanNhut              ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("⏳ Đang quét phần cứng & kiểm định chống gian lận...");
            Console.ResetColor();
            Console.WriteLine();

            StringBuilder report = new StringBuilder();
            report.AppendLine("==================================================================");
            report.AppendLine("     BÁO CÁO KIỂM TRA PHẦN CỨNG – HARDWARE INTEGRITY SCANNER by TanNhut");
            report.AppendLine("     Thời gian quét: " + DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss"));
            report.AppendLine("==================================================================");
            report.AppendLine();

            // ──── 1. CPU ────
            CpuInfo cpu = GetAndVerifyCpu();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [1] CPU (Bộ vi xử lý): ");
            Console.ResetColor();
            Console.WriteLine(string.Format("{0} ({1} Nhân / {2} Luồng) @ {3} MHz", cpu.Name, cpu.Cores, cpu.LogicalProcessors, cpu.ClockSpeed));

            if (cpu.IsSpoofed)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("    [🚨 CẢNH BÁO FAKE CPU] Tên CPU trong Windows đã bị can thiệp / sửa Registry!");
                Console.WriteLine("    -> Tên phần cứng gốc (Silicon CPUID): " + cpu.HardwareBrand);
                Console.WriteLine("    -> Tên hiển thị giả mạo (Windows):    " + cpu.Name);
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("    [🛡 CHUẨN XÁC] CPU nguyên bản – Khớp 100% với vi mã phần cứng (CPUID: " + cpu.HardwareBrand + ")");
                Console.ResetColor();
            }

            if (cpu.CpuFamily > 0)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(string.Format("    - Thế hệ vi mã thực tế (CPUID): Family=0x{0:X2} Model=0x{1:X2} Step=0x{2:X1} → {3}",
                    cpu.CpuFamily, cpu.CpuModel, cpu.CpuStepping, cpu.CpuGeneration));
                Console.ResetColor();
            }

            if (!string.IsNullOrEmpty(cpu.CpuGenerationNote))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("    [⚠ LƯU Ý THẾ HỆ] " + cpu.CpuGenerationNote);
                Console.ResetColor();
            }

            if (!string.IsNullOrEmpty(cpu.GenerationMismatch))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("    [🚨 CẢNH BÁO THẾ HỆ] " + cpu.GenerationMismatch);
                Console.ResetColor();
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(string.Format("    - Benchmark tính toán nhanh (500ms): {0:N0} điểm", cpu.BenchmarkScore));
            Console.ResetColor();

            report.AppendLine("[1] BỘ VI XỬ LÝ (CPU) & KIỂM ĐỊNH CHỐNG FAKE:");
            report.AppendLine("    - Tên hiển thị Windows : " + cpu.Name);
            report.AppendLine("    - Tên phần cứng (CPUID): " + cpu.HardwareBrand);
            if (cpu.CpuFamily > 0) report.AppendLine(string.Format("    - Vi mã thực tế: Family=0x{0:X2} Model=0x{1:X2} Stepping=0x{2:X1} → {3}", cpu.CpuFamily, cpu.CpuModel, cpu.CpuStepping, cpu.CpuGeneration));
            report.AppendLine(string.Format("    - Số nhân / Số luồng   : {0} Nhân / {1} Luồng", cpu.Cores, cpu.LogicalProcessors));
            report.AppendLine("    - Xung nhịp tối đa     : " + cpu.ClockSpeed + " MHz");
            report.AppendLine("    - Điểm benchmark nhanh : " + cpu.BenchmarkScore.ToString("N0") + " điểm");
            report.AppendLine("    - Kết luận kiểm định   : " + (cpu.IsSpoofed ? "🚨 PHÁT HIỆN FAKE / SỬA REGISTRY!" : "🛡 CHUẨN XÁC"));
            if (!string.IsNullOrEmpty(cpu.CpuGenerationNote)) report.AppendLine("    - Lưu ý thế hệ         : " + cpu.CpuGenerationNote);
            if (!string.IsNullOrEmpty(cpu.GenerationMismatch)) report.AppendLine("    - CẢNH BÁO THẾ HỆ     : " + cpu.GenerationMismatch);
            report.AppendLine();

            // ──── 2. RAM ────
            RamInfo ram = GetRam();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [2] RAM (Bộ nhớ trong): ");
            Console.ResetColor();
            Console.WriteLine(string.Format("{0} GB ({1} @ {2} MHz – Hãng chip: {3})", ram.Total, ram.Type, ram.Speed, ram.Manufacturer));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(string.Format("    - Khe cắm: {0}/{1} khe đang dùng (Trống: {2} khe) | Tối đa mainboard: {3} GB", ram.ActiveSlots, ram.MaxSlots, ram.EmptySlots, ram.MaxCapacity));

            if (ram.IsDualChannel)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("    [🛡 DUAL CHANNEL] Đang chạy 2 kênh – Hiệu năng bộ nhớ tối ưu!");
            }
            else if (ram.ActiveSlots == 1)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("    [⚠ SINGLE CHANNEL] Chỉ 1 thanh RAM – Mất 20-40% băng thông bộ nhớ so với Dual Channel!");
            }

            if (ram.IsConsistent)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("    [🛡 CHUẨN XÁC] Bộ nhớ RAM đồng bộ, dung lượng thực khớp với số khe cắm.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("    [⚠ LƯU Ý] Dung lượng tổng lệch so với các khe cắm (nghi vấn khai báo ảo).");
            }
            Console.ResetColor();

            report.AppendLine("[2] BỘ NHỚ TRONG (RAM):");
            report.AppendLine("    - Tổng dung lượng: " + ram.Total + " GB");
            report.AppendLine("    - Chuẩn RAM: " + ram.Type + " (" + ram.Speed + " MHz)");
            report.AppendLine("    - Hãng sản xuất chip nhớ: " + ram.Manufacturer);
            report.AppendLine(string.Format("    - Khe cắm: {0} khe (Đang dùng: {1}, Trống: {2})", ram.MaxSlots, ram.ActiveSlots, ram.EmptySlots));
            report.AppendLine("    - Khả năng nâng cấp tối đa: " + ram.MaxCapacity + " GB");
            report.AppendLine("    - Chế độ kênh: " + (ram.IsDualChannel ? "🛡 DUAL CHANNEL (Tối ưu)" : (ram.ActiveSlots == 1 ? "⚠ SINGLE CHANNEL (Kém hiệu năng)" : "Không xác định")));
            if (ram.Slots.Count > 0)
            {
                report.AppendLine("    - Chi tiết từng khe:");
                foreach (RamSlotInfo slot in ram.Slots)
                    report.AppendLine(string.Format("      + {0}: {1} GB – {2} MHz ({3})", slot.Bank, slot.Capacity, slot.Speed, slot.Manufacturer));
            }
            report.AppendLine("    - Kiểm định: " + (ram.IsConsistent ? "🛡 Hợp lệ" : "⚠ Dung lượng có dấu hiệu bất thường"));
            report.AppendLine();

            // ──── 3. Mainboard & BIOS ────
            SystemInfo sys = GetSystemInfo();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [3] Bo mạch chủ (Mainboard): ");
            Console.ResetColor();
            Console.WriteLine(string.Format("{0} – Model: {1} (Rev: {2})", sys.Motherboard.Manufacturer, sys.Motherboard.Product, sys.Motherboard.Version));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(string.Format("    - BIOS: {0} v{1} (Ngày phát hành: {2})", sys.BIOS.Vendor, sys.BIOS.Version, sys.BIOS.ReleaseDate));
            Console.ResetColor();

            report.AppendLine("[3] BO MẠCH CHỦ (MAINBOARD) & BIOS:");
            report.AppendLine("    - Hãng Mainboard : " + sys.Motherboard.Manufacturer);
            report.AppendLine("    - Model Mainboard: " + sys.Motherboard.Product + " (Rev: " + sys.Motherboard.Version + ")");
            if (!string.IsNullOrEmpty(sys.Motherboard.SerialNumber) && sys.Motherboard.SerialNumber != "N/A")
                report.AppendLine("    - Serial Mainboard: " + sys.Motherboard.SerialNumber);
            report.AppendLine("    - BIOS: " + sys.BIOS.Vendor + " v" + sys.BIOS.Version + " (" + sys.BIOS.ReleaseDate + ")");
            report.AppendLine();

            // ──── 4. GPU ────
            List<GpuDevice> gpus = GetAndVerifyGpus();
            report.AppendLine("[4] CARD ĐỒ HỌA (GPU) & KIỂM ĐỊNH CHỐNG FAKE:");
            for (int i = 0; i < gpus.Count; i++)
            {
                GpuDevice gpu = gpus[i];
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("✔ [4] GPU (" + (gpu.Type == "Discrete" ? "Card Rời" : "Card Tích Hợp") + "): ");
                Console.ResetColor();
                Console.WriteLine(string.Format("{0} (VRAM: {1} | TDP ước tính: {2})", gpu.Name, gpu.Vram, gpu.Tdp));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(string.Format("    - Mã phần cứng (PCI ID): VEN_{0} & DEV_{1} | Hãng OEM: {2}", gpu.VendorId, gpu.DeviceId, gpu.SubsystemVendor));

                if (gpu.IsVramMismatch)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(string.Format("    [🚨 CẢNH BÁO VRAM GIẢ] Tên hiển thị ngụ ý VRAM cao hơn VRAM thực tế ({0})!", gpu.VramActual));
                }

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
                report.AppendLine("      + VRAM: " + gpu.Vram + (gpu.IsVramMismatch ? " [🚨 KHÔNG KHỚP – VRAM THỰC: " + gpu.VramActual + "]" : ""));
                report.AppendLine("      + TDP ước tính: " + gpu.Tdp);
                report.AppendLine(string.Format("      + PCI Hardware ID: VEN_{0} & DEV_{1} (OEM: {2})", gpu.VendorId, gpu.DeviceId, gpu.SubsystemVendor));
                report.AppendLine("      + Kết quả: " + (gpu.IsFakeSuspected ? "🚨 " : "🛡 ") + gpu.VerificationNote);
            }
            report.AppendLine();

            // ──── 5. Storage + SMART ────
            List<DriveInfoItem> drives = GetAndVerifyStorage();
            report.AppendLine("[5] Ổ CỨNG LƯU TRỮ & SỨC KHỎE S.M.A.R.T. CHI TIẾT:");
            for (int i = 0; i < drives.Count; i++)
            {
                DriveInfoItem d = drives[i];
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("✔ [5] Ổ cứng: ");
                Console.ResetColor();
                Console.WriteLine(string.Format("{0} ({1}) | Chuẩn: {2} ({3})", d.Model, d.Size, d.BusType, d.MediaType));

                ConsoleColor healthColor = d.HealthStatus.Contains("Nguy") ? ConsoleColor.Red
                    : d.HealthStatus.Contains("Cảnh") ? ConsoleColor.Yellow : ConsoleColor.Cyan;
                Console.ForegroundColor = healthColor;
                Console.WriteLine("    [🛡 S.M.A.R.T.] Tình trạng: " + d.HealthStatus);

                if (d.PowerOnHours >= 0)
                {
                    ConsoleColor c = d.PowerOnHours > 25000 ? ConsoleColor.Red
                        : d.PowerOnHours > 15000 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
                    Console.ForegroundColor = c;
                    string pohNote = d.PowerOnHours > 25000 ? " 🚨 ĐÃ CHẠY RẤT LÂU!" : d.PowerOnHours > 15000 ? " ⚠ Đã dùng nhiều" : " ✔ Tuổi thọ bình thường";
                    Console.WriteLine(string.Format("    - Tuổi ổ cứng (Power-On Hours): {0:N0} giờ ({1:N0} ngày){2}", d.PowerOnHours, d.PowerOnHours / 24.0, pohNote));
                }
                if (d.ReallocatedSectors >= 0)
                {
                    Console.ForegroundColor = d.ReallocatedSectors > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
                    Console.WriteLine(string.Format("    - Reallocated Sectors (Bad Sector): {0}  {1}", d.ReallocatedSectors,
                        d.ReallocatedSectors > 0 ? "🚨 NGUY HIỂM – Có bad sector!" : "✔ Tốt"));
                }
                if (d.PendingSectors >= 0)
                {
                    Console.ForegroundColor = d.PendingSectors > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
                    Console.WriteLine(string.Format("    - Current Pending Sectors: {0}  {1}", d.PendingSectors,
                        d.PendingSectors > 0 ? "🚨 NGUY HIỂM!" : "✔ Tốt"));
                }
                if (d.UncorrectableErrors >= 0)
                {
                    Console.ForegroundColor = d.UncorrectableErrors > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
                    Console.WriteLine(string.Format("    - Uncorrectable Errors: {0}  {1}", d.UncorrectableErrors,
                        d.UncorrectableErrors > 0 ? "🚨 NGHIÊM TRỌNG!" : "✔ Tốt"));
                }
                if (d.WearPercent >= 0)
                {
                    ConsoleColor wc = d.WearPercent > 80 ? ConsoleColor.Red : d.WearPercent > 50 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
                    Console.ForegroundColor = wc;
                    Console.WriteLine(string.Format("    - Mài mòn SSD (Wear Level): {0}%  {1}", d.WearPercent,
                        d.WearPercent > 80 ? "🚨 Gần hết tuổi thọ!" : d.WearPercent > 50 ? "⚠ Đã dùng nhiều" : "✔ Còn tốt"));
                }
                if (d.TemperatureCelsius > 0)
                {
                    Console.ForegroundColor = d.TemperatureCelsius > 55 ? ConsoleColor.Red : ConsoleColor.DarkGray;
                    Console.WriteLine(string.Format("    - Nhiệt độ ổ cứng: {0:F0}°C  {1}", d.TemperatureCelsius,
                        d.TemperatureCelsius > 55 ? "⚠ Quá nóng!" : "✔ Bình thường"));
                }
                Console.ResetColor();

                report.AppendLine(string.Format("    - Ổ {0}: {1} | {2} | {3} | {4}", i + 1, d.Model, d.Size, d.MediaType, d.BusType));
                report.AppendLine("      + S.M.A.R.T.: " + d.HealthStatus);
                if (d.PowerOnHours >= 0) report.AppendLine(string.Format("      + Power-On Hours: {0:N0} giờ ({1:N0} ngày)", d.PowerOnHours, d.PowerOnHours / 24.0));
                if (d.ReallocatedSectors >= 0) report.AppendLine("      + Reallocated Sectors: " + d.ReallocatedSectors + (d.ReallocatedSectors > 0 ? " [🚨 NGUY HIỂM]" : " [✔ OK]"));
                if (d.PendingSectors >= 0) report.AppendLine("      + Pending Sectors: " + d.PendingSectors + (d.PendingSectors > 0 ? " [🚨 NGUY HIỂM]" : " [✔ OK]"));
                if (d.UncorrectableErrors >= 0) report.AppendLine("      + Uncorrectable Errors: " + d.UncorrectableErrors + (d.UncorrectableErrors > 0 ? " [🚨 NGHIÊM TRỌNG]" : " [✔ OK]"));
                if (d.WearPercent >= 0) report.AppendLine("      + SSD Wear Level: " + d.WearPercent + "%");
                if (d.TemperatureCelsius > 0) report.AppendLine(string.Format("      + Nhiệt độ: {0:F0}°C", d.TemperatureCelsius));
            }
            report.AppendLine();

            // ──── 6. Monitor + EDID ────
            MonitorInfo mon = GetMonitor();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [6] Màn hình hiển thị: ");
            Console.ResetColor();
            Console.WriteLine(string.Format("{0} @ {1} Hz", mon.Resolution, mon.RefreshRate));
            if (mon.PanelInfo != "N/A")
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(string.Format("    - Tấm nền EDID thực tế: {0}  (Mã sản phẩm: {1})", mon.EdidManufacturer, mon.EdidProductCode));
                Console.WriteLine("    - Thông tin panel: " + mon.PanelInfo);
                Console.ResetColor();
            }
            report.AppendLine("[6] MÀN HÌNH HIỂN THỊ:");
            report.AppendLine("    - Độ phân giải: " + mon.Resolution + " @ " + mon.RefreshRate + " Hz");
            if (mon.PanelInfo != "N/A")
            {
                report.AppendLine("    - EDID Manufacturer: " + mon.EdidManufacturer);
                report.AppendLine("    - EDID Product Code: " + mon.EdidProductCode);
                report.AppendLine("    - Thông tin tấm nền: " + mon.PanelInfo);
            }
            report.AppendLine();

            // ──── 7. Battery ────
            BatteryInfo bat = GetBattery();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [7] Tình trạng Pin: ");
            Console.ResetColor();
            if (bat.HasBattery)
            {
                string cycleText = bat.CycleCount >= 0 ? string.Format("{0:N0} chu kỳ sạc", bat.CycleCount) : "N/A";
                Console.WriteLine(string.Format("Gốc: {0} | Hiện tại: {1} (Chai: {2}) | Sạc: {3}", bat.DesignCapacity, bat.CurrentCapacity, bat.WearLevel, cycleText));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("    - Trạng thái: " + bat.Status + " | Điện áp: " + bat.Voltage);
                Console.ResetColor();
                report.AppendLine("[7] TÌNH TRẠNG PIN:");
                report.AppendLine("    - Dung lượng gốc   : " + bat.DesignCapacity);
                report.AppendLine("    - Dung lượng hiện tại: " + bat.CurrentCapacity);
                report.AppendLine("    - Tỷ lệ chai pin   : " + bat.WearLevel);
                report.AppendLine("    - Số chu kỳ sạc    : " + cycleText);
                report.AppendLine("    - Trạng thái       : " + bat.Status);
                report.AppendLine("    - Điện áp          : " + bat.Voltage);
            }
            else
            {
                Console.WriteLine("Không có Pin (Máy tính để bàn / Desktop)");
                report.AppendLine("[7] TÌNH TRẠNG PIN: Không có Pin (Desktop)");
            }
            report.AppendLine();

            // ──── 8. Network ────
            WifiInfo wifi = GetWifi();
            List<NetworkAdapterItem> netList = GetNetworkAdapters();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [8] Kết nối Mạng: ");
            Console.ResetColor();
            Console.WriteLine(string.Format("Wi-Fi: {0} (Mạng: {1} | Sóng: {2})", wifi.AdapterName, wifi.CurrentSsid, wifi.CurrentSignal));
            report.AppendLine("[8] KẾT NỐI MẠNG:");
            report.AppendLine("    - Card Wi-Fi: " + wifi.AdapterName);
            report.AppendLine("    - SSID đang kết nối: " + wifi.CurrentSsid + " (" + wifi.CurrentSignal + ")");
            if (netList.Count > 0)
            {
                report.AppendLine("    - Danh sách card mạng:");
                foreach (NetworkAdapterItem net in netList)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine(string.Format("    - {0} | MAC: {1}{2}", net.Name, net.MacAddress, net.IpAddress != "N/A" ? " | IP: " + net.IpAddress : ""));
                    Console.ResetColor();
                    report.AppendLine(string.Format("      + {0}: MAC={1}{2}", net.Name, net.MacAddress, net.IpAddress != "N/A" ? " IP=" + net.IpAddress : ""));
                }
            }
            report.AppendLine();

            // ──── 9. Camera & Audio ────
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
                Console.WriteLine("    - Âm thanh: " + string.Join(" | ", soundDevices.ToArray()));
                Console.ResetColor();
            }
            report.AppendLine("[9] CAMERA & THIẾT BỊ ÂM THANH:");
            report.AppendLine("    - Camera: " + camStr);
            foreach (string snd in soundDevices) report.AppendLine("    - Âm thanh: " + snd);
            report.AppendLine();

            // ──── 10. OS & Machine ────
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [10] Hệ điều hành & Máy: ");
            Console.ResetColor();
            Console.WriteLine(string.Format("{0} {1} | Serial: {2}", sys.Manufacturer, sys.Model, sys.SerialNumber));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(string.Format("    - HĐH: {0} (Cài ngày: {1}) | Uptime: {2}", sys.OS.Caption, sys.OS.InstallDate, sys.OS.Uptime));
            Console.ResetColor();
            report.AppendLine("[10] THÔNG TIN MÁY & HỆ ĐIỀU HÀNH:");
            report.AppendLine("    - Hãng / Model: " + sys.Manufacturer + " " + sys.Model);
            report.AppendLine("    - Serial: " + sys.SerialNumber);
            report.AppendLine("    - HĐH: " + sys.OS.Caption);
            report.AppendLine("    - Cài đặt ngày: " + sys.OS.InstallDate);
            report.AppendLine("    - Uptime: " + sys.OS.Uptime);
            report.AppendLine();

            // ──── 11. MDM / Autopilot ────
            MdmInfo mdm = GetAndVerifyMdm();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [11] Khóa Quản Lý (MDM / Autopilot / Computrace): ");
            Console.ResetColor();
            if (mdm.IsMdmDetected)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[🚨 CẢNH BÁO NGUY HIỂM] PHÁT HIỆN MÁY BỊ QUẢN LÝ DOANH NGHIỆP / DÍNH MDM!");
                foreach (string reason in mdm.DetectionReasons) Console.WriteLine("    -> " + reason);
                Console.WriteLine("    ⚠️ KHUYẾN CÁO: KHÔNG NÊN MUA! Máy thuộc tài sản công ty/trường học.");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("[🛡 SẠCH SẼ 100%] Máy tự do cá nhân – KHÔNG DÍNH MDM!");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("    - Autopilot / Intune / Azure AD / Computrace: Tất cả SẠCH");
                Console.ResetColor();
            }
            report.AppendLine("[11] KIỂM ĐỊNH MDM / AUTOPILOT / COMPUTRACE:");
            report.AppendLine("    - Kết quả: " + (mdm.IsMdmDetected ? "🚨 PHÁT HIỆN DÍNH MDM!" : "🛡 SẠCH SẼ 100%"));
            foreach (string r in mdm.DetectionReasons) report.AppendLine("      + " + r);
            report.AppendLine();

            // ──── 12. Security Audit (NEW) ────
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("⏳ Đang kiểm tra bảo mật...");
            Console.ResetColor();
            SecurityInfo sec = GetSecurityInfo();
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("✔ [12] Kiểm tra Bảo mật hệ thống: ");
            Console.ResetColor();

            ConsoleColor secureBootColor = sec.SecureBootEnabled ? ConsoleColor.Cyan : ConsoleColor.Yellow;
            Console.ForegroundColor = secureBootColor;
            Console.WriteLine("Secure Boot: " + (sec.SecureBootEnabled ? "✔ Bật (Enabled)" : "⚠ Tắt (Disabled)") +
                              " | TPM: " + (sec.TpmPresent ? sec.TpmVersion + (sec.TpmEnabled ? " ✔" : " (Tắt)") : "Không phát hiện"));

            Console.ForegroundColor = sec.IsGenuineWindows ? ConsoleColor.Cyan : ConsoleColor.Red;
            Console.WriteLine("    - Bản quyền Windows: " + sec.WindowsActivationStatus + (sec.IsGenuineWindows ? " ✔" : " 🚨 NGUY CƠ WINDOWS CRACK!"));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("    - BitLocker: " + sec.BitLockerStatus);
            Console.ResetColor();

            report.AppendLine("[12] KIỂM TRA BẢO MẬT HỆ THỐNG:");
            report.AppendLine("    - Secure Boot: " + (sec.SecureBootEnabled ? "Bật (Enabled)" : "Tắt (Disabled)"));
            report.AppendLine("    - TPM: " + (sec.TpmPresent ? sec.TpmVersion + (sec.TpmEnabled ? " (Active)" : " (Disabled)") : "Không có"));
            report.AppendLine("    - Windows Activation: " + sec.WindowsActivationStatus);
            report.AppendLine("    - BitLocker: " + sec.BitLockerStatus);
            report.AppendLine();

            // ──── 13. Temperature (NEW) ────
            TemperatureInfo temp = GetTemperatures();
            if (temp.IsAvailable)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("✔ [13] Nhiệt độ hệ thống (lúc nghỉ): ");
                Console.ResetColor();
                ConsoleColor tempColor = temp.CpuTempCelsius > 80 ? ConsoleColor.Red
                    : temp.CpuTempCelsius > 65 ? ConsoleColor.Yellow : ConsoleColor.Cyan;
                Console.ForegroundColor = tempColor;
                Console.WriteLine(string.Format("{0:F0}°C  {1}", temp.CpuTempCelsius,
                    temp.CpuTempCelsius > 80 ? "🚨 QUÁ NÓNG – Cần vệ sinh tản nhiệt ngay!" :
                    temp.CpuTempCelsius > 65 ? "⚠ Hơi nóng – Khả năng khô keo hoặc bụi nhiều" : "✔ Bình thường"));
                Console.ResetColor();
                report.AppendLine("[13] NHIỆT ĐỘ HỆ THỐNG:");
                report.AppendLine(string.Format("    - Nhiệt độ CPU (lúc nghỉ): {0:F0}°C", temp.CpuTempCelsius));
                report.AppendLine();
            }

            // ──── 14. USB Ports (NEW) ────
            List<UsbPortInfo> usbPorts = GetUsbPorts();
            if (usbPorts.Count > 0)
            {
                int usb3Count = 0, usb2Count = 0;
                foreach (UsbPortInfo p in usbPorts)
                {
                    if (p.Standard.Contains("3") || p.Standard.Contains("4")) usb3Count++;
                    else usb2Count++;
                }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write(string.Format("✔ [14] Cổng USB ({0} cổng phát hiện): ", usbPorts.Count));
                Console.ResetColor();
                Console.WriteLine(string.Format("USB 3.x/4: {0} cổng | USB 2.0: {1} cổng", usb3Count, usb2Count));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                foreach (UsbPortInfo p in usbPorts)
                    Console.WriteLine(string.Format("    - {0}  [{1}]", p.Name, p.Standard));
                Console.ResetColor();
                report.AppendLine(string.Format("[14] CỔNG USB ({0} cổng):", usbPorts.Count));
                foreach (UsbPortInfo p in usbPorts)
                    report.AppendLine(string.Format("    - {0}  [{1}]", p.Name, p.Standard));
                report.AppendLine();
            }

            // ──── 15. Health Score (NEW) ────
            HealthScoreResult score = CalculateHealthScore(cpu, ram, gpus, drives, bat, mdm, sec, temp);
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║              📊 ĐIỂM SỨC KHỎE TỔNG HỢP MÁY (Health Score)      ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();

            ConsoleColor scoreColor = score.TotalScore >= 80 ? ConsoleColor.Green : score.TotalScore >= 60 ? ConsoleColor.Yellow : ConsoleColor.Red;
            Console.ForegroundColor = scoreColor;
            Console.WriteLine(string.Format("  ĐIỂM: {0}/100  |  XẾP HẠNG: {1}  |  KẾT LUẬN: {2}", score.TotalScore, score.Grade, score.Verdict));
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  💡 GỢI Ý KHI MUA: " + score.PriceAdvice);
            Console.ResetColor();
            if (score.Penalties.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  ❌ Điểm trừ:");
                foreach (string p in score.Penalties) Console.WriteLine("    - " + p);
                Console.ResetColor();
            }
            if (score.Bonuses.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  ✔ Điểm cộng:");
                foreach (string b in score.Bonuses) Console.WriteLine("    + " + b);
                Console.ResetColor();
            }

            report.AppendLine("[15] ĐIỂM SỨC KHỎE TỔNG HỢP (HEALTH SCORE):");
            report.AppendLine(string.Format("    - Điểm: {0}/100 | Xếp hạng: {1} | Kết luận: {2}", score.TotalScore, score.Grade, score.Verdict));
            report.AppendLine("    - Gợi ý mua: " + score.PriceAdvice);
            if (score.Penalties.Count > 0) { report.AppendLine("    - Điểm trừ:"); foreach (string p in score.Penalties) report.AppendLine("      - " + p); }
            if (score.Bonuses.Count > 0)   { report.AppendLine("    - Điểm cộng:"); foreach (string b in score.Bonuses) report.AppendLine("      + " + b); }
            report.AppendLine();
            report.AppendLine("==================================================================");

            // Clipboard summary
            try
            {
                string clipText = string.Format(
                    "CẤU HÌNH & KIỂM ĐỊNH v2.0:\n" +
                    "- Máy: {0} {1} (Serial: {2})\n" +
                    "- CPU: {3} [{4}] CPUID={5}{6}\n" +
                    "- RAM: {7}GB {8} @ {9}MHz [{10}]\n" +
                    "- GPU: {11} ({12}) [VEN_{13}&DEV_{14}]{15}\n" +
                    "- Ổ cứng: {16} [{17}]{18}\n" +
                    "- Màn hình: {19} @ {20}Hz\n" +
                    "- Pin: {21}\n" +
                    "- Bảo mật: SecureBoot={22} TPM={23} Windows={24}\n" +
                    "- MDM: {25}\n" +
                    "- ĐIỂM SỨC KHỎE: {26}/100 ({27}) – {28}",
                    sys.Manufacturer, sys.Model, sys.SerialNumber,
                    cpu.Name, cpu.IsSpoofed ? "⚠FAKE" : "✔OK", cpu.HardwareBrand,
                    !string.IsNullOrEmpty(cpu.CpuGeneration) ? " [" + cpu.CpuGeneration + "]" : "",
                    ram.Total, ram.Type, ram.Speed, ram.IsDualChannel ? "DUAL CH" : "SINGLE CH",
                    gpus.Count > 0 ? gpus[0].Name : "N/A", gpus.Count > 0 ? gpus[0].Vram : "N/A",
                    gpus.Count > 0 ? gpus[0].VendorId : "N/A", gpus.Count > 0 ? gpus[0].DeviceId : "N/A",
                    gpus.Count > 0 && (gpus[0].IsFakeSuspected || gpus[0].IsVramMismatch) ? " ⚠NGHI VẤN" : "",
                    drives.Count > 0 ? drives[0].Model + " (" + drives[0].Size + ")" : "N/A",
                    drives.Count > 0 ? drives[0].HealthStatus : "N/A",
                    drives.Count > 0 && drives[0].PowerOnHours >= 0 ? string.Format(" [{0:N0}h]", drives[0].PowerOnHours) : "",
                    mon.Resolution, mon.RefreshRate,
                    bat.HasBattery ? string.Format("Chai {0} / {1}cy", bat.WearLevel, bat.CycleCount) : "Desktop",
                    sec.SecureBootEnabled ? "ON" : "OFF",
                    sec.TpmPresent ? sec.TpmVersion : "N/A",
                    sec.IsGenuineWindows ? "Genuine ✔" : "⚠NGHI VẤN CRACK",
                    mdm.IsMdmDetected ? "🚨DÍNH MDM!" : "SẠCH ✔",
                    score.TotalScore, score.Grade, score.Verdict
                );
                Clipboard.SetText(clipText);
            }
            catch { }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("✔ Đã quét hoàn tất! Tóm tắt cấu hình đã được sao chép vào Clipboard.");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();

            string reportPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ThongSo_PhanCung.txt");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("👉 Bạn có muốn xuất kết quả ra file báo cáo (ThongSo_PhanCung.txt)? [Y/N] (Mặc định Y): ");
            Console.ResetColor();

            string answer = "Y";
            try
            {
                string input = Console.ReadLine();
                if (!string.IsNullOrEmpty(input)) answer = input.Trim().ToUpper();
            }
            catch { }

            if (answer != "N" && answer != "NO")
            {
                try
                {
                    File.WriteAllText(reportPath, report.ToString(), Encoding.UTF8);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✔ Đã lưu file báo cáo: " + Path.GetFileName(reportPath));
                    Console.ResetColor();
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("❌ Không thể lưu file: " + ex.Message);
                    Console.ResetColor();
                }
            }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✔ Đã hoàn tất quét và kiểm định phần cứng!");
            Console.ResetColor();

            ShowUsedPcSuiteMenu();
        }

        #region Used PC Test Suite & Downloader Hub

        class SoftwareItem
        {
            public string Id, Name, Description, DownloadUrl, FileName, ExeSearchPattern, FolderName, ExternalUrl;
            public bool IsExternalOnly;
            public SoftwareItem(string id, string name, string desc, string url, string fn, string folder, string exe, bool ext, string extUrl)
            {
                Id = id; Name = name; Description = desc; DownloadUrl = url; FileName = fn;
                FolderName = folder; ExeSearchPattern = exe; IsExternalOnly = ext; ExternalUrl = extUrl;
            }
        }

        static void ShowUsedPcSuiteMenu()
        {
            while (true)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("╔═══════════════════════════════════════════════════════════════════════╗");
                Console.WriteLine("║     BỘ CÔNG CỤ TEST MÁY CŨ & TẢI TOOL CHUYÊN SÂU (PITVN v2.0)       ║");
                Console.WriteLine("╚═══════════════════════════════════════════════════════════════════════╝");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [1] 📺 Test Màn hình (Dead Pixel & IPS Backlight Bleed)");
                Console.WriteLine("  [2] ⌨️  Test Bàn phím trực quan (Keyboard Tester - phím liệt/kẹt)");
                Console.WriteLine("  [3] 🔥 CPU Stress Test & Kiểm tra Tản nhiệt (Thermal Throttling)");
                Console.WriteLine("  [4] 🚀 Đo tốc độ Đọc/Ghi Ổ cứng (Sequential R/W MB/s)");
                Console.WriteLine("  [5] 🔊 Test Loa Trái / Phải (Stereo Channel Isolation)");
                Console.WriteLine("  [6] 🔋 Kiểm tra Tốc độ Nạp/Xả Pin & Công suất Sạc");
                Console.WriteLine("  [7] 📥 Tải & Chạy Tool Chuyên Dụng (FurMark, HWMonitor, CPU-Z...)");
                Console.WriteLine("  [8] 🔌 Kiểm tra Cổng USB (USB Port Tester)");      // NEW
                Console.WriteLine("  [9] 🔐 Kiểm tra Bảo mật chi tiết (Security Audit)"); // NEW
                Console.WriteLine("  [R] 🔄 Quét lại toàn bộ phần cứng & Copy tóm tắt vào Clipboard");
                Console.WriteLine("  [0] ❌ Thoát chương trình");
                Console.ResetColor();
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("👉 Vui lòng chọn chức năng [0-9, R]: ");
                Console.ResetColor();

                string choice = Console.ReadLine();
                if (choice == null) break;
                choice = choice.Trim().ToUpper();

                if (choice == "0" || choice == "EXIT" || choice == "THOAT") { Console.ForegroundColor = ConsoleColor.Cyan; Console.WriteLine("\nCảm ơn bạn đã sử dụng công cụ! Chúc bạn chọn được chiếc máy ưng ý."); Console.ResetColor(); break; }
                switch (choice)
                {
                    case "1": RunScreenDeadPixelTest(); break;
                    case "2": RunVisualKeyboardTest(); break;
                    case "3": RunCpuStressAndThrottlingTest(); break;
                    case "4": RunDiskBenchmarkTest(); break;
                    case "5": RunAudioStereoTest(); break;
                    case "6": RunBatteryChargeTest(); break;
                    case "7": ShowSoftwareDownloaderMenu(); break;
                    case "8": RunUsbPortTest(); break;       // NEW
                    case "9": RunSecurityAuditDetail(); break; // NEW
                    case "R": Console.Clear(); Main(new string[0]); return;
                    default:
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("⚠ Lựa chọn không hợp lệ. Vui lòng nhập 0-9 hoặc R.");
                        Console.ResetColor(); break;
                }
            }
        }

        // ── NEW: USB Port Test ──
        static void RunUsbPortTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("          🔌 KIỂM TRA CỔNG USB (USB PORT TESTER)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• Tool sẽ liệt kê tất cả cổng USB Hub trên máy.");
            Console.WriteLine("• Cổng USB 3.x/4 cho tốc độ truyền dữ liệu cao hơn USB 2.0.");
            Console.WriteLine("• Nếu cổng bạn cắm thiết bị vào nhưng KHÔNG xuất hiện → Cổng đó có thể bị hỏng!");
            Console.WriteLine();

            List<UsbPortInfo> ports = GetUsbPorts();
            if (ports.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("⚠ Không phát hiện được USB Hub. Có thể driver bị lỗi hoặc không có quyền truy cập.");
                Console.ResetColor();
            }
            else
            {
                int usb3 = 0, usb2 = 0;
                foreach (UsbPortInfo p in ports) { if (p.Standard.Contains("3") || p.Standard.Contains("4")) usb3++; else usb2++; }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(string.Format("✔ Phát hiện {0} cổng USB: {1} cổng USB 3.x/4  |  {2} cổng USB 2.0", ports.Count, usb3, usb2));
                Console.ResetColor();
                Console.WriteLine();
                int idx = 1;
                foreach (UsbPortInfo p in ports)
                {
                    ConsoleColor c = (p.Standard.Contains("3") || p.Standard.Contains("4")) ? ConsoleColor.Cyan : ConsoleColor.DarkGray;
                    Console.ForegroundColor = c;
                    Console.WriteLine(string.Format("  [{0:D2}] {1}  [{2}]", idx++, p.Name, p.Standard));
                    Console.ResetColor();
                }
            }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("💡 HƯỚNG DẪN TEST THỦ CÔNG:");
            Console.WriteLine("  1. Cắm lần lượt thiết bị USB (USB 3.0 flash drive) vào từng cổng.");
            Console.WriteLine("  2. Mở 'This PC' hoặc 'Device Manager' và xem có nhận thiết bị không.");
            Console.WriteLine("  3. Dùng USB 3.0 flash drive để test tốc độ thực tế của từng cổng.");
            Console.WriteLine("  4. Cổng USB 3.x sẽ có vạch màu xanh bên trong đầu cắm.");
            Console.ResetColor();
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✔ Đã hoàn tất kiểm tra cổng USB!");
            Console.ResetColor();
        }

        // ── NEW: Security Audit Detail ──
        static void RunSecurityAuditDetail()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("          🔐 KIỂM TRA BẢO MẬT CHI TIẾT (SECURITY AUDIT)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("⏳ Đang kiểm tra bảo mật hệ thống...");
            Console.ResetColor();

            SecurityInfo sec = GetSecurityInfo();
            Console.WriteLine();

            // Secure Boot
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("━━━ [1] SECURE BOOT ━━━");
            Console.ResetColor();
            if (sec.SecureBootAvailable)
            {
                if (sec.SecureBootEnabled)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✔ Secure Boot: BẬT (Enabled)");
                    Console.WriteLine("  → Máy được bảo vệ chống bootkit và rootkit cấp UEFI.");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("⚠ Secure Boot: TẮT (Disabled)");
                    Console.WriteLine("  → Máy có thể bị cài phần mềm độc hại cấp UEFI.");
                    Console.WriteLine("  → Lưu ý: Windows 11 yêu cầu Secure Boot. Nếu tắt, có thể máy đang chạy Win 11 bypass.");
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("ℹ Secure Boot: Không xác định được (BIOS Legacy hoặc không truy cập được)");
            }
            Console.ResetColor();

            // TPM
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("━━━ [2] TPM (Trusted Platform Module) ━━━");
            Console.ResetColor();
            if (sec.TpmPresent)
            {
                Console.ForegroundColor = sec.TpmEnabled ? ConsoleColor.Green : ConsoleColor.Yellow;
                Console.WriteLine(string.Format("{0} TPM: {1}  |  Trạng thái: {2}", sec.TpmEnabled ? "✔" : "⚠", sec.TpmVersion, sec.TpmEnabled ? "Đang hoạt động" : "Hiện diện nhưng bị tắt"));
                if (sec.TpmVersion.Contains("2.0") || sec.TpmVersion.Contains("2"))
                    Console.WriteLine("  → TPM 2.0 – Đáp ứng đầy đủ yêu cầu Windows 11.");
                else
                    Console.WriteLine("  → TPM 1.2 – Không đáp ứng Windows 11 (cần TPM 2.0).");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("⚠ TPM: Không phát hiện hoặc bị tắt trong BIOS");
                Console.WriteLine("  → Không thể dùng Windows Hello, BitLocker hardware encryption.");
            }
            Console.ResetColor();

            // Windows Activation
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("━━━ [3] BẢN QUYỀN WINDOWS ━━━");
            Console.ResetColor();
            Console.ForegroundColor = sec.IsGenuineWindows ? ConsoleColor.Green : ConsoleColor.Red;
            Console.WriteLine(string.Format("{0} Trạng thái kích hoạt: {1}", sec.IsGenuineWindows ? "✔" : "🚨", sec.WindowsActivationStatus));
            if (!sec.IsGenuineWindows)
            {
                Console.WriteLine("  🚨 CẢNH BÁO: Windows có thể đang chạy dạng Crack/KMS không bản quyền!");
                Console.WriteLine("  → Rủi ro: Có thể bị vô hiệu hóa bởi Microsoft Update bất kỳ lúc nào.");
                Console.WriteLine("  → Rủi ro: Có thể chứa phần mềm độc hại trong bộ crack.");
            }
            Console.ResetColor();

            // BitLocker
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("━━━ [4] BITLOCKER ━━━");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("ℹ Trạng thái BitLocker: " + sec.BitLockerStatus);
            Console.ResetColor();

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✔ Đã hoàn tất kiểm tra bảo mật chi tiết!");
            Console.ResetColor();
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
            Console.WriteLine("  - Màu ĐEN: Soi hở sáng 4 góc/viền (IPS Backlight Bleed), điểm kẹt sáng.");
            Console.WriteLine("  - Màu ĐỎ / XANH LÁ / XANH DƯƠNG: Soi chết điểm ảnh phụ (Subpixel).");
            Console.WriteLine("• Thao tác: [Click chuột] hoặc [Space/→] đổi màu | [ESC] Thoát.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("👉 Nhấn Enter để BẮT ĐẦU test màn hình...");
            Console.ResetColor();
            Console.ReadLine();

            Color[] colors = { Color.White, Color.Black, Color.Red, Color.FromArgb(0, 255, 0), Color.FromArgb(0, 0, 255), Color.Yellow, Color.Magenta, Color.Cyan, Color.FromArgb(128, 128, 128) };
            string[] colorNames = { "TRẮNG (Soi điểm chết đen, đốm ố lót, bụi)", "ĐEN (Soi hở sáng IPS bleed, điểm kẹt sáng)", "ĐỎ (Red Subpixel)", "XANH LÁ (Green Subpixel)", "XANH DƯƠNG (Blue Subpixel)", "VÀNG (Yellow)", "HỒNG (Magenta)", "XANH LƠ (Cyan)", "XÁM (Độ đồng đều tấm nền)" };
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
                lblBanner.AutoSize = false; lblBanner.Height = 44; lblBanner.Dock = DockStyle.Bottom;
                lblBanner.TextAlign = ContentAlignment.MiddleCenter;
                lblBanner.Font = new Font("Segoe UI", 12f, FontStyle.Bold);
                lblBanner.BackColor = Color.FromArgb(170, 20, 20, 20); lblBanner.ForeColor = Color.White;
                lblBanner.Text = string.Format("[{0}/{1}] {2} | Click/Space: Đổi màu | ESC: Thoát", currentIndex + 1, colors.Length, colorNames[currentIndex]);
                form.Controls.Add(lblBanner);

                System.Windows.Forms.Timer fadeTimer = new System.Windows.Forms.Timer();
                fadeTimer.Interval = 2800;
                fadeTimer.Tick += delegate { lblBanner.Visible = false; fadeTimer.Stop(); };
                fadeTimer.Start();

                Action applyColor = delegate {
                    form.BackColor = colors[currentIndex];
                    lblBanner.Text = string.Format("[{0}/{1}] {2} | Click/Space: Đổi màu | ESC: Thoát", currentIndex + 1, colors.Length, colorNames[currentIndex]);
                    lblBanner.Visible = true; fadeTimer.Stop(); fadeTimer.Start();
                };

                form.MouseClick += delegate(object sender, MouseEventArgs e) {
                    if (e.Button == MouseButtons.Right) currentIndex = (currentIndex - 1 + colors.Length) % colors.Length;
                    else currentIndex = (currentIndex + 1) % colors.Length;
                    applyColor();
                };
                form.KeyDown += delegate(object sender, KeyEventArgs e) {
                    if (e.KeyCode == Keys.Escape) form.Close();
                    else if (e.KeyCode == Keys.Space || e.KeyCode == Keys.Right || e.KeyCode == Keys.Down || e.KeyCode == Keys.PageDown)
                    { currentIndex = (currentIndex + 1) % colors.Length; applyColor(); }
                    else if (e.KeyCode == Keys.Left || e.KeyCode == Keys.Up || e.KeyCode == Keys.PageUp)
                    { currentIndex = (currentIndex - 1 + colors.Length) % colors.Length; applyColor(); }
                };
                form.ShowDialog();
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✔ Đã hoàn tất kiểm tra màn hình!");
            Console.ResetColor();
        }

        class KeyDef
        {
            public Keys Key; public string Label; public int X, Y, Width, Height;
            public KeyDef(Keys key, string label, int x, int y, int width, int height) { Key = key; Label = label; X = x; Y = y; Width = width; Height = height; }
        }

        static void RunVisualKeyboardTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("    KIỂM TRA BÀN PHÍM TRỰC QUAN (VISUAL KEYBOARD TESTER)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• Lướt ngón tay qua từng hàng phím. Phím tốt → ĐỔI MÀU XANH LÁ.");
            Console.WriteLine("• Phím KHÔNG đổi màu → Phím đó bị liệt hoặc kẹt!");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("👉 Nhấn Enter để BẮT ĐẦU...");
            Console.ResetColor();
            Console.ReadLine();

            using (Form form = new Form())
            {
                form.Text = "Trình Kiểm Tra Bàn Phím Trực Quan – PITVN Community";
                form.Size = new Size(1080, 520);
                form.StartPosition = FormStartPosition.CenterScreen;
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false;
                form.BackColor = Color.FromArgb(24, 24, 28);
                form.KeyPreview = true;

                Panel topPanel = new Panel(); topPanel.Dock = DockStyle.Top; topPanel.Height = 70; topPanel.BackColor = Color.FromArgb(32, 32, 38);
                form.Controls.Add(topPanel);

                Label lblTitle = new Label(); lblTitle.Text = "⌨️ TRÌNH TEST BÀN PHÍM – BẤM PHÍM BẤT KỲ ĐỂ KIỂM TRA";
                lblTitle.Font = new Font("Segoe UI", 11f, FontStyle.Bold); lblTitle.ForeColor = Color.FromArgb(0, 210, 255);
                lblTitle.Location = new Point(16, 10); lblTitle.AutoSize = true;
                topPanel.Controls.Add(lblTitle);

                Label lblStatus = new Label(); lblStatus.Text = "Đã kiểm tra: 0 phím | Phím vừa bấm: [Chưa có]";
                lblStatus.Font = new Font("Segoe UI", 10.5f); lblStatus.ForeColor = Color.White;
                lblStatus.Location = new Point(16, 38); lblStatus.AutoSize = true;
                topPanel.Controls.Add(lblStatus);

                Button btnReset = new Button(); btnReset.Text = "🔄 Reset"; btnReset.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                btnReset.ForeColor = Color.White; btnReset.BackColor = Color.FromArgb(50, 50, 60); btnReset.FlatStyle = FlatStyle.Flat;
                btnReset.Size = new Size(120, 32); btnReset.Location = new Point(780, 20);
                topPanel.Controls.Add(btnReset);

                Button btnClose = new Button(); btnClose.Text = "❌ Đóng (ESC)"; btnClose.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                btnClose.ForeColor = Color.White; btnClose.BackColor = Color.FromArgb(180, 40, 40); btnClose.FlatStyle = FlatStyle.Flat;
                btnClose.Size = new Size(130, 32); btnClose.Location = new Point(915, 20);
                topPanel.Controls.Add(btnClose);

                Panel kbPanel = new Panel(); kbPanel.Location = new Point(16, 85); kbPanel.Size = new Size(1030, 380); kbPanel.BackColor = Color.FromArgb(18, 18, 22);
                form.Controls.Add(kbPanel);

                List<KeyDef> defs = new List<KeyDef>();
                int kw = 48, kh = 42, gap = 4;
                defs.Add(new KeyDef(Keys.Escape, "Esc", 10, 10, kw, kh));
                int xF = 10 + kw + 15;
                for (int i = 1; i <= 12; i++) { Keys fk = (Keys)Enum.Parse(typeof(Keys), "F" + i); defs.Add(new KeyDef(fk, "F" + i, xF, 10, kw, kh)); xF += kw + gap; if (i == 4 || i == 8) xF += 10; }
                defs.Add(new KeyDef(Keys.PrintScreen, "PrtSc", xF + 15, 10, 56, kh));
                defs.Add(new KeyDef(Keys.Delete, "Del", xF + 15 + 56 + gap, 10, 56, kh));
                int y1 = 10 + kh + gap + 10, x1 = 10;
                defs.Add(new KeyDef(Keys.Oemtilde, "~", x1, y1, kw, kh)); x1 += kw + gap;
                for (int i = 0; i < 10; i++) { defs.Add(new KeyDef((Keys)(Keys.D0 + (i < 9 ? i + 1 : 0)), (i < 9 ? (i + 1).ToString() : "0"), x1, y1, kw, kh)); x1 += kw + gap; }
                defs.Add(new KeyDef(Keys.OemMinus, "-", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.Oemplus, "=", x1, y1, kw, kh)); x1 += kw + gap;
                defs.Add(new KeyDef(Keys.Back, "Backspace", x1, y1, 100, kh));
                int y2 = y1 + kh + gap, x2 = 10;
                defs.Add(new KeyDef(Keys.Tab, "Tab", x2, y2, 70, kh)); x2 += 70 + gap;
                foreach (char c in "QWERTYUIOP") { defs.Add(new KeyDef((Keys)Enum.Parse(typeof(Keys), c.ToString()), c.ToString(), x2, y2, kw, kh)); x2 += kw + gap; }
                defs.Add(new KeyDef(Keys.OemOpenBrackets, "[", x2, y2, kw, kh)); x2 += kw + gap;
                defs.Add(new KeyDef(Keys.Oem6, "]", x2, y2, kw, kh)); x2 += kw + gap;
                defs.Add(new KeyDef(Keys.Oem5, "\\", x2, y2, 80, kh));
                int y3 = y2 + kh + gap, x3 = 10;
                defs.Add(new KeyDef(Keys.Capital, "Caps", x3, y3, 80, kh)); x3 += 80 + gap;
                foreach (char c in "ASDFGHJKL") { defs.Add(new KeyDef((Keys)Enum.Parse(typeof(Keys), c.ToString()), c.ToString(), x3, y3, kw, kh)); x3 += kw + gap; }
                defs.Add(new KeyDef(Keys.Oem1, ";", x3, y3, kw, kh)); x3 += kw + gap;
                defs.Add(new KeyDef(Keys.Oem7, "'", x3, y3, kw, kh)); x3 += kw + gap;
                defs.Add(new KeyDef(Keys.Return, "Enter", x3, y3, 122, kh));
                int y4 = y3 + kh + gap, x4 = 10;
                defs.Add(new KeyDef(Keys.ShiftKey, "Shift", x4, y4, 105, kh)); x4 += 105 + gap;
                foreach (char c in "ZXCVBNM") { defs.Add(new KeyDef((Keys)Enum.Parse(typeof(Keys), c.ToString()), c.ToString(), x4, y4, kw, kh)); x4 += kw + gap; }
                defs.Add(new KeyDef(Keys.Oemcomma, ",", x4, y4, kw, kh)); x4 += kw + gap;
                defs.Add(new KeyDef(Keys.OemPeriod, ".", x4, y4, kw, kh)); x4 += kw + gap;
                defs.Add(new KeyDef(Keys.OemQuestion, "/", x4, y4, kw, kh)); x4 += kw + gap;
                defs.Add(new KeyDef(Keys.RShiftKey, "Shift", x4, y4, 145, kh)); x4 += 145 + gap;
                defs.Add(new KeyDef(Keys.Up, "▲", x4 + 48 + gap, y4, kw, kh));
                int y5 = y4 + kh + gap, x5 = 10;
                defs.Add(new KeyDef(Keys.ControlKey, "Ctrl", x5, y5, 72, kh)); x5 += 72 + gap;
                defs.Add(new KeyDef(Keys.LWin, "Win", x5, y5, 60, kh)); x5 += 60 + gap;
                defs.Add(new KeyDef(Keys.Menu, "Alt", x5, y5, 62, kh)); x5 += 62 + gap;
                defs.Add(new KeyDef(Keys.Space, "Space", x5, y5, 370, kh)); x5 += 370 + gap;
                defs.Add(new KeyDef(Keys.RMenu, "AltGr", x5, y5, 62, kh)); x5 += 62 + gap;
                defs.Add(new KeyDef(Keys.RControlKey, "Ctrl", x5, y5, 68, kh)); x5 += 68 + gap + 4;
                defs.Add(new KeyDef(Keys.Left, "◄", x5, y5, kw, kh)); x5 += kw + gap;
                defs.Add(new KeyDef(Keys.Down, "▼", x5, y5, kw, kh)); x5 += kw + gap;
                defs.Add(new KeyDef(Keys.Right, "►", x5, y5, kw, kh));

                Dictionary<Keys, Panel> keyPanels = new Dictionary<Keys, Panel>();
                int pressedCount = 0;

                foreach (KeyDef kd in defs)
                {
                    Panel kp = new Panel();
                    kp.Location = new Point(kd.X, kd.Y); kp.Size = new Size(kd.Width, kd.Height);
                    kp.BackColor = Color.FromArgb(50, 50, 60); kp.Tag = kd.Key;
                    Label lbl = new Label();
                    lbl.Text = kd.Label; lbl.AutoSize = false; lbl.Dock = DockStyle.Fill;
                    lbl.TextAlign = ContentAlignment.MiddleCenter;
                    lbl.Font = new Font("Segoe UI", kd.Width > 80 ? 9f : 9f, FontStyle.Bold);
                    lbl.ForeColor = Color.FromArgb(180, 180, 200); lbl.Tag = kd.Key;
                    kp.Controls.Add(lbl); kbPanel.Controls.Add(kp);
                    if (!keyPanels.ContainsKey(kd.Key)) keyPanels[kd.Key] = kp;
                }

                Action<Keys> pressKey = delegate(Keys k) {
                    if (keyPanels.ContainsKey(k))
                    {
                        Panel kp = keyPanels[k];
                        if (kp.BackColor != Color.FromArgb(50, 205, 50)) { pressedCount++; kp.BackColor = Color.FromArgb(50, 205, 50); if (kp.Controls.Count > 0) kp.Controls[0].ForeColor = Color.Black; }
                        lblStatus.Text = string.Format("Đã kiểm tra: {0} phím | Phím vừa bấm: [{1}]", pressedCount, k.ToString());
                    }
                };

                Action doReset = delegate {
                    pressedCount = 0;
                    foreach (Keys k in keyPanels.Keys) { keyPanels[k].BackColor = Color.FromArgb(50, 50, 60); if (keyPanels[k].Controls.Count > 0) keyPanels[k].Controls[0].ForeColor = Color.FromArgb(180, 180, 200); }
                    lblStatus.Text = "Đã kiểm tra: 0 phím | Phím vừa bấm: [Chưa có]";
                };

                form.KeyDown += delegate(object sender, KeyEventArgs e) { if (e.KeyCode == Keys.Escape) form.Close(); else pressKey(e.KeyCode); };
                btnReset.Click += delegate(object sender, EventArgs e) { doReset(); };
                btnClose.Click += delegate(object sender, EventArgs e) { form.Close(); };
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
            Console.WriteLine("    🔥 CPU STRESS TEST & KIỂM TRA NHIỆT ĐỘ / THROTTLING");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• Ép tải 100% toàn bộ nhân CPU trong 15s hoặc 30s.");
            Console.WriteLine("• So sánh điểm benchmark trước và sau khi ép tải → phát hiện Throttling.");
            Console.WriteLine("• Throttling > 15% = Khô keo tản nhiệt hoặc quạt hỏng!");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("👉 Chọn thời gian stress test: [1] 15 giây  [2] 30 giây  (Mặc định 15s): ");
            Console.ResetColor();
            string dChoice = Console.ReadLine();
            int duration = (dChoice != null && dChoice.Trim() == "2") ? 30000 : 15000;

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(string.Format("⏳ Đang chạy Benchmark nguội ({0}ms)...", 500));
            Console.ResetColor();
            long scoreCold = RunCpuBenchmark(500);

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(string.Format("🔥 Đang ép tải {0} giây... (CPU đang chạy 100% tải!)", duration / 1000));
            Console.ResetColor();

            int threads = Environment.ProcessorCount;
            Thread[] workers = new Thread[threads];
            bool running = true;
            for (int i = 0; i < threads; i++)
            {
                workers[i] = new Thread(() => { double a = 1.0001; while (running) a = a * 1.000001 + 0.000002; });
                workers[i].IsBackground = true;
                workers[i].Start();
            }

            TemperatureInfo tempHot = new TemperatureInfo();
            Thread.Sleep(duration / 2);
            tempHot = GetTemperatures();
            Thread.Sleep(duration / 2);

            running = false;
            for (int i = 0; i < threads; i++) { try { workers[i].Join(500); } catch { } }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("⏳ Đang chạy Benchmark nóng...");
            Console.ResetColor();
            long scoreHot = RunCpuBenchmark(500);

            double throttlePct = scoreCold > 0 ? Math.Max(0.0, (1.0 - (double)scoreHot / scoreCold) * 100.0) : 0;

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("                    KẾT QUẢ STRESS TEST");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine(string.Format("  - Điểm Benchmark NGUỘI : {0:N0} điểm", scoreCold));
            Console.WriteLine(string.Format("  - Điểm Benchmark NÓNG  : {0:N0} điểm", scoreHot));
            if (tempHot.IsAvailable) Console.WriteLine(string.Format("  - Nhiệt độ CPU khi tải  : {0:F0}°C", tempHot.CpuTempCelsius));
            Console.ForegroundColor = throttlePct > 25 ? ConsoleColor.Red : throttlePct > 10 ? ConsoleColor.Yellow : ConsoleColor.Green;
            Console.WriteLine(string.Format("  - Sụt giảm hiệu năng   : {0:F1}%  {1}", throttlePct,
                throttlePct > 25 ? "🚨 THROTTLING NGHIÊM TRỌNG – Khô keo / quạt hỏng!" :
                throttlePct > 10 ? "⚠ Throttling nhẹ – Nên vệ sinh tản nhiệt" : "✔ Tản nhiệt tốt – Không bị throttling"));
            Console.ResetColor();
            Console.WriteLine();
        }

        static void RunDiskBenchmarkTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("    🚀 ĐO TỐC ĐỘ ĐỌC/GHI Ổ CỨNG (SEQUENTIAL R/W BENCHMARK)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• Ghi & Đọc 128 MB dữ liệu ngẫu nhiên để đo tốc độ MB/s thực tế.");
            Console.WriteLine("• NVMe PCIe Gen4: 3000-7000 MB/s | Gen3: 1500-3500 MB/s");
            Console.WriteLine("• SSD SATA 3: 400-560 MB/s | HDD: 80-160 MB/s");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("👉 Nhấn Enter để BẮT ĐẦU đo tốc độ...");
            Console.ResetColor();
            Console.ReadLine();

            string testFile = Path.Combine(Path.GetTempPath(), "disk_bench_pitvn.tmp");
            int testSizeMb = 128;
            byte[] data = new byte[testSizeMb * 1024 * 1024];
            new Random().NextBytes(data);

            try
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("⏳ Đang ghi 128 MB...");
                Console.ResetColor();
                Stopwatch swWrite = Stopwatch.StartNew();
                File.WriteAllBytes(testFile, data);
                swWrite.Stop();
                double writeMbs = (testSizeMb) / swWrite.Elapsed.TotalSeconds;

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("⏳ Đang đọc 128 MB...");
                Console.ResetColor();
                Stopwatch swRead = Stopwatch.StartNew();
                byte[] readData = File.ReadAllBytes(testFile);
                swRead.Stop();
                double readMbs = (testSizeMb) / swRead.Elapsed.TotalSeconds;

                try { File.Delete(testFile); } catch { }

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("══════════════════════════════════════════════════════════════════");
                Console.ResetColor();
                Console.WriteLine(string.Format("  - Tốc độ GHI thực tế: {0:F1} MB/s", writeMbs));
                Console.WriteLine(string.Format("  - Tốc độ ĐỌC thực tế: {0:F1} MB/s", readMbs));
                Console.WriteLine();

                string driveType;
                if (readMbs > 3000) driveType = "✔ NVMe PCIe Gen4/5 (Cao cấp)";
                else if (readMbs > 1500) driveType = "✔ NVMe PCIe Gen3 (Tốt)";
                else if (readMbs > 400) driveType = "✔ SSD SATA 3 (Ổn định)";
                else if (readMbs > 200) driveType = "⚠ SSD SATA giá rẻ hoặc eMMC";
                else if (readMbs > 80)  driveType = "⚠ HDD cơ học – Khá chậm";
                else driveType = "🚨 Rất chậm – SSD kém chất lượng hoặc HDD cũ!";

                Console.ForegroundColor = readMbs > 400 ? ConsoleColor.Green : readMbs > 200 ? ConsoleColor.Yellow : ConsoleColor.Red;
                Console.WriteLine("  → Phân loại: " + driveType);
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("⚠ Lỗi khi đo tốc độ: " + ex.Message);
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        static void RunAudioStereoTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("    🔊 KIỂM TRA LOA TRÁI / PHẢI (STEREO CHANNEL ISOLATION)");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine("• Test phát riêng loa Trái (440 Hz) và Phải (880 Hz).");
            Console.WriteLine("• Loa Trái không phát được → Màng loa bên trái bị tịt/rè.");
            Console.WriteLine("• Loa Phải không phát được → Màng loa bên phải bị tịt/rè.");
            Console.WriteLine();

            Action<string, bool, bool, int, int> playSound = delegate(string label, bool left, bool right, int freqL, int freqR)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write(string.Format("  → Phát âm thanh: {0} (3 giây) – Lắng nghe kỹ... ", label));
                Console.ResetColor();
                try
                {
                    int sampleRate = 44100, duration = 3;
                    int numSamples = sampleRate * duration;
                    byte[] wavData = new byte[44 + numSamples * 4];
                    // WAV Header
                    Buffer.BlockCopy(Encoding.ASCII.GetBytes("RIFF"), 0, wavData, 0, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes(36 + numSamples * 4), 0, wavData, 4, 4);
                    Buffer.BlockCopy(Encoding.ASCII.GetBytes("WAVEfmt "), 0, wavData, 8, 8);
                    Buffer.BlockCopy(BitConverter.GetBytes(16), 0, wavData, 16, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes((short)1), 0, wavData, 20, 2);
                    Buffer.BlockCopy(BitConverter.GetBytes((short)2), 0, wavData, 22, 2);
                    Buffer.BlockCopy(BitConverter.GetBytes(sampleRate), 0, wavData, 24, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes(sampleRate * 4), 0, wavData, 28, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes((short)4), 0, wavData, 32, 2);
                    Buffer.BlockCopy(BitConverter.GetBytes((short)16), 0, wavData, 34, 2);
                    Buffer.BlockCopy(Encoding.ASCII.GetBytes("data"), 0, wavData, 36, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes(numSamples * 4), 0, wavData, 40, 4);
                    for (int s = 0; s < numSamples; s++)
                    {
                        short sL = left  ? (short)(short.MaxValue * 0.7 * Math.Sin(2 * Math.PI * freqL * s / sampleRate)) : (short)0;
                        short sR = right ? (short)(short.MaxValue * 0.7 * Math.Sin(2 * Math.PI * freqR * s / sampleRate)) : (short)0;
                        Buffer.BlockCopy(BitConverter.GetBytes(sL), 0, wavData, 44 + s * 4, 2);
                        Buffer.BlockCopy(BitConverter.GetBytes(sR), 0, wavData, 46 + s * 4, 2);
                    }
                    using (MemoryStream ms = new MemoryStream(wavData))
                    using (SoundPlayer sp = new SoundPlayer(ms)) { sp.PlaySync(); }
                }
                catch (Exception ex) { Console.WriteLine("⚠ Lỗi: " + ex.Message); return; }
                Console.WriteLine("Xong.");
            };

            playSound("LOA TRÁI (440 Hz)", true, false, 440, 440);
            Thread.Sleep(500);
            playSound("LOA PHẢI (880 Hz)", false, true, 880, 880);
            Thread.Sleep(500);
            playSound("CẢ HAI LOA (440+880 Hz)", true, true, 440, 880);

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✔ Đã hoàn tất test loa stereo!");
            Console.ResetColor();
        }

        static void RunBatteryChargeTest()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.WriteLine("    🔋 KIỂM TRA TỐC ĐỘ NẠP/XẢ PIN & NGUỒN SẠC");
            Console.WriteLine("══════════════════════════════════════════════════════════════════");
            Console.ResetColor();

            BatteryInfo bat = GetBattery();
            if (!bat.HasBattery) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine("⚠ Máy tính Desktop không có pin."); Console.ResetColor(); return; }

            Console.WriteLine(string.Format("• Dung lượng thiết kế gốc  : {0}", bat.DesignCapacity));
            Console.WriteLine(string.Format("• Dung lượng sạc đầy hiện  : {0}", bat.CurrentCapacity));
            Console.WriteLine(string.Format("• Tỷ lệ chai pin (Wear)    : {0}", bat.WearLevel));
            Console.WriteLine(string.Format("• Số chu kỳ sạc (Cycle)    : {0}", bat.CycleCount >= 0 ? bat.CycleCount.ToString("N0") : "N/A"));
            Console.WriteLine(string.Format("• Nguồn điện hiện tại      : {0}", SystemInformation.PowerStatus.PowerLineStatus == PowerLineStatus.Online ? "🔌 Đang cắm sạc (AC Online)" : "🔋 Đang dùng Pin"));
            Console.WriteLine(string.Format("• Mức pin hiện tại         : {0:P0}", SystemInformation.PowerStatus.BatteryLifePercent));
            Console.WriteLine();

            double wearVal = 0;
            if (bat.WearLevel != null && bat.WearLevel.Contains("%")) double.TryParse(bat.WearLevel.Replace("%", "").Trim(), out wearVal);

            if (wearVal < 20)      { Console.ForegroundColor = ConsoleColor.Green;  Console.WriteLine(string.Format("👉 [RẤT TỐT] Pin còn {0:F1}% dung lượng gốc. Tuyệt vời!", 100 - wearVal)); }
            else if (wearVal < 40) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine(string.Format("👉 [KHÁ] Pin chai {0} – Chấp nhận được, thời lượng có giảm.", bat.WearLevel)); }
            else if (wearVal < 60) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine(string.Format("👉 [TRUNG BÌNH] Pin chai {0} – Thời lượng giảm rõ rệt.", bat.WearLevel)); }
            else                   { Console.ForegroundColor = ConsoleColor.Red;    Console.WriteLine(string.Format("👉 [🚨 CHAI NẶNG] Pin đã chai {0}! Cần thay pin hoặc trừ tiền.", bat.WearLevel)); }
            Console.ResetColor();
            Console.WriteLine();
        }

        static void ShowSoftwareDownloaderMenu()
        {
            List<SoftwareItem> tools = new List<SoftwareItem>();
            tools.Add(new SoftwareItem("1", "FurMark 2 (GPU Stress Test – Thử tải card & nguồn)", "Ép card đồ họa 100% để kiểm tra nhiệt độ và ổn định nguồn.", "https://sourceforge.net/projects/furmark/files/latest/download", "FurMark_win64.zip", "FurMark", "*furmark*.exe", false, ""));
            tools.Add(new SoftwareItem("2", "CPUID HWMonitor (Soi nhiệt độ CPU/GPU, quạt, W)", "Đo nhiệt độ, công suất, xung nhịp theo thời gian thực.", "https://download.cpuid.com/hwmonitor/hwmonitor_1.56.zip", "hwmonitor_1.56.zip", "HWMonitor", "*hwmonitor*.exe", false, ""));
            tools.Add(new SoftwareItem("3", "CrystalDiskInfo (S.M.A.R.T chi tiết, Power-On Hours)", "Xem chi tiết sức khỏe SSD/HDD, số giờ hoạt động, bad sector.", "https://sourceforge.net/projects/crystaldiskinfo/files/latest/download", "CrystalDiskInfo.zip", "CrystalDiskInfo", "*diskinfo*.exe", false, ""));
            tools.Add(new SoftwareItem("4", "CPUID CPU-Z (Chi tiết CPU, RAM Dual Channel & Benchmark)", "Xem vi kiến trúc CPU, kênh RAM, tích hợp benchmark.", "https://download.cpuid.com/cpu-z/cpu-z_2.11-en.zip", "cpu-z_2.11-en.zip", "CPU-Z", "*cpuz*.exe", false, ""));
            tools.Add(new SoftwareItem("5", "Cinebench (Mở trang tải Cinebench chính thức Maxon)", "", "", "", "Cinebench", "", true, "https://www.maxon.net/en/cinebench"));

            while (true)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("╔═══════════════════════════════════════════════════════════════════════╗");
                Console.WriteLine("║    TRÌNH TẢI PHẦN MỀM CHUYÊN DỤNG (PORTABLE – KHÔNG CẦN CÀI ĐẶT)    ║");
                Console.WriteLine("╚═══════════════════════════════════════════════════════════════════════╝");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [1] 🔥 FurMark 2 (GPU Stress Test – ~28 MB)");
                Console.WriteLine("  [2] 🌡️  CPUID HWMonitor (Nhiệt độ CPU/GPU – ~2 MB)");
                Console.WriteLine("  [3] 💾 CrystalDiskInfo (S.M.A.R.T chi tiết – ~8 MB)");
                Console.WriteLine("  [4] ⚡ CPUID CPU-Z (Chi tiết CPU, RAM – ~3.5 MB)");
                Console.WriteLine("  [5] 🎬 Cinebench (Mở trang tải chính thức)");
                Console.WriteLine("  [6] 📦 TẢI TRỌN BỘ 3 CÔNG CỤ NHẸ (CPU-Z + HWMonitor + CrystalDiskInfo)");
                Console.WriteLine("  [0] ⬅️  Quay lại Menu chính");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("👉 Chọn [0-6]: ");
                Console.ResetColor();

                string tc = Console.ReadLine(); if (tc == null) break; tc = tc.Trim();
                if (tc == "0") break;
                if (tc == "1") DownloadAndExtract(tools[0]);
                else if (tc == "2") DownloadAndExtract(tools[1]);
                else if (tc == "3") DownloadAndExtract(tools[2]);
                else if (tc == "4") DownloadAndExtract(tools[3]);
                else if (tc == "5")
                {
                    Console.Write("👉 Mở trang tải Cinebench? [Y/N]: ");
                    string a = Console.ReadLine();
                    if (string.IsNullOrEmpty(a) || a.Trim().ToUpper() == "Y") try { Process.Start("https://www.maxon.net/en/cinebench"); Console.WriteLine("✔ Đã mở trình duyệt!"); } catch (Exception ex) { Console.WriteLine("⚠ " + ex.Message); }
                }
                else if (tc == "6")
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("\n🚀 ĐANG TẢI TRỌN BỘ 3 CÔNG CỤ (CPU-Z + HWMONITOR + CRYSTALDISKINFO)...");
                    Console.ResetColor();
                    DownloadAndExtract(tools[3]); DownloadAndExtract(tools[1]); DownloadAndExtract(tools[2]);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n🎉 ĐÃ TẢI XONG TRỌN BỘ!");
                    Console.ResetColor();
                }
                else { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("⚠ Lựa chọn không hợp lệ."); Console.ResetColor(); }
            }
        }

        static void DownloadAndExtract(SoftwareItem item)
        {
            if (item.IsExternalOnly) return;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══  TẢI VỀ: " + item.Name + "  ══");
            Console.ResetColor();
            Console.WriteLine("• " + item.Description);

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string toolsDir = Path.Combine(baseDir, "Tools_Test");
            try { if (!Directory.Exists(toolsDir)) Directory.CreateDirectory(toolsDir); }
            catch { toolsDir = Path.Combine(Path.GetTempPath(), "Tools_Test_PITVN"); if (!Directory.Exists(toolsDir)) Directory.CreateDirectory(toolsDir); }

            string targetFolder = Path.Combine(toolsDir, item.FolderName);
            if (Directory.Exists(targetFolder))
            {
                string[] exes = Directory.GetFiles(targetFolder, item.ExeSearchPattern, SearchOption.AllDirectories);
                if (exes.Length > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine("✔ Đã có sẵn: " + exes[0]); Console.ResetColor();
                    Console.Write("👉 Khởi chạy ngay? [Y/N] (Mặc định Y): ");
                    string ans = Console.ReadLine();
                    if (string.IsNullOrEmpty(ans) || ans.Trim().ToUpper() == "Y") try { Process.Start(exes[0]); } catch { }
                    return;
                }
            }

            string zipPath = Path.Combine(toolsDir, item.FileName);
            Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine("⏳ Đang tải..."); Console.ResetColor();
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(item.DownloadUrl);
                req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";
                req.Timeout = 60000; req.AllowAutoRedirect = true;
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                using (Stream stream = resp.GetResponseStream())
                using (FileStream fs = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    long total = resp.ContentLength; byte[] buf = new byte[65536]; long read = 0; int r; Stopwatch sw = Stopwatch.StartNew(); long lastUp = 0;
                    while ((r = stream.Read(buf, 0, buf.Length)) > 0)
                    {
                        fs.Write(buf, 0, r); read += r;
                        if (sw.ElapsedMilliseconds - lastUp > 200 || (total > 0 && read >= total))
                        {
                            lastUp = sw.ElapsedMilliseconds;
                            double spd = sw.ElapsedMilliseconds > 0 ? (read / 1048576.0) / (sw.ElapsedMilliseconds / 1000.0) : 0;
                            if (total > 0) { double pct = (double)read / total * 100; int bar = (int)(pct / 100.0 * 25); Console.Write(string.Format("\r   [{0}{1}] {2,5:F1}% ({3:F1}/{4:F1} MB) @ {5:F2} MB/s", new string('█', bar), new string('░', 25 - bar), pct, read / 1048576.0, total / 1048576.0, spd)); }
                            else Console.Write(string.Format("\r   Đã tải: {0:F1} MB @ {1:F2} MB/s", read / 1048576.0, spd));
                        }
                    }
                    Console.WriteLine();
                }
                Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine("⏳ Đang giải nén..."); Console.ResetColor();
                if (!Directory.Exists(targetFolder)) Directory.CreateDirectory(targetFolder);
                ZipFile.ExtractToDirectory(zipPath, targetFolder);
                try { File.Delete(zipPath); } catch { }
                string[] found = Directory.GetFiles(targetFolder, item.ExeSearchPattern, SearchOption.AllDirectories);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("✔ Đã tải và giải nén thành công" + (found.Length > 0 ? ": " + found[0] : ""));
                Console.ResetColor();
                if (found.Length > 0) { Console.Write("👉 Khởi chạy ngay? [Y/N]: "); string ans = Console.ReadLine(); if (string.IsNullOrEmpty(ans) || ans.Trim().ToUpper() == "Y") try { Process.Start(found[0]); } catch { } }
            }
            catch (Exception ex) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("⚠ Tải thất bại: " + ex.Message); Console.ResetColor(); }
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
                        if (obj["Name"] != null) info.Name = obj["Name"].ToString().Trim();
                        if (obj["NumberOfCores"] != null) info.Cores = obj["NumberOfCores"].ToString().Trim();
                        if (obj["NumberOfLogicalProcessors"] != null) info.LogicalProcessors = obj["NumberOfLogicalProcessors"].ToString().Trim();
                        if (obj["MaxClockSpeed"] != null) info.ClockSpeed = obj["MaxClockSpeed"].ToString().Trim();
                        break;
                    }
                }
            }
            catch { }

            // 1. CPUID brand string (từ silicon)
            info.HardwareBrand = GetHardwareCpuBrand();

            // 2. Registry name
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0"))
                {
                    if (key != null) { object val = key.GetValue("ProcessorNameString"); if (val != null) info.RegistryName = val.ToString().Trim(); }
                }
            }
            catch { }

            // 3. Phát hiện giả mạo Registry
            if (info.HardwareBrand != "Unknown" && !string.IsNullOrEmpty(info.HardwareBrand))
            {
                string normHw = NormalizeString(info.HardwareBrand);
                string normWin = NormalizeString(info.Name);
                string normReg = NormalizeString(info.RegistryName);
                if (!string.IsNullOrEmpty(normReg) && !normHw.Contains(normReg) && !normReg.Contains(normHw))
                    info.IsSpoofed = true;
                else if (!normHw.Contains(normWin) && !normWin.Contains(normHw))
                    info.IsSpoofed = true;
            }

            // 4. NEW: Đọc Family/Model/Stepping
            GetCpuFamilyModelStepping(out info.CpuFamily, out info.CpuModel, out info.CpuStepping);
            if (info.CpuFamily > 0)
            {
                string cpuNote;
                info.CpuGeneration = DecodeCpuGeneration(info.CpuFamily, info.CpuModel, info.HardwareBrand, out cpuNote);
                info.CpuGenerationNote = cpuNote;
                // 5. NEW: Kiểm tra mismatch thế hệ
                info.GenerationMismatch = CheckCpuGenerationMismatch(info.Name, info.CpuGeneration);
                if (!string.IsNullOrEmpty(info.GenerationMismatch)) info.IsSpoofed = true;
            }

            // 6. Benchmark
            info.BenchmarkScore = RunCpuBenchmark(500);
            return info;
        }

        static string NormalizeString(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            StringBuilder sb = new StringBuilder();
            foreach (char c in s.ToUpper()) { if (char.IsLetterOrDigit(c)) sb.Append(c); }
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
                        string vram = "N/A"; string vramActual = "N/A"; long vramBytes = 0;

                        if (obj["AdapterRAM"] != null)
                        {
                            vramBytes = Convert.ToInt64(obj["AdapterRAM"]);
                            if (vramBytes > 0) { long gb = (vramBytes + 1073741823L) / 1073741824L; vram = gb + " GB"; vramActual = gb + " GB"; }
                        }
                        if (vram == "N/A")
                        {
                            string regV = GetVramFromRegistry(name);
                            if (!string.IsNullOrEmpty(regV) && regV != "N/A") { vram = regV; vramActual = regV; }
                        }

                        string type = "Integrated";
                        string upper = name.ToUpper();
                        if (upper.Contains("NVIDIA") || upper.Contains("GEFORCE") || upper.Contains("RTX") || upper.Contains("GTX") ||
                            upper.Contains("RADEON RX") || upper.Contains("INTEL ARC") || upper.Contains("RX 4") || upper.Contains("RX 5") || upper.Contains("RX 6") || upper.Contains("RX 7"))
                            type = "Discrete";

                        GpuDevice gpu = new GpuDevice();
                        gpu.Name = name; gpu.Type = type; gpu.Vram = vram; gpu.VramActual = vramActual;
                        gpu.Tdp = EstimateGpuTdp(name);
                        gpu.PnpDeviceId = obj["PNPDeviceID"] != null ? obj["PNPDeviceID"].ToString() : "";

                        ParsePciHardwareId(gpu);

                        // NEW: Kiểm tra VRAM mismatch
                        CheckVramNameMismatch(gpu);

                        VerifyGpuAuthenticity(gpu);
                        list.Add(gpu);
                    }
                }
            }
            catch { }

            if (list.Count == 0)
            {
                GpuDevice def = new GpuDevice();
                def.Name = "Unknown GPU"; def.Type = "Integrated"; def.VerificationNote = "Không xác định";
                list.Add(def);
            }
            return list;
        }

        static void CheckVramNameMismatch(GpuDevice gpu)
        {
            // Kiểm tra tên ngụ ý VRAM cao hơn thực tế
            string nameUpper = gpu.Name.ToUpper();
            string actualVram = gpu.VramActual;
            if (actualVram == "N/A") return;

            int actualGb = 0;
            try { actualGb = int.Parse(actualVram.Replace("GB", "").Trim()); } catch { return; }

            // GTX 1060 6GB nhưng chỉ có 3GB
            if ((nameUpper.Contains("1060") || nameUpper.Contains("1070") || nameUpper.Contains("1080")) && nameUpper.Contains("6GB") && actualGb < 5) { gpu.IsVramMismatch = true; }
            if (nameUpper.Contains("6GB") && actualGb <= 3) { gpu.IsVramMismatch = true; }
            if (nameUpper.Contains("8GB") && actualGb <= 4) { gpu.IsVramMismatch = true; }
            if (nameUpper.Contains("12GB") && actualGb <= 6) { gpu.IsVramMismatch = true; }
            if (nameUpper.Contains("16GB") && actualGb <= 8) { gpu.IsVramMismatch = true; }
            if (nameUpper.Contains("24GB") && actualGb <= 12) { gpu.IsVramMismatch = true; }
        }

        static void ParsePciHardwareId(GpuDevice gpu)
        {
            if (string.IsNullOrEmpty(gpu.PnpDeviceId)) return;
            string u = gpu.PnpDeviceId.ToUpper();
            int venIdx = u.IndexOf("VEN_"); if (venIdx != -1 && venIdx + 8 <= u.Length) gpu.VendorId = u.Substring(venIdx + 4, 4);
            int devIdx = u.IndexOf("DEV_"); if (devIdx != -1 && devIdx + 8 <= u.Length) gpu.DeviceId = u.Substring(devIdx + 4, 4);
            int subIdx = u.IndexOf("SUBSYS_");
            if (subIdx != -1 && subIdx + 15 <= u.Length)
            {
                string subsysFull = u.Substring(subIdx + 7, 8);
                string sv = subsysFull.Substring(4, 4);
                if (sv == "1043") gpu.SubsystemVendor = "ASUS";
                else if (sv == "1462") gpu.SubsystemVendor = "MSI";
                else if (sv == "1458") gpu.SubsystemVendor = "GIGABYTE";
                else if (sv == "3842") gpu.SubsystemVendor = "EVGA";
                else if (sv == "19DA") gpu.SubsystemVendor = "ZOTAC";
                else if (sv == "10DE") gpu.SubsystemVendor = "NVIDIA Standard / Colorful";
                else if (sv == "1028") gpu.SubsystemVendor = "Dell";
                else if (sv == "103C") gpu.SubsystemVendor = "HP";
                else if (sv == "17AA") gpu.SubsystemVendor = "Lenovo";
                else if (sv == "1558") gpu.SubsystemVendor = "Clevo";
                else if (sv == "196E") gpu.SubsystemVendor = "Point of View";
                else if (sv == "1B4C") gpu.SubsystemVendor = "Galax / KFA2";
                else if (sv == "3842") gpu.SubsystemVendor = "EVGA";
                else if (sv == "0000") gpu.SubsystemVendor = "Unknown / Nghi vấn VBIOS flash (SUBSYS=0000)";
                else if (sv == "FFFF") gpu.SubsystemVendor = "Unknown / Nghi vấn VBIOS flash (SUBSYS=FFFF)";
                else gpu.SubsystemVendor = "OEM (" + sv + ")";
            }
        }

        static void VerifyGpuAuthenticity(GpuDevice gpu)
        {
            string nameUpper = gpu.Name.ToUpper();
            string dev = gpu.DeviceId.ToUpper();

            // ── NVIDIA Fermi cổ (GTS 450 / GTX 550 Ti) bị flash thành chip mới ──
            HashSet<string> fermiChips = new HashSet<string> { "0DC4", "0DC5", "0DC6", "0DD8", "1244", "1245", "0DE0", "0DE1", "0DE2", "0DE3", "0DF0", "0DF1", "0DF2", "0DF3" };
            if (fermiChips.Contains(dev))
            {
                if (nameUpper.Contains("1050") || nameUpper.Contains("1060") || nameUpper.Contains("1070") || nameUpper.Contains("960") || nameUpper.Contains("970") || nameUpper.Contains("RTX"))
                { gpu.IsFakeSuspected = true; gpu.VerificationNote = "Phát hiện giả mạo! Tên hiển thị là '" + gpu.Name + "' nhưng chip thực là Fermi đời cổ (GTS 450/550Ti)."; return; }
            }

            // ── NVIDIA Kepler cổ (GT 630/640/730) bị flash ──
            HashSet<string> keplerOld = new HashSet<string> { "0FC1", "0FC2", "0FC6", "0FE1", "1287", "1288", "1290", "1291", "1292", "1293", "0F00", "0F01", "1184", "1185", "1187", "1188" };
            if (keplerOld.Contains(dev))
            {
                if (nameUpper.Contains("1050") || nameUpper.Contains("1060") || nameUpper.Contains("1070") || nameUpper.Contains("RTX") || nameUpper.Contains("GTX 16"))
                { gpu.IsFakeSuspected = true; gpu.VerificationNote = "Phát hiện giả mạo! Tên là '" + gpu.Name + "' nhưng chip thực là GT 630/640/730 (Kepler đời cũ)."; return; }
            }

            // ── GTX 750 Ti chip (Maxwell, thường bị flash thành GTX 1060) ──
            HashSet<string> maxwell750 = new HashSet<string> { "1380", "1381", "1382", "1390", "1391", "1392", "13B0", "13B1", "13B2", "13BA" };
            if (maxwell750.Contains(dev))
            {
                if (nameUpper.Contains("1060") || nameUpper.Contains("1070") || nameUpper.Contains("1080") || nameUpper.Contains("RTX"))
                { gpu.IsFakeSuspected = true; gpu.VerificationNote = "Phát hiện giả mạo! Tên là '" + gpu.Name + "' nhưng mã chip là GTX 750/750Ti (Maxwell 2014)."; return; }
            }

            // ── GTX 960/970/980 chip (Maxwell, bị flash thành GTX 1060/1070) ──
            HashSet<string> maxwell900 = new HashSet<string> { "1401", "1407", "1408", "13C0", "13C2", "13D7", "13D8", "13D9", "17C2", "17C8", "1617", "1618" };
            if (maxwell900.Contains(dev))
            {
                if (nameUpper.Contains("1070") || nameUpper.Contains("1080") || nameUpper.Contains("RTX 20") || nameUpper.Contains("RTX 30"))
                { gpu.IsFakeSuspected = true; gpu.VerificationNote = "Phát hiện giả mạo! Tên là '" + gpu.Name + "' nhưng mã chip là GTX 960/970/980 (Maxwell)."; return; }
            }

            // ── GT 1030 GDDR4 giả GDDR5 ──
            if (dev == "1D01" && nameUpper.Contains("1030"))
            {
                // Có thể phát hiện qua tên nếu chứa "GDDR5" nhưng thực tế là GDDR4
                // Không thể detect chính xác qua WMI, nhưng note lại
                gpu.VerificationNote = "GT 1030 – LƯU Ý: Có 2 phiên bản GDDR4 (chậm hơn 50%) và GDDR5. Kiểm tra tên sản phẩm trên vỏ hộp!";
            }

            // ── AMD RX 470/480 bị flash thành RX 580 ──
            HashSet<string> polaris470 = new HashSet<string> { "67DF", "687F", "67FF", "6FDF" };
            if (polaris470.Contains(dev))
            {
                // RX 470 chip nhưng tên hiển thị RX 580
                if (nameUpper.Contains("RX 580") && !nameUpper.Contains("RX 470") && !nameUpper.Contains("RX 480"))
                { gpu.IsFakeSuspected = true; gpu.VerificationNote = "Nghi vấn! Mã chip VEN_1002 DEV_" + dev + " thường là RX 470/480, nhưng tên hiển thị là RX 580 – có thể flash VBIOS."; return; }
            }

            // ── AMD RX 550 / RX 560 cũ bị flash ──
            HashSet<string> polaris11 = new HashSet<string> { "699F", "67EF", "67FF" };
            if (polaris11.Contains(dev))
            {
                if (nameUpper.Contains("RX 580") || nameUpper.Contains("RX 590"))
                { gpu.IsFakeSuspected = true; gpu.VerificationNote = "Phát hiện nghi vấn! DEV_" + dev + " là RX 550/560 nhưng tên hiển thị là RX 580/590."; return; }
            }

            // ── Kiểm tra Vendor ID hợp lệ ──
            if (gpu.VendorId == "10DE")      // NVIDIA
            {
                if (!nameUpper.Contains("NVIDIA") && !nameUpper.Contains("GEFORCE") && !nameUpper.Contains("QUADRO") && !nameUpper.Contains("TESLA") && !nameUpper.Contains("NVS"))
                { gpu.IsFakeSuspected = true; gpu.VerificationNote = "Mã Vendor ID là NVIDIA (10DE) nhưng tên hiển thị không phải NVIDIA!"; return; }
                gpu.VerificationNote = "Xác thực chip NVIDIA hợp lệ – Khớp Vendor ID và tên hiển thị.";
            }
            else if (gpu.VendorId == "8086") // Intel
            {
                gpu.VerificationNote = "Xác thực chip đồ họa Intel tích hợp hợp lệ (Genuine Intel Graphics).";
            }
            else if (gpu.VendorId == "1002") // AMD
            {
                if (!nameUpper.Contains("AMD") && !nameUpper.Contains("RADEON") && !nameUpper.Contains("FIREPRO") && !nameUpper.Contains("VEGA") && !nameUpper.Contains("RX") && !nameUpper.Contains("R9") && !nameUpper.Contains("R7"))
                { gpu.IsFakeSuspected = true; gpu.VerificationNote = "Mã Vendor ID là AMD (1002) nhưng tên hiển thị không phải AMD/Radeon!"; return; }
                gpu.VerificationNote = "Xác thực chip AMD Radeon hợp lệ.";
            }
            else
            {
                gpu.VerificationNote = "Đã nhận diện phần cứng qua bus PCI.";
            }

            // Cảnh báo SUBSYS = 0000 hoặc FFFF
            if (gpu.SubsystemVendor != null && (gpu.SubsystemVendor.Contains("0000") || gpu.SubsystemVendor.Contains("FFFF")))
            {
                gpu.IsFakeSuspected = true;
                gpu.VerificationNote += " + CẢNH BÁO: SUBSYS ID = 0000/FFFF – Dấu hiệu flash VBIOS!";
            }

            // VRAM mismatch đã kiểm tra, nhưng update note
            if (gpu.IsVramMismatch)
                gpu.VerificationNote += string.Format(" + CẢNH BÁO: VRAM tên hiển thị không khớp VRAM thực ({0})!", gpu.VramActual);
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
                        string model = obj["Model"] != null ? obj["Model"].ToString().Trim() : "Unknown";
                        long size = obj["Size"] != null ? Convert.ToInt64(obj["Size"]) : 0;
                        string mediaType = "SSD"; string busType = "SATA";
                        if (obj["MediaType"] != null) { string mt = obj["MediaType"].ToString(); if (mt == "3") mediaType = "HDD"; }
                        if (obj["BusType"] != null) { string bt = obj["BusType"].ToString(); if (bt == "17") busType = "NVMe"; else if (bt == "7") busType = "USB"; else if (bt == "3") busType = "SATA"; }
                        string health = "Tốt (Healthy)";
                        if (obj["HealthStatus"] != null) { int hs = Convert.ToInt32(obj["HealthStatus"]); if (hs == 1) health = "Cảnh báo (Warning – Nên sao lưu dữ liệu)"; else if (hs == 2) health = "Nguy hiểm (Unhealthy – Có thể hỏng!)"; }

                        DriveInfoItem item = new DriveInfoItem();
                        item.Model = model; item.Size = (size / (1024 * 1024 * 1024)) + " GB"; item.MediaType = mediaType; item.BusType = busType; item.HealthStatus = health;

                        // NEW: Đọc S.M.A.R.T chi tiết
                        FillSmartDetails(item, obj);
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
                            string model = obj["Model"] != null ? obj["Model"].ToString().Trim() : "Unknown";
                            long size = obj["Size"] != null ? Convert.ToInt64(obj["Size"]) : 0;
                            string mt = obj["MediaType"] != null ? obj["MediaType"].ToString().ToUpper() : "";
                            DriveInfoItem item = new DriveInfoItem();
                            item.Model = model; item.Size = (size / (1024 * 1024 * 1024)) + " GB";
                            item.MediaType = mt.Contains("HDD") ? "HDD" : "SSD"; item.BusType = "SATA"; item.HealthStatus = "Tốt (S.M.A.R.T. OK)";
                            list.Add(item);
                        }
                    }
                }
                catch { }
            }

            if (list.Count == 0) { DriveInfoItem def = new DriveInfoItem(); def.Model = "Unknown"; def.Size = "N/A"; def.HealthStatus = "N/A"; list.Add(def); }

            // NEW: Thử đọc SMART chi tiết từ MSFT_StorageReliabilityCounter
            TryFillSmartFromReliabilityCounter(list);
            return list;
        }

        static void FillSmartDetails(DriveInfoItem item, ManagementObject obj)
        {
            try
            {
                if (obj["Size"] != null) { /* size already handled */ }
                // Try to get wear from MSFT_PhysicalDisk
                // MediaType 4 = SSD, check usage
            }
            catch { }
        }

        static void TryFillSmartFromReliabilityCounter(List<DriveInfoItem> drives)
        {
            try
            {
                ManagementScope scope = new ManagementScope(@"Root\Microsoft\Windows\Storage");
                scope.Connect();
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSFT_StorageReliabilityCounter")))
                {
                    List<ManagementObject> objs = new List<ManagementObject>();
                    foreach (ManagementObject obj in searcher.Get()) objs.Add(obj);

                    for (int i = 0; i < Math.Min(drives.Count, objs.Count); i++)
                    {
                        ManagementObject obj = objs[i];
                        DriveInfoItem d = drives[i];
                        try
                        {
                            if (obj["PowerOnHours"] != null)
                            {
                                long poh = Convert.ToInt64(obj["PowerOnHours"]);
                                if (poh > 0) d.PowerOnHours = (int)poh;
                            }
                        }
                        catch { }
                        try
                        {
                            if (obj["Temperature"] != null)
                            {
                                double t = Convert.ToDouble(obj["Temperature"]);
                                if (t > 0 && t < 200) d.TemperatureCelsius = t;
                            }
                        }
                        catch { }
                        try
                        {
                            if (obj["Wear"] != null)
                            {
                                int wear = Convert.ToInt32(obj["Wear"]);
                                if (wear >= 0 && wear <= 100) d.WearPercent = wear;
                            }
                        }
                        catch { }
                        try
                        {
                            if (obj["ReadErrorsTotal"] != null)
                            {
                                long re = Convert.ToInt64(obj["ReadErrorsTotal"]);
                                if (re >= 0) d.ReallocatedSectors = (int)Math.Min(re, int.MaxValue);
                            }
                        }
                        catch { }
                        try
                        {
                            if (obj["WriteErrorsTotal"] != null)
                            {
                                long we = Convert.ToInt64(obj["WriteErrorsTotal"]);
                                if (we >= 0) d.UncorrectableErrors = (int)Math.Min(we, int.MaxValue);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        // NEW: Đọc EDID Monitor thông tin từ Registry
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
                            info.Resolution = obj["CurrentHorizontalResolution"].ToString() + " x " + obj["CurrentVerticalResolution"].ToString();
                        if (obj["CurrentRefreshRate"] != null)
                            info.RefreshRate = obj["CurrentRefreshRate"].ToString();
                        if (!string.IsNullOrEmpty(info.Resolution) && info.Resolution != "Unknown") break;
                    }
                }
            }
            catch { }

            // NEW: Đọc EDID từ Registry
            try
            {
                using (RegistryKey displayKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\DISPLAY"))
                {
                    if (displayKey != null)
                    {
                        foreach (string monitorId in displayKey.GetSubKeyNames())
                        {
                            using (RegistryKey monKey = displayKey.OpenSubKey(monitorId))
                            {
                                if (monKey == null) continue;
                                foreach (string instanceId in monKey.GetSubKeyNames())
                                {
                                    using (RegistryKey instKey = monKey.OpenSubKey(instanceId + @"\Device Parameters"))
                                    {
                                        if (instKey == null) continue;
                                        object edidObj = instKey.GetValue("EDID");
                                        if (edidObj is byte[])
                                        {
                                            byte[] edid = (byte[])edidObj;
                                            if (edid.Length >= 20)
                                            {
                                                // Manufacturer ID: bytes 8-9 (3 letters encoded)
                                                if (edid[0] == 0x00 && edid[1] == 0xFF && edid[2] == 0xFF) // Valid EDID header
                                                {
                                                    int mfgRaw = (edid[8] << 8) | edid[9];
                                                    char c1 = (char)(((mfgRaw >> 10) & 0x1F) + 'A' - 1);
                                                    char c2 = (char)(((mfgRaw >> 5) & 0x1F) + 'A' - 1);
                                                    char c3 = (char)(((mfgRaw) & 0x1F) + 'A' - 1);
                                                    string mfgCode = "" + c1 + c2 + c3;
                                                    int prodCode = (edid[11] << 8) | edid[10];
                                                    info.EdidManufacturer = DecodeEdidManufacturer(mfgCode);
                                                    info.EdidProductCode = mfgCode + string.Format("{0:X4}", prodCode);
                                                    info.PanelInfo = string.Format("{0} (Mã nhà sản xuất: {1}, Mã sản phẩm: {2:X4})", info.EdidManufacturer, mfgCode, prodCode);
                                                    goto edidDone;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            edidDone:
            return info;
        }

        static string DecodeEdidManufacturer(string code)
        {
            switch (code.ToUpper())
            {
                case "AUO": return "AU Optronics (AUO)";
                case "BOE": return "BOE Technology Group";
                case "CMN": return "Innolux / Chi Mei (CMN)";
                case "LGD": return "LG Display (LGD)";
                case "SDC": return "Samsung Display (SDC)";
                case "SHP": return "Sharp (SHP)";
                case "CPT": return "Chunghwa Picture Tubes (CPT)";
                case "HSD": return "HannStar Display";
                case "SEC": return "Samsung Electronics";
                case "IVO": return "InfoVision Optoelectronics (IVO)";
                case "CSO": return "China Star Optoelectronics (CSO)";
                case "NCP": return "New Channel Panel (NCP)";
                case "TMX": return "Tianma (TMX)";
                case "PNR": return "Pioneer (PNR)";
                case "HWP": return "Hewlett-Packard (HP)";
                case "DEL": return "Dell";
                case "ACR": return "Acer";
                case "SAM": return "Samsung";
                case "LEN": return "Lenovo";
                case "APP": return "Apple";
                case "ASU": return "ASUS";
                case "MSI": return "MSI";
                case "AVO": return "Envision / AVOCENT";
                case "VIZ": return "Vizio";
                case "BNQ": return "BenQ";
                case "GSM": return "Goldstar (LG Electronics)";
                case "PHL": return "Philips";
                case "AOC": return "AOC";
                case "VSC": return "ViewSonic";
                case "TAA": return "Orion Electric";
                default: return "Panel Manufacturer: " + code;
            }
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
                        if (obj["Capacity"] != null) { cap = Convert.ToInt64(obj["Capacity"]); totalBytes += cap; slotSumBytes += cap; }
                        int speed = 0;
                        if (obj["Speed"] != null) { speed = Convert.ToInt32(obj["Speed"]); if (speed > dominantSpeed) dominantSpeed = speed; }
                        string mfgRaw = obj["Manufacturer"] != null ? obj["Manufacturer"].ToString() : "";
                        string mfgDecoded = DecodeRamManufacturer(mfgRaw);
                        if (!string.IsNullOrEmpty(mfgDecoded) && mfgDecoded != "Unknown") mfgSet.Add(mfgDecoded);
                        string bank = obj["DeviceLocator"] != null ? obj["DeviceLocator"].ToString() : "Slot";
                        RamSlotInfo slot = new RamSlotInfo();
                        slot.Bank = bank; slot.Capacity = (cap / (1024 * 1024 * 1024)).ToString();
                        slot.Speed = speed > 0 ? speed.ToString() : "N/A"; slot.Manufacturer = mfgDecoded;
                        info.Slots.Add(slot);
                        if (obj["SMBIOSMemoryType"] != null) { try { smbiosType = Convert.ToInt32(obj["SMBIOSMemoryType"]); } catch { } }
                    }
                }

                info.ActiveSlots = info.Slots.Count;
                info.Total = Math.Round((double)totalBytes / (1024.0 * 1024.0 * 1024.0)).ToString();
                info.Speed = dominantSpeed > 0 ? dominantSpeed.ToString() : "N/A";
                info.Manufacturer = mfgSet.Count > 0 ? string.Join(", ", new List<string>(mfgSet).ToArray()) : "Generic";
                if (slotSumBytes > 0 && Math.Abs(slotSumBytes - totalBytes) > 1024 * 1024 * 1024) info.IsConsistent = false;

                // NEW: Dual Channel detection – 2 hoặc 4 khe đều có RAM, dung lượng bằng nhau
                if (info.ActiveSlots >= 2)
                {
                    info.IsDualChannel = (info.ActiveSlots % 2 == 0); // Heuristic: số khe chẵn thường là dual channel
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
                        if (obj["MaxCapacity"] != null) { long maxKb = Convert.ToInt64(obj["MaxCapacity"]); info.MaxCapacity = (maxKb / (1024 * 1024)).ToString(); }
                        if (obj["MemoryDevices"] != null) info.MaxSlots = Convert.ToInt32(obj["MemoryDevices"]);
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
            if (upper.Contains("859B") || upper.Contains("CRUCIAL") || upper.Contains("9B85") || upper.Contains("MICRON")) return "Crucial / Micron";
            if (upper.Contains("059B") || upper.Contains("9B05")) return "Crucial";
            if (upper.Contains("830B") || upper.Contains("NANYA") || upper.Contains("0B83")) return "Nanya";
            if (upper.Contains("85F7") || upper.Contains("G.SKILL") || upper.Contains("F785") || upper.Contains("04CD") || upper.Contains("CD04")) return "G.Skill";
            if (upper.Contains("1315") || upper.Contains("GLOWAY")) return "Gloway";
            if (upper.Contains("TEAMGROUP") || upper.Contains("TEAM")) return "TeamGroup";
            if (upper.Contains("PATRIOT")) return "Patriot";
            if (upper.Contains("GSKILL")) return "G.Skill";
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
                            object qwMem = sub.GetValue("HardwareInformation.qwMemorySize");
                            if (qwMem != null) { long bytes = Convert.ToInt64(qwMem); if (bytes > 0) return ((bytes + 1073741823L) / 1073741824L) + " GB"; }
                            object mem = sub.GetValue("HardwareInformation.MemorySize");
                            if (mem != null) { long bytes = Convert.ToInt64(mem); if (bytes > 0) return ((bytes + 1073741823L) / 1073741824L) + " GB"; }
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
            if (u.Contains("RTX 4070 TI")) return "285W";
            if (u.Contains("RTX 4070 SUPER")) return "220W";
            if (u.Contains("RTX 4070")) return "200W";
            if (u.Contains("RTX 4060 TI")) return "165W";
            if (u.Contains("RTX 4060")) return "115W";
            if (u.Contains("RTX 4050")) return "75W-95W";
            if (u.Contains("RTX 3090")) return "350W";
            if (u.Contains("RTX 3080 TI")) return "350W";
            if (u.Contains("RTX 3080")) return "320W";
            if (u.Contains("RTX 3070 TI")) return "290W";
            if (u.Contains("RTX 3070")) return "220W";
            if (u.Contains("RTX 3060 TI")) return "200W";
            if (u.Contains("RTX 3060")) return "170W";
            if (u.Contains("RTX 3050")) return "75W-130W";
            if (u.Contains("RTX 2080 TI")) return "250W";
            if (u.Contains("RTX 2080")) return "215W";
            if (u.Contains("RTX 2070")) return "175W";
            if (u.Contains("RTX 2060")) return "160W";
            if (u.Contains("GTX 1080 TI")) return "250W";
            if (u.Contains("GTX 1080")) return "180W";
            if (u.Contains("GTX 1070 TI")) return "180W";
            if (u.Contains("GTX 1070")) return "150W";
            if (u.Contains("GTX 1660 TI") || u.Contains("GTX 1660 SUPER")) return "120W";
            if (u.Contains("GTX 1660")) return "120W";
            if (u.Contains("GTX 1650 SUPER")) return "100W";
            if (u.Contains("GTX 1650")) return "50W-75W";
            if (u.Contains("GTX 1060")) return "120W";
            if (u.Contains("GTX 1050 TI")) return "75W";
            if (u.Contains("GTX 1050")) return "75W";
            if (u.Contains("GTX 960")) return "120W";
            if (u.Contains("GTX 970")) return "145W";
            if (u.Contains("GTX 980")) return "165W";
            if (u.Contains("GTX 750 TI")) return "60W";
            if (u.Contains("RADEON RX 7900 XTX")) return "355W";
            if (u.Contains("RADEON RX 7900 XT")) return "315W";
            if (u.Contains("RADEON RX 7800 XT")) return "263W";
            if (u.Contains("RADEON RX 7700 XT")) return "245W";
            if (u.Contains("RADEON RX 7600")) return "165W";
            if (u.Contains("RADEON RX 6950 XT")) return "335W";
            if (u.Contains("RADEON RX 6900")) return "300W";
            if (u.Contains("RADEON RX 6800 XT")) return "300W";
            if (u.Contains("RADEON RX 6800")) return "250W";
            if (u.Contains("RADEON RX 6750")) return "250W";
            if (u.Contains("RADEON RX 6700 XT")) return "230W";
            if (u.Contains("RADEON RX 6700")) return "175W";
            if (u.Contains("RADEON RX 6650")) return "180W";
            if (u.Contains("RADEON RX 6600 XT")) return "160W";
            if (u.Contains("RADEON RX 6600")) return "132W";
            if (u.Contains("RADEON RX 6500")) return "107W";
            if (u.Contains("RADEON RX 5700 XT")) return "225W";
            if (u.Contains("RADEON RX 5700")) return "180W";
            if (u.Contains("RADEON RX 5600")) return "150W";
            if (u.Contains("RADEON RX 590")) return "225W";
            if (u.Contains("RADEON RX 580")) return "185W";
            if (u.Contains("RADEON RX 570")) return "150W";
            if (u.Contains("RADEON RX 480")) return "150W";
            if (u.Contains("RADEON RX 470")) return "120W";
            if (u.Contains("INTEL ARC A770")) return "225W";
            if (u.Contains("INTEL ARC A750")) return "225W";
            if (u.Contains("INTEL ARC A580")) return "185W";
            if (u.Contains("INTEL ARC A380")) return "75W";
            if (u.Contains("INTEL ARC A310")) return "30W";
            if (u.Contains("INTEL IRIS XE")) return "10W-28W";
            if (u.Contains("INTEL UHD 770")) return "15W-25W";
            if (u.Contains("INTEL UHD")) return "6W-25W";
            if (u.Contains("INTEL HD")) return "6W-20W";
            if (u.Contains("NVIDIA MX")) return "10W-50W";
            if (u.Contains("NVIDIA QUADRO")) return "25W-250W";
            if (u.Contains("NVIDIA TESLA")) return "70W-350W";
            if (u.Contains("AMD RADEON PRO")) return "25W-300W";
            if (u.Contains("AMD VEGA")) return "150W-300W";
            return "15W-75W (Ước lượng)";
        }

        static BatteryInfo GetBattery()
        {
            BatteryInfo info = new BatteryInfo();
            long designCap = 0, fullCap = 0;
            try
            {
                ManagementScope scope = new ManagementScope(@"Root\WMI");
                scope.Connect();
                using (ManagementObjectSearcher s1 = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM BatteryStaticData")))
                { foreach (ManagementObject obj in s1.Get()) { if (obj["DesignedCapacity"] != null) designCap = Convert.ToInt64(obj["DesignedCapacity"]); break; } }
                using (ManagementObjectSearcher s2 = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM BatteryFullChargedCapacity")))
                { foreach (ManagementObject obj in s2.Get()) { if (obj["FullChargedCapacity"] != null) fullCap = Convert.ToInt64(obj["FullChargedCapacity"]); break; } }
                if (designCap > 0)
                {
                    info.HasBattery = true;
                    info.DesignCapacity = designCap + " mWh";
                    if (fullCap > 0) { info.CurrentCapacity = fullCap + " mWh"; double wear = 100.0 - ((double)fullCap * 100.0 / designCap); if (wear < 0) wear = 0; info.WearLevel = Math.Round(wear, 1) + "%"; }
                }
                using (ManagementObjectSearcher s3 = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM BatteryCycleCount")))
                { foreach (ManagementObject obj in s3.Get()) { if (obj["CycleCount"] != null) { info.CycleCount = Convert.ToInt32(obj["CycleCount"]); break; } } }
            }
            catch { }
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Battery"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        info.HasBattery = true;
                        if (obj["BatteryStatus"] != null) { int s = Convert.ToInt32(obj["BatteryStatus"]); if (s == 1) info.Status = "Đang dùng pin (Discharging)"; else if (s == 2) info.Status = "Đang cắm sạc (AC/Charging)"; else if (s == 3) info.Status = "Đã sạc đầy (Full)"; else info.Status = "Kết nối nguồn"; }
                        if (obj["DesignVoltage"] != null) { double v = Convert.ToDouble(obj["DesignVoltage"]) / 1000.0; info.Voltage = v.ToString("0.0") + " V"; }
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
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID LIKE '%Wi-Fi%' OR NetConnectionID LIKE '%Wireless%'"))
                { foreach (ManagementObject obj in searcher.Get()) { if (obj["Name"] != null) { info.AdapterName = obj["Name"].ToString().Trim(); break; } } }
                ProcessStartInfo psi = new ProcessStartInfo(); psi.FileName = "netsh"; psi.Arguments = "wlan show interfaces"; psi.RedirectStandardOutput = true; psi.UseShellExecute = false; psi.CreateNoWindow = true;
                using (Process proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    foreach (string line in output.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.None))
                    {
                        string t = line.Trim();
                        if (t.StartsWith("SSID") && !t.StartsWith("BSSID")) { string[] p = t.Split(new char[] { ':' }, 2); if (p.Length > 1) info.CurrentSsid = p[1].Trim(); }
                        else if (t.StartsWith("Signal") || t.StartsWith("Tín hiệu")) { string[] p = t.Split(new char[] { ':' }, 2); if (p.Length > 1) info.CurrentSignal = p[1].Trim(); }
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
                        if (desc.StartsWith("WAN Miniport", StringComparison.OrdinalIgnoreCase) || desc.StartsWith("Microsoft Wi-Fi Direct", StringComparison.OrdinalIgnoreCase) || desc.StartsWith("Bluetooth Device (Personal Area", StringComparison.OrdinalIgnoreCase)) continue;
                        string ip = "N/A";
                        if (obj["IPAddress"] != null) { string[] ips = (string[])obj["IPAddress"]; if (ips.Length > 0) ip = ips[0]; }
                        NetworkAdapterItem item = new NetworkAdapterItem(); item.Name = desc; item.MacAddress = mac; item.IpAddress = ip;
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
                { foreach (ManagementObject obj in searcher.Get()) { if (obj["Name"] != null) { string n = obj["Name"].ToString().Trim(); if (!list.Contains(n)) list.Add(n); } } }
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
                { foreach (ManagementObject obj in searcher.Get()) { if (obj["Name"] != null) { string n = obj["Name"].ToString().Trim(); if (!list.Contains(n)) list.Add(n); } } }
            }
            catch { }
            return list;
        }

        // ── NEW: Đọc nhiệt độ CPU từ WMI ──
        static TemperatureInfo GetTemperatures()
        {
            TemperatureInfo info = new TemperatureInfo();
            try
            {
                ManagementScope scope = new ManagementScope(@"root\WMI");
                scope.Connect();
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSAcpi_ThermalZoneTemperature")))
                {
                    List<double> temps = new List<double>();
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["CurrentTemperature"] != null)
                        {
                            double rawTemp = Convert.ToDouble(obj["CurrentTemperature"]);
                            double celsius = (rawTemp / 10.0) - 273.15;
                            if (celsius > 0 && celsius < 150) temps.Add(celsius);
                        }
                    }
                    if (temps.Count > 0)
                    {
                        info.CpuTempCelsius = temps[0];
                        info.IsAvailable = true;
                    }
                }
            }
            catch { }
            return info;
        }

        // ── NEW: Liệt kê cổng USB ──
        static List<UsbPortInfo> GetUsbPorts()
        {
            List<UsbPortInfo> list = new List<UsbPortInfo>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_USBHub"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = obj["Name"] != null ? obj["Name"].ToString().Trim() : "USB Hub";
                        string devId = obj["DeviceID"] != null ? obj["DeviceID"].ToString() : "";
                        if (name.Contains("Root Hub") || name.Contains("USB Root")) continue;
                        UsbPortInfo p = new UsbPortInfo();
                        p.Name = name; p.DeviceId = devId;
                        // Đoán chuẩn USB từ tên
                        string nameUpper = name.ToUpper();
                        if (nameUpper.Contains("USB 4") || nameUpper.Contains("THUNDERBOLT")) p.Standard = "USB4 / Thunderbolt";
                        else if (nameUpper.Contains("SUPERSPEED") || nameUpper.Contains("SS USB") || nameUpper.Contains("3.1") || nameUpper.Contains("3.2") || nameUpper.Contains("USB31") || nameUpper.Contains("USB32")) p.Standard = "USB 3.1/3.2 Gen 2";
                        else if (nameUpper.Contains("USB3") || nameUpper.Contains("3.0") || nameUpper.Contains("USB 3")) p.Standard = "USB 3.0";
                        else p.Standard = "USB 2.0";
                        list.Add(p);
                    }
                }
            }
            catch { }

            // Cũng kiểm tra Win32_USBController
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_USBController"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = obj["Name"] != null ? obj["Name"].ToString().Trim() : "USB Controller";
                        UsbPortInfo p = new UsbPortInfo();
                        p.Name = name;
                        string nu = name.ToUpper();
                        if (nu.Contains("USB4") || nu.Contains("THUNDERBOLT")) p.Standard = "USB4 / Thunderbolt";
                        else if (nu.Contains("3.1") || nu.Contains("3.2") || nu.Contains("SUPERSPEED")) p.Standard = "USB 3.1/3.2";
                        else if (nu.Contains("3.0") || nu.Contains("EXTENSIBLE") || nu.Contains("XHCI")) p.Standard = "USB 3.0 (xHCI)";
                        else if (nu.Contains("EHCI") || nu.Contains("2.0")) p.Standard = "USB 2.0 (EHCI)";
                        else p.Standard = "USB 2.0";
                        // Kiểm tra trùng lặp
                        bool dup = false;
                        foreach (UsbPortInfo ex in list) { if (ex.Name == name) { dup = true; break; } }
                        if (!dup) list.Add(p);
                    }
                }
            }
            catch { }
            return list;
        }

        // ── NEW: Kiểm tra bảo mật hệ thống ──
        static SecurityInfo GetSecurityInfo()
        {
            SecurityInfo info = new SecurityInfo();

            // 1. Secure Boot
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State"))
                {
                    if (key != null)
                    {
                        info.SecureBootAvailable = true;
                        object val = key.GetValue("UEFISecureBootEnabled");
                        if (val != null) info.SecureBootEnabled = Convert.ToInt32(val) == 1;
                    }
                }
            }
            catch { }

            // Fallback Secure Boot check
            if (!info.SecureBootAvailable)
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot"))
                    {
                        if (key != null) info.SecureBootAvailable = true;
                    }
                }
                catch { }
            }

            // 2. TPM
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(@"root\CIMv2\Security\MicrosoftTpm", "SELECT * FROM Win32_Tpm"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        info.TpmPresent = true;
                        if (obj["SpecVersion"] != null) info.TpmVersion = "TPM " + obj["SpecVersion"].ToString().Trim().Split(',')[0].Trim();
                        if (obj["IsEnabled_InitialValue"] != null) info.TpmEnabled = Convert.ToBoolean(obj["IsEnabled_InitialValue"]);
                        break;
                    }
                }
            }
            catch { }

            // Fallback TPM from Registry
            if (!info.TpmPresent)
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\TPM"))
                    { if (key != null) { info.TpmPresent = true; info.TpmVersion = "TPM (phiên bản không xác định)"; } }
                }
                catch { }
            }

            // 3. Windows Activation
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL AND ApplicationId = '55c92734-d682-4d71-983e-d6ec3f16059f'"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["LicenseStatus"] != null)
                        {
                            int status = Convert.ToInt32(obj["LicenseStatus"]);
                            switch (status)
                            {
                                case 0: info.WindowsActivationStatus = "Chưa kích hoạt (Unlicensed)"; info.IsGenuineWindows = false; break;
                                case 1: info.WindowsActivationStatus = "Đã kích hoạt hợp lệ (Licensed – Genuine)"; info.IsGenuineWindows = true; break;
                                case 2: info.WindowsActivationStatus = "Kích hoạt bổ sung bên ngoài (Out-of-Box Grace)"; info.IsGenuineWindows = false; break;
                                case 3: info.WindowsActivationStatus = "Trong thời hạn gia hạn (Non-Genuine Grace)"; info.IsGenuineWindows = false; break;
                                case 4: info.WindowsActivationStatus = "Thông báo (Notification Mode) – Có thể crack!"; info.IsGenuineWindows = false; break;
                                case 5: info.WindowsActivationStatus = "Kích hoạt tạm thời (Extended Grace)"; info.IsGenuineWindows = false; break;
                                default: info.WindowsActivationStatus = string.Format("Trạng thái {0} (Không xác định)", status); info.IsGenuineWindows = false; break;
                            }
                            break;
                        }
                    }
                }
            }
            catch { }
            if (string.IsNullOrEmpty(info.WindowsActivationStatus) || info.WindowsActivationStatus == "Unknown")
            {
                info.WindowsActivationStatus = "Không lấy được thông tin kích hoạt";
                info.IsGenuineWindows = false;
            }

            // 4. BitLocker
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(@"root\CIMV2\Security\MicrosoftVolumeEncryption", "SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = 'C:'"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["ProtectionStatus"] != null)
                        {
                            int ps = Convert.ToInt32(obj["ProtectionStatus"]);
                            if (ps == 0) info.BitLockerStatus = "Không bật (Protection Off)";
                            else if (ps == 1) info.BitLockerStatus = "Đang bật – Ổ C: đã được mã hóa BitLocker!";
                            else info.BitLockerStatus = "Đang chờ kích hoạt";
                        }
                        break;
                    }
                }
            }
            catch
            {
                // Fallback: Check registry
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\BitLocker"))
                    { if (key != null) info.BitLockerStatus = "Có cấu hình BitLocker (cần quyền Admin để đọc trạng thái)"; }
                }
                catch { }
                if (string.IsNullOrEmpty(info.BitLockerStatus) || info.BitLockerStatus == "Không có thông tin")
                    info.BitLockerStatus = "Không có thông tin (cần quyền Admin để kiểm tra)";
            }

            return info;
        }

        // ── NEW: Tính điểm sức khỏe tổng hợp ──
        static HealthScoreResult CalculateHealthScore(CpuInfo cpu, RamInfo ram, List<GpuDevice> gpus, List<DriveInfoItem> drives, BatteryInfo bat, MdmInfo mdm, SecurityInfo sec, TemperatureInfo temp)
        {
            HealthScoreResult result = new HealthScoreResult();
            int score = 100;

            // ── CPU ──
            if (cpu.IsSpoofed)         { score -= 30; result.Penalties.Add("CPU bị fake / sửa Registry (trừ 30 điểm)"); }
            else if (!string.IsNullOrEmpty(cpu.GenerationMismatch)) { score -= 25; result.Penalties.Add("CPU thế hệ không khớp tên hiển thị (trừ 25 điểm)"); }
            else                       { result.Bonuses.Add("CPU xác thực CPUID hợp lệ"); }
            if (!string.IsNullOrEmpty(cpu.CpuGenerationNote) && (cpu.CpuGeneration.Contains("Core 2") || cpu.CpuGeneration.Contains("Netburst") || cpu.CpuGeneration.Contains("2nd Gen") || cpu.CpuGeneration.Contains("1st Gen")))
            { score -= 10; result.Penalties.Add("CPU đời quá cũ (trừ 10 điểm)"); }

            // ── GPU ──
            foreach (GpuDevice gpu in gpus)
            {
                if (gpu.IsFakeSuspected) { score -= 25; result.Penalties.Add("GPU nghi vấn fake / mod VBIOS (trừ 25 điểm)"); break; }
                if (gpu.IsVramMismatch)  { score -= 15; result.Penalties.Add("GPU VRAM tên không khớp thực tế (trừ 15 điểm)"); break; }
            }

            // ── Storage S.M.A.R.T. ──
            foreach (DriveInfoItem d in drives)
            {
                if (d.ReallocatedSectors > 0) { score -= 20; result.Penalties.Add(string.Format("Ổ cứng có Bad Sector (Reallocated={0}, trừ 20 điểm)", d.ReallocatedSectors)); }
                if (d.PendingSectors > 0)     { score -= 15; result.Penalties.Add(string.Format("Ổ cứng có Pending Sector (={0}, trừ 15 điểm)", d.PendingSectors)); }
                if (d.UncorrectableErrors > 0){ score -= 20; result.Penalties.Add(string.Format("Ổ cứng có lỗi Uncorrectable (={0}, trừ 20 điểm)", d.UncorrectableErrors)); }
                if (d.PowerOnHours > 25000)   { score -= 15; result.Penalties.Add(string.Format("Ổ cứng đã chạy {0:N0} giờ – quá lâu (trừ 15 điểm)", d.PowerOnHours)); }
                else if (d.PowerOnHours > 15000) { score -= 8; result.Penalties.Add(string.Format("Ổ cứng đã chạy {0:N0} giờ – nhiều (trừ 8 điểm)", d.PowerOnHours)); }
                else if (d.PowerOnHours >= 0 && d.PowerOnHours < 3000) { result.Bonuses.Add("Ổ cứng còn mới (Power-On < 3000h)"); }
                if (d.WearPercent > 80)       { score -= 10; result.Penalties.Add(string.Format("SSD mài mòn cao {0}% (trừ 10 điểm)", d.WearPercent)); }
                if (d.TemperatureCelsius > 55) { score -= 5; result.Penalties.Add("Nhiệt độ ổ cứng cao (trừ 5 điểm)"); }
                if (d.HealthStatus.Contains("Nguy")) { score -= 20; result.Penalties.Add("S.M.A.R.T. báo nguy hiểm (trừ 20 điểm)"); }
                else if (d.HealthStatus.Contains("Cảnh")) { score -= 10; result.Penalties.Add("S.M.A.R.T. cảnh báo (trừ 10 điểm)"); }
                else { result.Bonuses.Add("S.M.A.R.T. ổ cứng bình thường"); }
            }

            // ── RAM ──
            if (!ram.IsConsistent) { score -= 10; result.Penalties.Add("RAM dung lượng bất thường (trừ 10 điểm)"); }
            if (ram.IsDualChannel) result.Bonuses.Add("RAM Dual Channel – Hiệu năng tối ưu");
            else if (ram.ActiveSlots == 1) { score -= 3; result.Penalties.Add("RAM Single Channel – Kém hiệu năng (trừ 3 điểm)"); }

            // ── MDM / Autopilot ──
            if (mdm.IsMdmDetected) { score -= 30; result.Penalties.Add("Máy dính MDM / Autopilot – RẤT NGUY HIỂM (trừ 30 điểm)"); }
            else result.Bonuses.Add("Không dính MDM / Autopilot / Computrace");

            // ── Battery ──
            if (bat.HasBattery)
            {
                double wearVal = 0;
                if (bat.WearLevel != null && bat.WearLevel.Contains("%")) double.TryParse(bat.WearLevel.Replace("%", "").Trim(), out wearVal);
                if (wearVal > 60)      { score -= 10; result.Penalties.Add(string.Format("Pin chai nặng {0} (trừ 10 điểm)", bat.WearLevel)); }
                else if (wearVal > 40) { score -= 5; result.Penalties.Add(string.Format("Pin chai vừa {0} (trừ 5 điểm)", bat.WearLevel)); }
                else if (wearVal < 20) { result.Bonuses.Add("Pin còn rất tốt (Wear < 20%)"); }
                if (bat.CycleCount > 800) { score -= 5; result.Penalties.Add(string.Format("Pin đã sạc {0} chu kỳ (trừ 5 điểm)", bat.CycleCount)); }
            }

            // ── Security ──
            if (!sec.IsGenuineWindows) { score -= 10; result.Penalties.Add("Windows nghi vấn không bản quyền (trừ 10 điểm)"); }
            else result.Bonuses.Add("Windows có bản quyền hợp lệ");
            if (!sec.SecureBootEnabled && sec.SecureBootAvailable) { score -= 5; result.Penalties.Add("Secure Boot bị tắt (trừ 5 điểm)"); }

            // ── Temperature ──
            if (temp.IsAvailable)
            {
                if (temp.CpuTempCelsius > 80) { score -= 10; result.Penalties.Add(string.Format("CPU quá nóng khi nghỉ {0:F0}°C (trừ 10 điểm)", temp.CpuTempCelsius)); }
                else if (temp.CpuTempCelsius > 65) { score -= 5; result.Penalties.Add(string.Format("CPU hơi nóng {0:F0}°C (trừ 5 điểm)", temp.CpuTempCelsius)); }
                else { result.Bonuses.Add(string.Format("Nhiệt độ CPU bình thường ({0:F0}°C)", temp.CpuTempCelsius)); }
            }

            // Clamp
            if (score < 0) score = 0;
            if (score > 100) score = 100;
            result.TotalScore = score;

            // Xếp hạng và tư vấn giá
            if (score >= 90)      { result.Grade = "A+"; result.Verdict = "Xuất sắc – Máy như mới"; result.PriceAdvice = "Có thể mua bình thường, ít cần thương lượng."; }
            else if (score >= 80) { result.Grade = "A";  result.Verdict = "Tốt – Đáng mua";         result.PriceAdvice = "Mua thoải mái, có thể thương lượng 5-10%."; }
            else if (score >= 70) { result.Grade = "B";  result.Verdict = "Khá – Chấp nhận được";   result.PriceAdvice = "Nên thương lượng giảm 10-20% so với giá niêm yết."; }
            else if (score >= 60) { result.Grade = "C";  result.Verdict = "Trung bình – Cần cân nhắc"; result.PriceAdvice = "Yêu cầu giảm 20-35% hoặc bỏ qua nếu có lựa chọn khác."; }
            else if (score >= 40) { result.Grade = "D";  result.Verdict = "Kém – Nhiều vấn đề";     result.PriceAdvice = "Chỉ mua nếu giảm giá > 40%, và phải tính chi phí sửa chữa."; }
            else                   { result.Grade = "F";  result.Verdict = "Không nên mua";          result.PriceAdvice = "KHÔNG NÊN MUA – Rủi ro quá cao hoặc phát hiện gian lận!"; }

            return result;
        }

        static MdmInfo GetAndVerifyMdm()
        {
            MdmInfo info = new MdmInfo();

            // 1. Autopilot Policy Cache
            try
            {
                using (RegistryKey apKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache"))
                {
                    if (apKey != null)
                    {
                        object pAvail = apKey.GetValue("ProfileAvailable");
                        if (pAvail != null && Convert.ToInt32(pAvail) == 1) { info.IsAutopilotDetected = true; info.IsMdmDetected = true; info.DetectionReasons.Add("Profile Windows Autopilot đang sẵn sàng áp dụng (ProfileAvailable = 1)"); }
                        object pJson = apKey.GetValue("PolicyJsonCache");
                        if (pJson != null)
                        {
                            string json = pJson.ToString();
                            if (!string.IsNullOrEmpty(json))
                            {
                                int tdIdx = json.IndexOf("CloudAssignedTenantDomain");
                                if (tdIdx >= 0)
                                {
                                    string sub = json.Substring(tdIdx); int start = sub.IndexOf(":\"\\\""); if (start < 0) start = sub.IndexOf(":\"");
                                    if (start >= 0) { int vs = sub.IndexOf('"', start + 1); if (vs >= 0) { int ve = sub.IndexOf('"', vs + 1); if (ve > vs) { string domain = sub.Substring(vs + 1, ve - vs - 1).Replace("\\", "").Trim(); if (!string.IsNullOrEmpty(domain)) { info.AutopilotTenant = domain; info.IsAutopilotDetected = true; info.IsMdmDetected = true; info.DetectionReasons.Add("Tổ chức quản lý Autopilot: " + domain); } } } }
                                }
                                if (json.Contains("\"ForcedEnrollment\":1") || json.Contains("\"ForcedEnrollment\": 1")) { info.IsAutopilotDetected = true; info.IsMdmDetected = true; info.DetectionReasons.Add("Bắt buộc ghi danh Autopilot khi cài lại Windows (ForcedEnrollment = 1)"); }
                            }
                        }
                    }
                }
            }
            catch { }

            // 2. MDM Enrollments
            try
            {
                using (RegistryKey enrollments = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Enrollments"))
                {
                    if (enrollments != null)
                    {
                        foreach (string subName in enrollments.GetSubKeyNames())
                        {
                            if (subName.Equals("Context", StringComparison.OrdinalIgnoreCase) || subName.Equals("Status", StringComparison.OrdinalIgnoreCase) || subName.Equals("ValidNodePaths", StringComparison.OrdinalIgnoreCase)) continue;
                            using (RegistryKey sub = enrollments.OpenSubKey(subName))
                            {
                                if (sub == null) continue;
                                object provObj = sub.GetValue("ProviderID"); object urlObj = sub.GetValue("DiscoveryServiceFullURL"); object upnObj = sub.GetValue("UPN");
                                string prov = provObj != null ? provObj.ToString().Trim() : ""; string url = urlObj != null ? urlObj.ToString().Trim() : ""; string upn = upnObj != null ? upnObj.ToString().Trim() : "";
                                if (!string.IsNullOrEmpty(url) && (url.Contains("manage.microsoft.com") || url.Contains("enrollment") || url.Contains("http"))) { info.IsMdmDetected = true; info.MdmDiscoveryUrl = url; if (!string.IsNullOrEmpty(prov)) info.MdmProvider = prov; info.DetectionReasons.Add(string.Format("Đăng ký MDM Server: {0} ({1})", prov, url)); }
                                else if (!string.IsNullOrEmpty(upn) && upn.Contains("@") && !string.IsNullOrEmpty(prov) && !prov.Equals("Local Authority", StringComparison.OrdinalIgnoreCase) && !prov.Equals("Deploy Authority", StringComparison.OrdinalIgnoreCase) && !prov.Equals("Cloud Authority", StringComparison.OrdinalIgnoreCase)) { info.IsMdmDetected = true; info.MdmProvider = prov; info.DetectionReasons.Add(string.Format("Tài khoản tổ chức gán vào máy: {0} ({1})", upn, prov)); }
                            }
                        }
                    }
                }
            }
            catch { }

            // 3. dsregcmd
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("dsregcmd.exe", "/status"); psi.CreateNoWindow = true; psi.UseShellExecute = false; psi.RedirectStandardOutput = true;
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd(); p.WaitForExit(3000);
                    if (!string.IsNullOrEmpty(output))
                    {
                        using (StringReader sr = new StringReader(output))
                        {
                            string line;
                            while ((line = sr.ReadLine()) != null)
                            {
                                string t = line.Trim();
                                if (t.StartsWith("AzureAdJoined", StringComparison.OrdinalIgnoreCase) && t.EndsWith("YES", StringComparison.OrdinalIgnoreCase)) { info.IsAzureAdJoined = true; info.IsMdmDetected = true; info.DetectionReasons.Add("Máy đã gia nhập Azure Active Directory (AzureAdJoined = YES)"); }
                                else if (t.StartsWith("EnterpriseJoined", StringComparison.OrdinalIgnoreCase) && t.EndsWith("YES", StringComparison.OrdinalIgnoreCase)) { info.IsDomainJoined = true; info.IsMdmDetected = true; info.DetectionReasons.Add("Máy đã gia nhập mạng doanh nghiệp (EnterpriseJoined = YES)"); }
                                else if (t.StartsWith("DomainJoined", StringComparison.OrdinalIgnoreCase) && t.EndsWith("YES", StringComparison.OrdinalIgnoreCase)) { info.IsDomainJoined = true; info.IsMdmDetected = true; info.DetectionReasons.Add("Máy trực thuộc Domain công ty (DomainJoined = YES)"); }
                                else if (t.StartsWith("TenantName", StringComparison.OrdinalIgnoreCase)) { int c = t.IndexOf(':'); if (c >= 0) { string tn = t.Substring(c + 1).Trim(); if (!string.IsNullOrEmpty(tn) && !tn.Equals("NOT SET", StringComparison.OrdinalIgnoreCase)) { info.DomainName = tn; info.IsMdmDetected = true; info.DetectionReasons.Add("Tên doanh nghiệp quản lý (TenantName): " + tn); } } }
                                else if (t.StartsWith("DeviceManagementUrl", StringComparison.OrdinalIgnoreCase)) { int c = t.IndexOf(':'); if (c >= 0) { string dm = t.Substring(c + 1).Trim(); if (!string.IsNullOrEmpty(dm) && !dm.Equals("NOT SET", StringComparison.OrdinalIgnoreCase)) { info.IsMdmDetected = true; info.MdmDiscoveryUrl = dm; info.DetectionReasons.Add("Cổng quản lý thiết bị: " + dm); } } }
                            }
                        }
                    }
                }
            }
            catch { }

            // 4. Computrace / Absolute Persistence
            try
            {
                string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string rpc1 = Path.Combine(sys32, "rpcnet.exe"); string rpc2 = Path.Combine(sys32, "rpcnetp.exe"); string rpc3 = Path.Combine(sys32, "rpcnet.dll");
                if (File.Exists(rpc1) || File.Exists(rpc2) || File.Exists(rpc3)) { info.IsComputraceDetected = true; info.IsMdmDetected = true; info.DetectionReasons.Add("Dính Computrace / Absolute Persistence ngầm trong BIOS (rpcnet.exe/rpcnetp.exe)"); }
                using (RegistryKey rpcKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\rpcnetp"))
                { if (rpcKey != null) { info.IsComputraceDetected = true; info.IsMdmDetected = true; info.DetectionReasons.Add("Dịch vụ Computrace (rpcnetp service) đang cài đặt trong hệ điều hành"); } }
            }
            catch { }

            // 5. CloudDomainJoin
            try
            {
                using (RegistryKey cdjKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"))
                { if (cdjKey != null && cdjKey.SubKeyCount > 0) { info.IsAzureAdJoined = true; info.IsMdmDetected = true; info.DetectionReasons.Add("Phát hiện CloudDomainJoin – Máy đã liên kết với máy chủ đám mây"); } }
            }
            catch { }

            return info;
        }

        static string FormatWmiDate(string raw)
        {
            if (string.IsNullOrEmpty(raw) || raw.Length < 8) return "N/A";
            try
            {
                string y = raw.Substring(0, 4), m = raw.Substring(4, 2), d = raw.Substring(6, 2);
                if (raw.Length >= 14) return string.Format("{0}/{1}/{2} {3}:{4}:{5}", d, m, y, raw.Substring(8, 2), raw.Substring(10, 2), raw.Substring(12, 2));
                return string.Format("{0}/{1}/{2}", d, m, y);
            }
            catch { return raw; }
        }

        static string GetUptime(string lastBootRaw)
        {
            if (string.IsNullOrEmpty(lastBootRaw) || lastBootRaw.Length < 14) return "N/A";
            try
            {
                DateTime bootTime = new DateTime(int.Parse(lastBootRaw.Substring(0, 4)), int.Parse(lastBootRaw.Substring(4, 2)), int.Parse(lastBootRaw.Substring(6, 2)), int.Parse(lastBootRaw.Substring(8, 2)), int.Parse(lastBootRaw.Substring(10, 2)), int.Parse(lastBootRaw.Substring(12, 2)));
                TimeSpan span = DateTime.Now - bootTime;
                return string.Format("{0} ngày {1} giờ {2} phút", span.Days, span.Hours, span.Minutes);
            }
            catch { return "N/A"; }
        }

        static SystemInfo GetSystemInfo()
        {
            SystemInfo info = new SystemInfo();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                { foreach (ManagementObject obj in searcher.Get()) { if (obj["Manufacturer"] != null) info.Manufacturer = obj["Manufacturer"].ToString().Trim(); if (obj["Model"] != null) info.Model = obj["Model"].ToString().Trim(); break; } }
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard"))
                { foreach (ManagementObject obj in searcher.Get()) { if (obj["Manufacturer"] != null) info.Motherboard.Manufacturer = obj["Manufacturer"].ToString().Trim(); if (obj["Product"] != null) info.Motherboard.Product = obj["Product"].ToString().Trim(); if (obj["Version"] != null) info.Motherboard.Version = obj["Version"].ToString().Trim(); if (obj["SerialNumber"] != null) info.Motherboard.SerialNumber = obj["SerialNumber"].ToString().Trim(); break; } }
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["Manufacturer"] != null) info.BIOS.Vendor = obj["Manufacturer"].ToString().Trim();
                        if (obj["SMBIOSBIOSVersion"] != null) info.BIOS.Version = obj["SMBIOSBIOSVersion"].ToString().Trim();
                        else if (obj["Version"] != null) info.BIOS.Version = obj["Version"].ToString().Trim();
                        if (obj["ReleaseDate"] != null) info.BIOS.ReleaseDate = FormatWmiDate(obj["ReleaseDate"].ToString());
                        if (obj["SerialNumber"] != null)
                        {
                            string sn = obj["SerialNumber"].ToString().Trim();
                            if (!sn.Equals("Default string", StringComparison.OrdinalIgnoreCase) && !sn.Equals("To Be Filled By O.E.M.", StringComparison.OrdinalIgnoreCase) && !sn.Equals("None", StringComparison.OrdinalIgnoreCase) && !sn.Equals("System Serial Number", StringComparison.OrdinalIgnoreCase) && sn != "0") info.SerialNumber = sn;
                        }
                        break;
                    }
                }
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                { foreach (ManagementObject obj in searcher.Get()) { if (obj["Caption"] != null) info.OS.Caption = obj["Caption"].ToString().Trim(); if (obj["InstallDate"] != null) info.OS.InstallDate = FormatWmiDate(obj["InstallDate"].ToString()); if (obj["LastBootUpTime"] != null) info.OS.Uptime = GetUptime(obj["LastBootUpTime"].ToString()); break; } }
            }
            catch { }
            return info;
        }
        #endregion
    }
}
