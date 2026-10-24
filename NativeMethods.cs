using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    internal static class NativeMethods
    {
        public const int SystemProcessInformation = 5;
        public const int SystemProcessorPerformanceInformation = 8;
        public const int SystemProcessIdInformation = 88;
        public const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

        public const uint SHGFI_ICON = 0x100;
        public const uint SHGFI_SMALLICON = 0x1;
        public const uint SHGFI_LARGEICON = 0x0;
        public const uint SHGFI_USEFILEATTRIBUTES = 0x10;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x80;

        public const int WM_DPICHANGED = 0x02E0;
        public const int WM_MOUSEWHEEL = 0x020A;
        public const int WM_MOUSEHWHEEL = 0x020E;
        public const int WM_LBUTTONDOWN = 0x0201, WM_LBUTTONUP = 0x0202, WM_LBUTTONDBLCLK = 0x0203;
        public const int MK_SHIFT = 0x0004;
        public const int TVS_NOHSCROLL = 0x8000;
        public const int TVM_SETEXTENDEDSTYLE = 0x1100 + 44;
        public const int TVS_EX_DOUBLEBUFFER = 0x0004;

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int Left, Top, Right, Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        // Leading part of the native structure; the trailing I/O counters are not needed.
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_PROCESS_INFORMATION
        {
            public uint NextEntryOffset;
            public uint NumberOfThreads;
            public long WorkingSetPrivateSize;
            public uint HardFaultCount;
            public uint NumberOfThreadsHighWatermark;
            public ulong CycleTime;
            public long CreateTime;
            public long UserTime;
            public long KernelTime;
            public UNICODE_STRING ImageName;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
            public uint HandleCount;
            public uint SessionId;
            public UIntPtr UniqueProcessKey;
            public UIntPtr PeakVirtualSize;
            public UIntPtr VirtualSize;
            public uint PageFaultCount;
            public UIntPtr PeakWorkingSetSize;
            public UIntPtr WorkingSetSize;
            public UIntPtr QuotaPeakPagedPoolUsage;
            public UIntPtr QuotaPagedPoolUsage;
            public UIntPtr QuotaPeakNonPagedPoolUsage;
            public UIntPtr QuotaNonPagedPoolUsage;
            public UIntPtr PagefileUsage;
            public UIntPtr PeakPagefileUsage;
            public UIntPtr PrivatePageCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
        {
            public long IdleTime, KernelTime, UserTime, DpcTime, InterruptTime;
            public uint InterruptCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_PROCESS_ID_INFORMATION
        {
            public IntPtr ProcessId;
            public UNICODE_STRING ImageName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHFILEINFO
        {
            public IntPtr hIcon;
            public int iIcon;
            public uint dwAttributes;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName;
        }

        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, ref SYSTEM_PROCESS_ID_INFORMATION info, int length, out int returnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int max);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr SHGetFileInfo(string path, uint fileAttributes, ref SHFILEINFO info, uint infoSize, uint flags);

        [DllImport("user32.dll")]
        public static extern bool DestroyIcon(IntPtr handle);

        [DllImport("user32.dll")]
        public static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, ref RECT lParam);

        [DllImport("user32.dll")]
        public static extern bool GetClientRect(IntPtr hWnd, out RECT rect);

        [DllImport("user32.dll")]
        public static extern bool InvalidateRect(IntPtr hWnd, IntPtr rect, bool erase);

        [DllImport("user32.dll")]
        public static extern int GetDpiForWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern IntPtr WindowFromPoint(System.Drawing.Point point);

        public const int GW_OWNER = 4;
        public const int GWL_EXSTYLE = -20;
        public const int WS_EX_TOOLWINDOW = 0x80;
        public const int SW_RESTORE = 9;
        public const uint SHOP_FILEPATH = 2;

        public delegate bool EnumWindowsCallback(IntPtr hWnd, IntPtr state);

        [DllImport("user32.dll")]
        public static extern bool EnumWindows(EnumWindowsCallback callback, IntPtr state);

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("user32.dll")]
        public static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern IntPtr GetWindow(IntPtr hWnd, int relationship);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int maxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetWindowLong(IntPtr hWnd, int index);

        [DllImport("user32.dll")]
        public static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int command);

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool IsHungAppWindow(IntPtr hWnd);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        public static extern bool SHObjectProperties(IntPtr hWnd, uint type, string objectName, string propertyPage);

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        public static extern int SetWindowTheme(IntPtr hWnd, string subAppName, string subIdList);

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hWnd, int attribute, ref int value, int size);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORYSTATUSEX
        {
            public uint Length;
            public uint MemoryLoad;
            public ulong TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual, AvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX status);

        private static MEMORYSTATUSEX GetMemoryStatus()
        {
            var status = new MEMORYSTATUSEX { Length = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (!GlobalMemoryStatusEx(ref status))
                throw new System.ComponentModel.Win32Exception();
            return status;
        }

        /// <summary>Physical memory available to Windows, in bytes.</summary>
        public static long GetTotalPhysicalMemory() => (long)GetMemoryStatus().TotalPhys;

        /// <summary>Physical memory in use, in bytes: what Task Manager reports as "In use".</summary>
        public static long GetMemoryInUse()
        {
            MEMORYSTATUSEX status = GetMemoryStatus();
            return (long)(status.TotalPhys - status.AvailPhys);
        }

        /// <summary>
        /// Time all processors have spent on interrupts and deferred procedure calls since boot, in
        /// 100 ns units, or 0 when it cannot be read. No process is charged for this time.
        /// </summary>
        public static long GetInterruptAndDpcTime(int processorCount)
        {
            int size = Marshal.SizeOf<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>();
            IntPtr buffer = Marshal.AllocHGlobal(size * processorCount);
            try
            {
                if (NtQuerySystemInformation(SystemProcessorPerformanceInformation, buffer, size * processorCount, out int returned) < 0)
                    return 0;
                long total = 0;
                for (int i = 0; i < returned / size; i++)
                {
                    var info = Marshal.PtrToStructure<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>(IntPtr.Add(buffer, i * size));
                    total += info.DpcTime + info.InterruptTime;
                }
                return total;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>Switches the window's title bar between the light and dark system styles.</summary>
        public static void SetDarkTitleBar(IntPtr hWnd, bool dark)
        {
            const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
            int value = dark ? 1 : 0;
            DwmSetWindowAttribute(hWnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref value, sizeof(int));
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, IntPtr buffer, int length, out int returnLength);

        /// <summary>
        /// Command line a process was started with, or null when Windows will not let this process
        /// look: system and protected processes, and other users' unless running as administrator.
        /// </summary>
        public static string GetCommandLine(int pid)
        {
            const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
            const int ProcessCommandLineInformation = 60;
            IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (process == IntPtr.Zero) return null;
            try
            {
                int size = 2048;
                for (int attempt = 0; attempt < 2; attempt++)
                {
                    IntPtr buffer = Marshal.AllocHGlobal(size);
                    try
                    {
                        int status = NtQueryInformationProcess(process, ProcessCommandLineInformation, buffer, size, out int needed);
                        if (status < 0 && needed > size)
                        {
                            size = needed;
                            continue;
                        }
                        if (status < 0) return null;
                        // A UNICODE_STRING header followed by the characters it points to.
                        var text = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
                        return text.Buffer == IntPtr.Zero ? "" : Marshal.PtrToStringUni(text.Buffer, text.Length / 2);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }
                return null;
            }
            finally
            {
                CloseHandle(process);
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, IntPtr buffer, IntPtr size, out IntPtr read);

        private static IntPtr ReadPointer(IntPtr process, IntPtr address, IntPtr scratch) =>
            ReadProcessMemory(process, address, scratch, (IntPtr)IntPtr.Size, out _) ? Marshal.ReadIntPtr(scratch) : IntPtr.Zero;

        /// <summary>
        /// The folder a process is working in, read from its memory, or null when Windows will not let
        /// this process look. 64-bit only: the offsets below are those of the 64-bit structures.
        /// </summary>
        public static string GetCurrentDirectory(int pid)
        {
            if (IntPtr.Size != 8) return null;
            const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, PROCESS_VM_READ = 0x10;
            const int ProcessBasicInformation = 0;
            const int PebProcessParameters = 0x20, ParametersCurrentDirectory = 0x38;
            IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid);
            if (process == IntPtr.Zero) return null;
            IntPtr scratch = Marshal.AllocHGlobal(1024);
            try
            {
                // PROCESS_BASIC_INFORMATION: exit status, then the address of the process environment block.
                if (NtQueryInformationProcess(process, ProcessBasicInformation, scratch, 48, out _) < 0) return null;
                IntPtr peb = Marshal.ReadIntPtr(scratch, 8);
                if (peb == IntPtr.Zero) return null;
                IntPtr parameters = ReadPointer(process, IntPtr.Add(peb, PebProcessParameters), scratch);
                if (parameters == IntPtr.Zero) return null;
                // The current directory is a UNICODE_STRING (and a handle) inside the process parameters.
                if (!ReadProcessMemory(process, IntPtr.Add(parameters, ParametersCurrentDirectory), scratch, (IntPtr)16, out _)) return null;
                var path = Marshal.PtrToStructure<UNICODE_STRING>(scratch);
                if (path.Buffer == IntPtr.Zero || path.Length == 0 || path.Length > 1000) return null;
                if (!ReadProcessMemory(process, path.Buffer, scratch, (IntPtr)path.Length, out _)) return null;
                return Marshal.PtrToStringUni(scratch, path.Length / 2);
            }
            finally
            {
                Marshal.FreeHGlobal(scratch);
                CloseHandle(process);
            }
        }

        [DllImport("user32.dll")]
        public static extern IntPtr GetShellWindow();

        private static List<KeyValuePair<string, string>> deviceMap;

        /// <summary>
        /// Full image path of a process, obtained without opening a handle to it, so it also
        /// works for services and protected processes when running unelevated.
        /// </summary>
        public static string GetImagePath(int pid)
        {
            if (pid == 0) return null;
            int capacity = 1024;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                IntPtr buffer = Marshal.AllocHGlobal(capacity);
                try
                {
                    var info = new SYSTEM_PROCESS_ID_INFORMATION
                    {
                        ProcessId = (IntPtr)pid,
                        ImageName = new UNICODE_STRING { Length = 0, MaximumLength = (ushort)capacity, Buffer = buffer }
                    };
                    int status = NtQuerySystemInformation(SystemProcessIdInformation, ref info,
                        Marshal.SizeOf<SYSTEM_PROCESS_ID_INFORMATION>(), out _);
                    if (status == STATUS_INFO_LENGTH_MISMATCH && info.ImageName.MaximumLength > capacity)
                    {
                        capacity = info.ImageName.MaximumLength;
                        continue;
                    }
                    if (status < 0 || info.ImageName.Length == 0) return null;
                    return DevicePathToDosPath(Marshal.PtrToStringUni(buffer, info.ImageName.Length / 2));
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            return null;
        }

        // "\Device\HarddiskVolume3\Windows\notepad.exe" -> "C:\Windows\notepad.exe"
        private static string DevicePathToDosPath(string devicePath)
        {
            if (deviceMap == null)
            {
                var map = new List<KeyValuePair<string, string>>();
                var target = new StringBuilder(512);
                foreach (string drive in Environment.GetLogicalDrives())
                {
                    string letter = drive.Substring(0, 2);
                    if (QueryDosDevice(letter, target, target.Capacity) != 0)
                        map.Add(new KeyValuePair<string, string>(target.ToString() + "\\", letter + "\\"));
                }
                deviceMap = map;
            }
            foreach (var entry in deviceMap)
            {
                if (devicePath.StartsWith(entry.Key, StringComparison.OrdinalIgnoreCase))
                    return entry.Value + devicePath.Substring(entry.Key.Length);
            }
            return null;
        }
    }

    /// <summary>Horizontal scrolling from the mouse: Shift with the ordinary wheel, or a tilting wheel or touchpad.</summary>
    internal static class HorizontalWheel
    {
        /// <summary>
        /// How far a wheel message asks to scroll right, in pixels (negative for left); 0 when it is not
        /// a horizontal scroll. As in Explorer and browsers, Shift with the wheel turned down goes right.
        /// </summary>
        public static int Pixels(ref Message m, float dpiScale)
        {
            int delta = (short)((m.WParam.ToInt64() >> 16) & 0xFFFF);
            if (m.Msg == NativeMethods.WM_MOUSEWHEEL && (m.WParam.ToInt64() & NativeMethods.MK_SHIFT) != 0) delta = -delta;
            else if (m.Msg != NativeMethods.WM_MOUSEHWHEEL) return 0;
            // One notch is 120 units; precision wheels and touchpads send smaller amounts, which scroll less.
            return (int)Math.Round(delta * 60 * dpiScale / 120);
        }
    }

    /// <summary>A list view that scrolls sideways with Shift and the mouse wheel.</summary>
    internal sealed class WheelListView : ListView
    {
        private const int LVM_SCROLL = 0x1014;

        protected override void WndProc(ref Message m)
        {
            int pixels = HorizontalWheel.Pixels(ref m, DeviceDpi / 96f);
            if (pixels != 0)
            {
                NativeMethods.SendMessage(Handle, LVM_SCROLL, (IntPtr)pixels, IntPtr.Zero);
                m.Result = m.Msg == NativeMethods.WM_MOUSEHWHEEL ? (IntPtr)1 : IntPtr.Zero;
                return;
            }
            base.WndProc(ref m);
        }
    }
}
