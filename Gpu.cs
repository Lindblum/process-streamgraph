using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace ProcessStreamgraph
{
    /// <summary>
    /// Per-process GPU use from the "GPU Engine" and "GPU Process Memory" performance counters, the
    /// ones Task Manager reads. A GPU has several engines (3D, copy, video decode and so on) that run
    /// side by side; like Task Manager's overall figure, GPU use here is that of the busiest engine,
    /// and each process is given its share of that engine, so the processes add up to the total.
    /// </summary>
    internal sealed class GpuMonitor
    {
        private struct Reading
        {
            public long Raw, Time;
        }

        private PerformanceCounterCategory engines, memory;
        private volatile bool ready;
        private Dictionary<string, Reading> previous = new Dictionary<string, Reading>();

        /// <summary>The engine whose use the last sample reports, such as "3D"; null when the GPU is idle.</summary>
        public string BusiestEngine { get; private set; }

        /// <summary>False until the counters are open, which takes Windows a few seconds the first time.</summary>
        public bool Available => ready;

        /// <summary>True when this version of Windows or its graphics driver has no GPU counters.</summary>
        public bool Failed { get; private set; }

        /// <summary>
        /// Dedicated video memory of the graphics adapters, in bytes; 0 when it cannot be read. Known
        /// once <see cref="Available"/> is true.
        /// </summary>
        public long DedicatedMemory { get; private set; }

        public GpuMonitor()
        {
            // The first read loads the counter provider and takes seconds; later ones take milliseconds.
            Task.Run(() =>
            {
                try
                {
                    var engineCategory = new PerformanceCounterCategory("GPU Engine");
                    var memoryCategory = new PerformanceCounterCategory("GPU Process Memory");
                    previous = ReadEngines(engineCategory);
                    memoryCategory.ReadCategory();
                    DedicatedMemory = ReadDedicatedMemory(TrackedAdapters());
                    engines = engineCategory;
                    memory = memoryCategory;
                    ready = true;
                }
                catch (Exception e) when (e is InvalidOperationException || e is UnauthorizedAccessException || e is System.ComponentModel.Win32Exception)
                {
                    Failed = true;
                }
            });
        }

        /// <summary>
        /// Each process's share of the busiest engine since the previous call, in percent, and its
        /// dedicated video memory in bytes. Both are empty until the counters are available.
        /// </summary>
        public void Sample(Dictionary<int, double> usage, Dictionary<int, long> dedicated)
        {
            usage.Clear();
            dedicated.Clear();
            if (!ready) return;
            Dictionary<string, Reading> current;
            InstanceDataCollection memoryData;
            try
            {
                current = ReadEngines(engines);
                memoryData = memory.ReadCategory()["dedicated usage"];
            }
            catch (Exception e) when (e is InvalidOperationException || e is System.ComponentModel.Win32Exception)
            {
                return;
            }

            // Use of each engine by each process. Instances are named like
            // pid_1234_luid_0x00000000_0x0000d1f4_phys_0_eng_3_engtype_3d.
            var byEngine = new Dictionary<string, Dictionary<int, double>>();
            var engineTotals = new Dictionary<string, double>();
            foreach (KeyValuePair<string, Reading> entry in current)
            {
                if (!previous.TryGetValue(entry.Key, out Reading before)) continue;
                long elapsed = entry.Value.Time - before.Time;
                if (elapsed <= 0) continue;
                double percent = Math.Max(0, (entry.Value.Raw - before.Raw) * 100.0 / elapsed);
                if (percent == 0 || !TryParse(entry.Key, out int pid, out string engine)) continue;
                if (!byEngine.TryGetValue(engine, out Dictionary<int, double> processes))
                    byEngine[engine] = processes = new Dictionary<int, double>();
                processes.TryGetValue(pid, out double sum);
                processes[pid] = sum + percent;
                engineTotals.TryGetValue(engine, out double total);
                engineTotals[engine] = total + percent;
            }
            previous = current;

            string busiest = null;
            double most = 0;
            foreach (KeyValuePair<string, double> engine in engineTotals)
            {
                if (engine.Value > most)
                {
                    most = engine.Value;
                    busiest = engine.Key;
                }
            }
            BusiestEngine = busiest == null ? null : EngineName(busiest);
            if (busiest != null)
            {
                // Rounding in the counters can take an engine a little past 100%.
                double fit = most > 100 ? 100 / most : 1;
                foreach (KeyValuePair<int, double> process in byEngine[busiest]) usage[process.Key] = process.Value * fit;
            }

            foreach (InstanceData instance in memoryData.Values)
            {
                if (!TryParsePid(instance.InstanceName, out int pid)) continue;
                dedicated.TryGetValue(pid, out long sum);
                dedicated[pid] = sum + instance.RawValue;
            }
        }

        private static Dictionary<string, Reading> ReadEngines(PerformanceCounterCategory category)
        {
            var readings = new Dictionary<string, Reading>();
            foreach (InstanceData instance in category.ReadCategory()["utilization percentage"].Values)
            {
                CounterSample sample = instance.Sample;
                readings[instance.InstanceName.ToLowerInvariant()] = new Reading { Raw = sample.RawValue, Time = sample.TimeStamp100nSec };
            }
            return readings;
        }

        private static bool TryParsePid(string instance, out int pid)
        {
            pid = 0;
            if (!instance.StartsWith("pid_", StringComparison.OrdinalIgnoreCase)) return false;
            int end = instance.IndexOf('_', 4);
            return end > 4 && int.TryParse(instance.Substring(4, end - 4), NumberStyles.None, CultureInfo.InvariantCulture, out pid);
        }

        // The engine is the instance name without its process: adapter, physical GPU, engine number and type.
        private static bool TryParse(string instance, out int pid, out string engine)
        {
            engine = null;
            if (!TryParsePid(instance, out pid)) return false;
            int luid = instance.IndexOf("_luid_", StringComparison.Ordinal);
            if (luid < 0) return false;
            engine = instance.Substring(luid + 1);
            return true;
        }

        /// <summary>The engine type from an engine key, as Task Manager writes it: "3D", "Video Decode".</summary>
        private static string EngineName(string engine)
        {
            int at = engine.IndexOf("engtype_", StringComparison.Ordinal);
            string type = at < 0 ? engine : engine.Substring(at + 8);
            switch (type)
            {
                case "3d": return "3D";
                case "copy": return "Copy";
                case "videodecode": return "Video Decode";
                case "videoencode": return "Video Encode";
                case "videoprocessing": return "Video Processing";
                case "legacyoverlay": return "Legacy Overlay";
                case "security": return "Security";
                case "vr": return "VR";
            }
            // Compute_0, Graphics_1 and the like.
            string name = type.Replace('_', ' ');
            return name.Length == 0 ? "GPU" : char.ToUpperInvariant(name[0]) + name.Substring(1);
        }

        [DllImport("dxgi.dll")]
        private static extern int CreateDXGIFactory1(ref Guid riid, out IntPtr factory);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int EnumAdapters1(IntPtr factory, uint index, out IntPtr adapter);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int GetDesc1(IntPtr adapter, out DXGI_ADAPTER_DESC1 desc);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DXGI_ADAPTER_DESC1
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Description;
            public uint VendorId, DeviceId, SubSysId, Revision;
            public UIntPtr DedicatedVideoMemory, DedicatedSystemMemory, SharedSystemMemory;
            public uint LuidLow;
            public int LuidHigh;
            public uint Flags;
        }

        /// <summary>
        /// The adapters Windows keeps GPU counters for, by LUID as the counters write it:
        /// "0x00000000_0x00015d06".
        /// </summary>
        private static HashSet<string> TrackedAdapters()
        {
            var luids = new HashSet<string>();
            try
            {
                foreach (string instance in new PerformanceCounterCategory("GPU Adapter Memory").GetInstanceNames())
                {
                    string name = instance.ToLowerInvariant();
                    int start = name.IndexOf("luid_", StringComparison.Ordinal), end = name.IndexOf("_phys", StringComparison.Ordinal);
                    if (start >= 0 && end > start) luids.Add(name.Substring(start + 5, end - start - 5));
                }
            }
            catch (InvalidOperationException)
            {
                // No adapter counters: every adapter DXGI lists is counted.
            }
            return luids;
        }

        /// <summary>
        /// Total dedicated video memory of the graphics adapters, as DXGI reports it and Task Manager
        /// shows it. Integrated graphics, which use system memory, have little or none. DXGI can list
        /// an adapter twice under different LUIDs, so only those Windows keeps counters for are
        /// counted, unless it keeps counters for none of them.
        /// </summary>
        private static long ReadDedicatedMemory(HashSet<string> tracked)
        {
            // Slots in the COM interfaces' function tables: IDXGIFactory1::EnumAdapters1, IDXGIAdapter1::GetDesc1.
            const int EnumAdapters1Slot = 12, GetDesc1Slot = 10, ReleaseSlot = 2;
            const uint DXGI_ADAPTER_FLAG_SOFTWARE = 2;
            var iid = new Guid("770aae78-f26f-4dba-a829-253c83d1b387");
            try
            {
                if (CreateDXGIFactory1(ref iid, out IntPtr factory) < 0) return 0;
                try
                {
                    var enumAdapters = Method<EnumAdapters1>(factory, EnumAdapters1Slot);
                    long all = 0, counted = 0;
                    for (uint i = 0; enumAdapters(factory, i, out IntPtr adapter) >= 0; i++)
                    {
                        if (Method<GetDesc1>(adapter, GetDesc1Slot)(adapter, out DXGI_ADAPTER_DESC1 desc) >= 0 &&
                            (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0)
                        {
                            long bytes = (long)desc.DedicatedVideoMemory.ToUInt64();
                            all += bytes;
                            if (tracked.Contains($"0x{desc.LuidHigh:x8}_0x{desc.LuidLow:x8}")) counted += bytes;
                        }
                        Release(adapter, ReleaseSlot);
                    }
                    return counted > 0 ? counted : all;
                }
                finally
                {
                    Release(factory, ReleaseSlot);
                }
            }
            catch (Exception e) when (e is DllNotFoundException || e is EntryPointNotFoundException)
            {
                return 0;
            }
        }

        private static T Method<T>(IntPtr comObject, int slot) where T : Delegate
        {
            IntPtr table = Marshal.ReadIntPtr(comObject);
            return Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(table, slot * IntPtr.Size));
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint ReleaseMethod(IntPtr comObject);

        private static void Release(IntPtr comObject, int slot) => Method<ReleaseMethod>(comObject, slot)(comObject);
    }
}
