using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    internal enum Metric { Cpu, Memory, Network, Gpu, GpuMemory }

    /// <summary>Whether a process has a window and, if so, whether it is answering its messages.</summary>
    internal enum WindowState { None, Running, NotResponding }

    internal sealed class ProcInfo
    {
        public int Pid;
        public int ParentPid;
        public string Name;              // the program's file name, such as "brave.exe"
        public string DisplayName;       // the name Task Manager uses, such as "Brave Browser"
        public string Path;
        public string CommandLine;       // null when it could not be read
        public string Arguments = "";    // the command line without the program name
        public long CreateTime;          // FILETIME (UTC); 0 when unknown
        public Color Color;
        public bool Alive = true;
        public long FirstSample;
        public long LastSample;
        public double Cpu;               // latest sample, percent of all processors
        public long Memory;              // latest sample, private working set in bytes
        public double Network;           // latest sample, KB/s sent plus received
        public double Gpu;               // latest sample, percent of the busiest GPU engine
        public long GpuMemory;           // latest sample, dedicated video memory in bytes
        public WindowState WindowState;
        public SafetyReport Report;      // shared by every process running the same program file
        public string Role;              // its part in its program, from the command line; null when unknown
        public ServiceInfo[] Services;   // Windows services it hosts; null when none
        public string WindowTitle;       // title of its frontmost window; null when it has none
        public string WorkingFolder;     // for shells, script hosts and command-line tools; null otherwise
        public string Details = "";      // the four above, as the Details column shows them
        public Dictionary<Endpoint, Connection> Connections;   // traffic by remote endpoint; null before any
        public TreeNode Node;

        internal long LastCpuTime;
        internal readonly float[] CpuHistory = new float[ProcessMonitor.HistoryLength];
        internal readonly float[] MemHistory = new float[ProcessMonitor.HistoryLength];   // MB
        internal readonly float[] NetHistory = new float[ProcessMonitor.HistoryLength];   // KB/s
        internal readonly float[] GpuHistory = new float[ProcessMonitor.HistoryLength];   // percent
        internal readonly float[] GpuMemHistory = new float[ProcessMonitor.HistoryLength];   // MB

        public Safety Safety => Report?.Overall ?? Safety.Unrated;

        public DateTime? StartTime => CreateTime > 0 ? DateTime.FromFileTimeUtc(CreateTime).ToLocalTime() : (DateTime?)null;

        // Enough for any ordinary program; past this the endpoints longest idle make way, so that one
        // talking to thousands of peers cannot use up memory.
        private const int MaxConnections = 4000;

        /// <summary>Adds traffic with one remote endpoint.</summary>
        internal void AddTraffic(Endpoint remote, long sent, long received, DateTime now)
        {
            if (Connections == null) Connections = new Dictionary<Endpoint, Connection>();
            if (!Connections.TryGetValue(remote, out Connection connection))
            {
                if (Connections.Count >= MaxConnections)
                {
                    Connection idlest = null;
                    foreach (Connection c in Connections.Values)
                        if (idlest == null || c.LastActive < idlest.LastActive) idlest = c;
                    Connections.Remove(idlest.Endpoint);
                }
                Connections[remote] = connection = new Connection { Endpoint = remote };
            }
            connection.Sent += sent;
            connection.Received += received;
            connection.LastActive = now;
        }

        /// <summary>Rebuilds Details, and a service host's display name, after what they are made from changes.</summary>
        public void RefreshDetails()
        {
            DisplayName = AppNames.DisplayNameOf(this);
            var parts = new List<string>(3);
            if (Services != null && Services.Length > 0)
            {
                // A service host is best known by its services; its command line only names their group.
                parts.Add(Services.Length == 1 ? Services[0].DisplayName
                    : Services.Length + " services: " + string.Join(", ", Array.ConvertAll(Services, s => s.DisplayName)));
            }
            else if (Role != null)
            {
                parts.Add(Role);
            }
            if (WorkingFolder != null) parts.Add("in " + ShortFolder(WorkingFolder));
            if (!string.IsNullOrEmpty(WindowTitle)) parts.Add("\u201C" + WindowTitle + "\u201D");
            Details = string.Join("  \u00B7  ", parts);
        }

        // The last two folders of a path, which is usually what tells projects apart: "Projects\\app".
        private static string ShortFolder(string path)
        {
            string trimmed = path.TrimEnd('\\');
            if (string.Equals(trimmed, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase))
                return "home folder";
            string[] parts = trimmed.Split('\\');
            return parts.Length <= 2 ? trimmed + (parts.Length == 1 ? "\\" : "") : parts[parts.Length - 2] + "\\" + parts[parts.Length - 1];
        }

        /// <summary>
        /// CPU or GPU percent, memory or video memory in MB, or network KB/s at the given sample; 0
        /// outside the process lifetime.
        /// </summary>
        public float Value(Metric metric, long sample)
        {
            if (sample < FirstSample || sample > LastSample) return 0f;
            int slot = (int)(sample % ProcessMonitor.HistoryLength);
            switch (metric)
            {
                case Metric.Cpu: return CpuHistory[slot];
                case Metric.Memory: return MemHistory[slot];
                case Metric.Gpu: return GpuHistory[slot];
                case Metric.GpuMemory: return GpuMemHistory[slot];
                default: return NetHistory[slot];
            }
        }
    }

    /// <summary>
    /// Samples every process on the system with a single NtQuerySystemInformation call and keeps
    /// a rolling history of CPU, memory and network usage per process.
    /// </summary>
    internal sealed class ProcessMonitor : IDisposable
    {
        // The history is a fixed number of samples: enough for the full time span at the shortest
        // refresh interval, plus a few seconds for the graphs, which trail the newest sample slightly
        // so they can pan smoothly; more than enough at longer intervals.
        public const double MinIntervalSeconds = 0.5;
        public const int HistorySeconds = 300;
        public const int HistoryLength = (int)((HistorySeconds + 5) / MinIntervalSeconds) + 1;

        private readonly Dictionary<int, ProcInfo> live = new Dictionary<int, ProcInfo>();
        private readonly List<ProcInfo> all = new List<ProcInfo>();
        private readonly DateTime[] sampleTimes = new DateTime[HistoryLength];
        private readonly double[] sampleSeconds = new double[HistoryLength];
        private readonly int processorCount = Environment.ProcessorCount;
        private readonly NetworkMonitor network = new NetworkMonitor();
        private readonly GpuMonitor gpu = new GpuMonitor();
        private readonly Dictionary<int, double> gpuUsage = new Dictionary<int, double>();
        private readonly Dictionary<int, long> gpuMemory = new Dictionary<int, long>();
        private IntPtr buffer;
        private int bufferSize = 1 << 20;
        private long lastTimestamp;
        private long lastInterruptTime;
        private long lastSampleFileTime;

        /// <summary>Index of the most recent sample; -1 before the first one.</summary>
        public long SampleIndex { get; private set; } = -1;

        public int SampleCount => (int)Math.Min(SampleIndex + 1, HistoryLength);

        /// <summary>Running processes plus exited ones that still have history in the window.</summary>
        public IReadOnlyList<ProcInfo> Processes => all;

        public List<ProcInfo> Added { get; } = new List<ProcInfo>();
        public List<ProcInfo> Removed { get; } = new List<ProcInfo>();
        public int LiveCount => live.Count;
        public int ProcessorCount => processorCount;

        /// <summary>False when per-process network traffic cannot be measured; those values are then all zero.</summary>
        public bool NetworkAvailable => network.Available;

        /// <summary>The trace, for naming the addresses processes talk to.</summary>
        public NetworkMonitor Network => network;

        /// <summary>True when network traffic is unavailable only because the process lacks the rights.</summary>
        public bool NetworkAccessDenied => network.AccessDenied;

        /// <summary>The GPU counters, for whether they are available and which engine is busiest.</summary>
        public GpuMonitor Gpu => gpu;

        /// <summary>Physical memory in bytes.</summary>
        public long TotalPhysicalMemory { get; } = NativeMethods.GetTotalPhysicalMemory();

        /// <summary>
        /// Memory in use that no process holds privately: kernel pools, shared libraries and mapped
        /// files, page tables and driver allocations. Together with the processes' private working sets
        /// it makes up Task Manager's "In use". Not one of <see cref="Processes"/>; only memory is set.
        /// </summary>
        public ProcInfo SystemMemory { get; } = new ProcInfo
        {
            Pid = -1, Name = "System & shared", DisplayName = "System & shared",
            Details = "Kernel, shared libraries and files, page tables, drivers"
        };

        /// <summary>
        /// Processor time spent on hardware interrupts and deferred procedure calls, which no process is
        /// charged for. Not one of <see cref="Processes"/>; only CPU is set.
        /// </summary>
        public ProcInfo Interrupts { get; } = new ProcInfo
        {
            Pid = -2, Name = "Interrupts & DPCs", DisplayName = "Interrupts & DPCs",
            Details = "Hardware and drivers, charged to no process"
        };

        /// <summary>The band for what the metric's processes leave out, or null when it has none.</summary>
        public ProcInfo SystemLayer(Metric metric) =>
            metric == Metric.Memory ? SystemMemory : metric == Metric.Cpu ? Interrupts : null;

        public ProcessMonitor()
        {
            buffer = Marshal.AllocHGlobal(bufferSize);
        }

        public DateTime SampleTime(long sample) => sampleTimes[(int)(sample % HistoryLength)];

        /// <summary>
        /// When a sample was taken, in seconds on a steady clock. Samples are not evenly spaced: the
        /// refresh interval can change, and timers drift.
        /// </summary>
        public double SampleSeconds(long sample) => sampleSeconds[(int)(sample % HistoryLength)];

        public ProcInfo FindLive(int pid) => live.TryGetValue(pid, out ProcInfo p) ? p : null;

        public void Sample()
        {
            long timestamp = Stopwatch.GetTimestamp();
            double elapsed100ns = lastTimestamp == 0 ? 0 : (timestamp - lastTimestamp) * 1e7 / Stopwatch.Frequency;
            double cpuCapacity = elapsed100ns * processorCount;
            lastTimestamp = timestamp;

            int status;
            while ((status = NativeMethods.NtQuerySystemInformation(NativeMethods.SystemProcessInformation,
                       buffer, bufferSize, out int needed)) == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
            {
                bufferSize = Math.Max(needed, bufferSize) + (1 << 16);
                buffer = Marshal.ReAllocHGlobal(buffer, (IntPtr)bufferSize);
            }
            if (status < 0)
                throw new InvalidOperationException("NtQuerySystemInformation failed: 0x" + status.ToString("X8"));

            Dictionary<int, long> traffic = network.Drain();
            Dictionary<NetworkMonitor.Flow, NetworkMonitor.FlowBytes> flows = network.DrainFlows();
            gpu.Sample(gpuUsage, gpuMemory);
            double seconds = elapsed100ns / 1e7;

            SampleIndex++;
            int slot = (int)(SampleIndex % HistoryLength);
            sampleTimes[slot] = DateTime.Now;
            sampleSeconds[slot] = (double)timestamp / Stopwatch.Frequency;
            Added.Clear();
            Removed.Clear();

            long privateTotal = 0;
            IntPtr entry = buffer;
            while (true)
            {
                var spi = Marshal.PtrToStructure<NativeMethods.SYSTEM_PROCESS_INFORMATION>(entry);
                int pid = (int)spi.UniqueProcessId.ToInt64();
                long cpuTime = spi.UserTime + spi.KernelTime;

                if (!live.TryGetValue(pid, out ProcInfo p) || p.CreateTime != spi.CreateTime)
                {
                    if (p != null)
                    {
                        // The PID was reused between two samples.
                        p.Alive = false;
                        Removed.Add(p);
                    }
                    p = CreateProcess(pid, ref spi);
                    // A process born since the previous sample spent all of its CPU time in this interval.
                    p.LastCpuTime = SampleIndex > 0 && spi.CreateTime > lastSampleFileTime ? 0 : cpuTime;
                    live[pid] = p;
                    all.Add(p);
                    Added.Add(p);
                }

                double cpu = cpuCapacity > 0 ? (cpuTime - p.LastCpuTime) * 100.0 / cpuCapacity : 0;
                p.Cpu = Math.Max(0, Math.Min(100, cpu));
                p.LastCpuTime = cpuTime;
                p.Memory = spi.WorkingSetPrivateSize;
                p.LastSample = SampleIndex;
                // The idle process "uses" whatever nobody else does, so it stays out of the CPU graph.
                p.CpuHistory[slot] = pid == 0 ? 0f : (float)p.Cpu;
                p.MemHistory[slot] = p.Memory / 1048576f;
                privateTotal += p.Memory;
                traffic.TryGetValue(pid, out long bytes);
                p.Network = seconds > 0 ? bytes / 1024.0 / seconds : 0;
                p.NetHistory[slot] = (float)p.Network;
                gpuUsage.TryGetValue(pid, out p.Gpu);
                p.GpuHistory[slot] = (float)p.Gpu;
                gpuMemory.TryGetValue(pid, out p.GpuMemory);
                p.GpuMemHistory[slot] = p.GpuMemory / 1048576f;

                if (spi.NextEntryOffset == 0) break;
                entry = IntPtr.Add(entry, (int)spi.NextEntryOffset);
            }

            SystemMemory.Memory = Math.Max(0, NativeMethods.GetMemoryInUse() - privateTotal);
            SystemMemory.MemHistory[slot] = SystemMemory.Memory / 1048576f;
            SystemMemory.LastSample = SampleIndex;

            long interruptTime = NativeMethods.GetInterruptAndDpcTime(processorCount);
            double interrupts = cpuCapacity > 0 && lastInterruptTime > 0 ? (interruptTime - lastInterruptTime) * 100.0 / cpuCapacity : 0;
            lastInterruptTime = interruptTime;
            Interrupts.Cpu = Math.Max(0, Math.Min(100, interrupts));
            Interrupts.CpuHistory[slot] = (float)Interrupts.Cpu;
            Interrupts.LastSample = SampleIndex;

            // Traffic by endpoint goes to the processes as they now stand, new ones included.
            if (flows.Count > 0)
            {
                DateTime now = DateTime.Now;
                foreach (KeyValuePair<NetworkMonitor.Flow, NetworkMonitor.FlowBytes> flow in flows)
                    if (live.TryGetValue(flow.Key.Pid, out ProcInfo owner))
                        owner.AddTraffic(flow.Key.Remote, flow.Value.Sent, flow.Value.Received, now);
            }

            foreach (ProcInfo p in all)
            {
                if (p.Alive && p.LastSample != SampleIndex)
                {
                    p.Alive = false;
                    live.Remove(p.Pid);
                    Removed.Add(p);
                }
            }
            long oldest = SampleIndex - HistoryLength + 1;
            all.RemoveAll(p => !p.Alive && p.LastSample < oldest);
            lastSampleFileTime = DateTime.UtcNow.ToFileTimeUtc();
        }

        private ProcInfo CreateProcess(int pid, ref NativeMethods.SYSTEM_PROCESS_INFORMATION spi)
        {
            string name = spi.ImageName.Buffer != IntPtr.Zero
                ? Marshal.PtrToStringUni(spi.ImageName.Buffer, spi.ImageName.Length / 2)
                : null;
            if (string.IsNullOrEmpty(name))
                name = pid == 0 ? "System Idle Process" : pid == 4 ? "System" : "<unknown>";

            string path = NativeMethods.GetImagePath(pid);
            string commandLine = pid == 0 || pid == 4 ? null : NativeMethods.GetCommandLine(pid);
            var parentPid = (int)spi.InheritedFromUniqueProcessId.ToInt64();
            live.TryGetValue(parentPid, out ProcInfo parent);
            string role = ProcessRoles.RoleOf(name, commandLine, (int)spi.SessionId, parent);
            if (ProcessRoles.IsChromiumHelper(commandLine) && parent != null && parent.Role == null && string.Equals(parent.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                // Its helpers are what show a program's first process to be the one in charge.
                parent.Role = "Main process";
                parent.RefreshDetails();
            }
            var process = new ProcInfo
            {
                Pid = pid,
                ParentPid = parentPid,
                Name = name,
                Path = path,
                CommandLine = commandLine,
                Arguments = ArgumentsOf(commandLine, path),
                CreateTime = spi.CreateTime,
                Color = ColorFor(name, pid),
                FirstSample = SampleIndex,
                Role = role
            };
            process.RefreshDetails();
            return process;
        }

        // Drops the program name that a command line starts with.
        private static string ArgumentsOf(string commandLine, string path)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return "";
            string text = commandLine.TrimStart();
            int end;
            if (text[0] == '"')
            {
                end = text.IndexOf('"', 1);
                end = end < 0 ? text.Length : end + 1;
            }
            else if (path != null && text.StartsWith(path, StringComparison.OrdinalIgnoreCase))
            {
                end = path.Length;      // an unquoted path, which may contain spaces
            }
            else
            {
                end = text.IndexOfAny(new[] { ' ', '\t' });
                if (end < 0) end = text.Length;
            }
            return text.Substring(end).Trim();
        }

        // Hue follows the image name, so every instance of a program sits in one colour family;
        // lightness varies with the PID so neighbouring instances can still be told apart.
        private static Color ColorFor(string name, int pid)
        {
            uint hash = 2166136261;
            foreach (char c in name)
                hash = unchecked((hash ^ (uint)char.ToLowerInvariant(c)) * 16777619u);
            double hue = hash % 360;
            double lightness = 0.46 + (pid / 4 % 5) * 0.04;
            return FromHsl(hue, 0.58, lightness);
        }

        private static Color FromHsl(double h, double s, double l)
        {
            double c = (1 - Math.Abs(2 * l - 1)) * s;
            double hp = h / 60.0;
            double x = c * (1 - Math.Abs(hp % 2 - 1));
            double r = 0, g = 0, b = 0;
            switch ((int)hp)
            {
                case 0: r = c; g = x; break;
                case 1: r = x; g = c; break;
                case 2: g = c; b = x; break;
                case 3: g = x; b = c; break;
                case 4: r = x; b = c; break;
                default: r = c; b = x; break;
            }
            double m = l - c / 2;
            return Color.FromArgb((int)Math.Round((r + m) * 255), (int)Math.Round((g + m) * 255), (int)Math.Round((b + m) * 255));
        }

        public void Dispose()
        {
            network.Dispose();
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }
        }
    }
}
