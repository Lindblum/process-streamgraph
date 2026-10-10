using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace ProcessStreamgraph
{
    /// <summary>
    /// Counts bytes sent and received per process, and per remote endpoint, from the
    /// Microsoft-Windows-Kernel-Network trace events (ETW), the only source Windows offers for
    /// per-process network traffic; that provider needs administrator rights. The same session also
    /// listens to the DNS client's events, which say which names each process looked up and the
    /// addresses that came back; those need only membership of the Performance Log Users group.
    /// </summary>
    internal sealed class NetworkMonitor : IDisposable
    {
        // Each instance runs its own session, named after its process ID, so that a second copy of the
        // program cannot take over or shut down the first one's.
        private const string SessionPrefix = "ProcessStreamgraph-Network-";
        private static readonly int OwnPid = Process.GetCurrentProcess().Id;
        private static readonly string SessionName = SessionPrefix + OwnPid;

        private const uint ERROR_SUCCESS = 0;
        private const uint ERROR_ACCESS_DENIED = 5;
        private const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
        private const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
        private const byte TRACE_LEVEL_INFORMATION = 4;
        private const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
        private const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
        private const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
        private const uint EVENT_TRACE_CONTROL_STOP = 1;
        private const ulong INVALID_PROCESSTRACE_HANDLE = ulong.MaxValue;

        private static readonly Guid KernelNetworkProvider = new Guid("7DD42A49-5329-4832-8DFD-43D979153A88");
        private static readonly Guid DnsClientProvider = new Guid("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
        private const short DnsQueryCompleted = 3008;

        // Data sent and received: TCP over IPv4 (10, 11) and IPv6 (26, 27), UDP over IPv4 (42, 43) and
        // IPv6 (58, 59). The provider's other events are connection bookkeeping. Each starts with the
        // process ID, the byte count, the destination and source addresses, then their ports.
        private static readonly short[] DataEvents = { 10, 11, 26, 27, 42, 43, 58, 59 };

        [StructLayout(LayoutKind.Sequential)]
        private struct WNODE_HEADER
        {
            public uint BufferSize;
            public uint ProviderId;
            public ulong HistoricalContext;
            public long TimeStamp;
            public Guid Guid;
            public uint ClientContext;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_TRACE_PROPERTIES
        {
            public WNODE_HEADER Wnode;
            public uint BufferSize;
            public uint MinimumBuffers;
            public uint MaximumBuffers;
            public uint MaximumFileSize;
            public uint LogFileMode;
            public uint FlushTimer;
            public uint EnableFlags;
            public int AgeLimit;
            public uint NumberOfBuffers;
            public uint FreeBuffers;
            public uint EventsLost;
            public uint BuffersWritten;
            public uint LogBuffersLost;
            public uint RealTimeBuffersLost;
            public IntPtr LoggerThreadId;
            public uint LogFileNameOffset;
            public uint LoggerNameOffset;
        }

        // EVENT_TRACE_LOGFILEW on 64-bit Windows; only the fields that have to be set are declared.
        [StructLayout(LayoutKind.Explicit, Size = 448)]
        private struct EVENT_TRACE_LOGFILE
        {
            [FieldOffset(8)] public IntPtr LoggerName;
            [FieldOffset(28)] public uint ProcessTraceMode;
            [FieldOffset(424)] public IntPtr EventRecordCallback;
        }

        // Offsets into EVENT_RECORD on 64-bit Windows.
        private const int RecordProcessId = 12, RecordProviderId = 24, RecordEventId = 40, RecordUserDataLength = 86, RecordUserData = 96;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void EventRecordCallback(IntPtr eventRecord);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint StartTraceW(out ulong sessionHandle, string sessionName, IntPtr properties);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint ControlTraceW(ulong sessionHandle, string sessionName, IntPtr properties, uint control);

        [DllImport("advapi32.dll")]
        private static extern uint QueryAllTracesW([In, Out] IntPtr[] properties, uint count, out uint sessionCount);

        [DllImport("advapi32.dll")]
        private static extern uint EnableTraceEx2(ulong sessionHandle, ref Guid providerId, uint controlCode, byte level,
            ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, IntPtr enableParameters);

        [DllImport("advapi32.dll")]
        private static extern ulong OpenTraceW(ref EVENT_TRACE_LOGFILE logfile);

        [DllImport("advapi32.dll")]
        private static extern uint ProcessTrace(ulong[] handles, uint count, IntPtr startTime, IntPtr endTime);

        [DllImport("advapi32.dll")]
        private static extern uint CloseTrace(ulong traceHandle);

        private readonly object gate = new object();
        private readonly EventRecordCallback callback;     // held so the delegate outlives the native call
        private Dictionary<int, long> pending = new Dictionary<int, long>();
        private Dictionary<int, long> spare = new Dictionary<int, long>();
        private Dictionary<Flow, FlowBytes> pendingFlows = new Dictionary<Flow, FlowBytes>();
        private Dictionary<Flow, FlowBytes> spareFlows = new Dictionary<Flow, FlowBytes>();
        private ulong traceHandle = INVALID_PROCESSTRACE_HANDLE;
        private bool sessionStarted;

        // This computer's own addresses, to tell which end of a connection is the far one.
        private volatile HashSet<IpAddr> localAddresses = LocalAddresses();

        // The name each address was last looked up under: by process and address, then by address alone.
        private readonly object namesGate = new object();
        private readonly Dictionary<KeyValuePair<int, IpAddr>, string> namesByProcess = new Dictionary<KeyValuePair<int, IpAddr>, string>();
        private readonly Dictionary<IpAddr, string> names = new Dictionary<IpAddr, string>();
        private const int MaxNames = 100000;

        /// <summary>One process's traffic with one remote endpoint.</summary>
        public struct Flow : IEquatable<Flow>
        {
            public int Pid;
            public Endpoint Remote;
            public bool Equals(Flow other) => Pid == other.Pid && Remote.Equals(other.Remote);
            public override bool Equals(object obj) => obj is Flow other && Equals(other);
            public override int GetHashCode() => Pid * 7919 ^ Remote.GetHashCode();
        }

        public sealed class FlowBytes
        {
            public long Sent, Received;
        }

        /// <summary>True when the trace session is running and traffic is being counted.</summary>
        public bool Available { get; }

        /// <summary>True when DNS lookups are being followed, so addresses can be named.</summary>
        public bool NamesAvailable { get; }

        /// <summary>True when the session could not be started for lack of rights.</summary>
        public bool AccessDenied { get; }

        public NetworkMonitor()
        {
            callback = OnEvent;
            if (!Environment.Is64BitProcess) return;

            StopStaleSessions();
            uint status = StartSession(out ulong session), dnsStatus = status;
            if (status == ERROR_SUCCESS)
            {
                sessionStarted = true;
                Guid provider = KernelNetworkProvider;
                status = EnableTraceEx2(session, ref provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    TRACE_LEVEL_INFORMATION, 0, 0, 0, IntPtr.Zero);
                Guid dns = DnsClientProvider;
                dnsStatus = EnableTraceEx2(session, ref dns, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    TRACE_LEVEL_INFORMATION, 0, 0, 0, IntPtr.Zero);
            }
            AccessDenied = status == ERROR_ACCESS_DENIED;
            // Without the rights for traffic, the session still serves for following DNS lookups.
            if (status != ERROR_SUCCESS && dnsStatus != ERROR_SUCCESS)
            {
                Dispose();
                return;
            }
            NetworkChange.NetworkAddressChanged += OnAddressChanged;

            IntPtr name = Marshal.StringToHGlobalUni(SessionName);
            try
            {
                var logfile = new EVENT_TRACE_LOGFILE
                {
                    LoggerName = name,
                    ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
                    EventRecordCallback = Marshal.GetFunctionPointerForDelegate(callback)
                };
                traceHandle = OpenTraceW(ref logfile);
            }
            finally
            {
                Marshal.FreeHGlobal(name);
            }
            if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
            {
                Dispose();
                return;
            }

            // ProcessTrace blocks, delivering events to the callback, until the session is stopped.
            new Thread(() => ProcessTrace(new[] { traceHandle }, 1, IntPtr.Zero, IntPtr.Zero))
            {
                IsBackground = true,
                Name = "Network trace"
            }.Start();
            Available = status == ERROR_SUCCESS;
            NamesAvailable = dnsStatus == ERROR_SUCCESS;
        }

        private void OnAddressChanged(object sender, EventArgs e) => localAddresses = LocalAddresses();

        private static HashSet<IpAddr> LocalAddresses()
        {
            var set = new HashSet<IpAddr> { IpAddr.From(IPAddress.Loopback), IpAddr.From(IPAddress.IPv6Loopback) };
            try
            {
                foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
                    foreach (UnicastIPAddressInformation address in adapter.GetIPProperties().UnicastAddresses)
                        set.Add(IpAddr.From(address.Address));
            }
            catch (NetworkInformationException)
            {
            }
            return set;
        }

        /// <summary>Bytes sent and received per process and remote endpoint since the previous call.</summary>
        public Dictionary<Flow, FlowBytes> DrainFlows()
        {
            lock (gate)
            {
                Dictionary<Flow, FlowBytes> result = pendingFlows;
                spareFlows.Clear();
                pendingFlows = spareFlows;
                spareFlows = result;
                return result;
            }
        }

        /// <summary>The domain a process (or failing that, any process) last looked up and got this address for.</summary>
        public string NameFor(int pid, IpAddr address)
        {
            lock (namesGate)
            {
                if (namesByProcess.TryGetValue(new KeyValuePair<int, IpAddr>(pid, address), out string name)) return name;
                return names.TryGetValue(address, out name) ? name : null;
            }
        }

        /// <summary>Bytes sent plus received per process ID since the previous call.</summary>
        public Dictionary<int, long> Drain()
        {
            lock (gate)
            {
                Dictionary<int, long> result = pending;
                spare.Clear();
                pending = spare;
                spare = result;
                return result;
            }
        }

        private static readonly long DnsProviderLow = BitConverter.ToInt64(DnsClientProvider.ToByteArray(), 0);

        private void OnEvent(IntPtr record)
        {
            short id = Marshal.ReadInt16(record, RecordEventId);
            int length = (ushort)Marshal.ReadInt16(record, RecordUserDataLength);
            IntPtr data = Marshal.ReadIntPtr(record, RecordUserData);
            if (id == DnsQueryCompleted)
            {
                if (Marshal.ReadInt64(record, RecordProviderId) == DnsProviderLow)
                    OnDnsAnswer(Marshal.ReadInt32(record, RecordProcessId), data, length);
                return;
            }
            if (Array.IndexOf(DataEvents, id) < 0) return;
            if (length < 8) return;

            // All of these events start with the owning process ID followed by the byte count.
            int pid = Marshal.ReadInt32(data, 0);
            uint size = (uint)Marshal.ReadInt32(data, 4);
            bool v6 = id == 26 || id == 27 || id == 58 || id == 59;
            bool sent = id == 10 || id == 26 || id == 42 || id == 58;
            bool udp = id >= 42;
            bool hasEnds = length >= (v6 ? 44 : 20);
            var flow = new Flow { Pid = pid };
            if (hasEnds)
            {
                IpAddr destination, source;
                int ports;
                if (v6)
                {
                    destination = IpAddr.V6Raw((ulong)Marshal.ReadInt64(data, 8), (ulong)Marshal.ReadInt64(data, 16));
                    source = IpAddr.V6Raw((ulong)Marshal.ReadInt64(data, 24), (ulong)Marshal.ReadInt64(data, 32));
                    ports = 40;
                }
                else
                {
                    destination = IpAddr.V4((uint)Marshal.ReadInt32(data, 8));
                    source = IpAddr.V4((uint)Marshal.ReadInt32(data, 12));
                    ports = 16;
                }
                // The far end is the destination, unless that is one of this computer's own addresses
                // and the source is not. Ports are in network byte order.
                HashSet<IpAddr> local = localAddresses;
                bool farIsSource = local.Contains(destination) && !local.Contains(source);
                int portOffset = ports + (farIsSource ? 2 : 0);
                ushort port = (ushort)((Marshal.ReadByte(data, portOffset) << 8) | Marshal.ReadByte(data, portOffset + 1));
                flow.Remote = new Endpoint(farIsSource ? source : destination, port, udp);
            }
            lock (gate)
            {
                pending.TryGetValue(pid, out long bytes);
                pending[pid] = bytes + size;
                if (!hasEnds) return;
                if (!pendingFlows.TryGetValue(flow, out FlowBytes counts)) pendingFlows[flow] = counts = new FlowBytes();
                if (sent) counts.Sent += size;
                else counts.Received += size;
            }
        }

        // DNS query completed: the name, then the record type (4 bytes), options (8) and status (4),
        // then the answers as text, such as "::ffff:104.20.23.154;::ffff:172.66.147.243;".
        private void OnDnsAnswer(int pid, IntPtr data, int length)
        {
            if (length < 20 || pid == OwnPid) return;
            string name = Marshal.PtrToStringUni(data);
            int offset = (name.Length + 1) * 2;
            if (name.Length == 0 || offset + 16 + 2 > length) return;
            if (Marshal.ReadInt32(data, offset + 12) != 0) return;     // the lookup failed
            string answers = Marshal.PtrToStringUni(IntPtr.Add(data, offset + 16));
            if (string.IsNullOrEmpty(answers)) return;
            lock (namesGate)
            {
                if (names.Count > MaxNames)
                {
                    names.Clear();
                    namesByProcess.Clear();
                }
                foreach (string answer in answers.Split(';'))
                {
                    // Other kinds of answer, such as "type: 5 alias.example.net" for an alias, are skipped.
                    if (!IPAddress.TryParse(answer.Trim(), out IPAddress address)) continue;
                    IpAddr key = IpAddr.From(address);
                    names[key] = name;
                    namesByProcess[new KeyValuePair<int, IpAddr>(pid, key)] = name;
                }
            }
        }

        private static uint StartSession(out ulong session)
        {
            ulong handle = 0;
            uint status = WithProperties(properties => StartTraceW(out handle, SessionName, properties));
            session = handle;
            return status;
        }

        private static void StopSession(string name)
        {
            WithProperties(properties => ControlTraceW(0, name, properties, EVENT_TRACE_CONTROL_STOP));
        }

        /// <summary>
        /// Stops sessions left behind by instances that were killed or crashed; a trace session
        /// otherwise lives on until the next restart of Windows.
        /// </summary>
        private static void StopStaleSessions()
        {
            const int maxSessions = 64, nameBytes = 2 * 1024;
            int headerSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>();
            int totalSize = headerSize + 2 * nameBytes;     // session name, then log file name
            var buffers = new IntPtr[maxSessions];
            try
            {
                for (int i = 0; i < maxSessions; i++)
                {
                    buffers[i] = Marshal.AllocHGlobal(totalSize);
                    for (int offset = 0; offset < totalSize; offset += 4) Marshal.WriteInt32(buffers[i], offset, 0);
                    var properties = new EVENT_TRACE_PROPERTIES
                    {
                        Wnode = new WNODE_HEADER { BufferSize = (uint)totalSize },
                        LoggerNameOffset = (uint)headerSize,
                        LogFileNameOffset = (uint)(headerSize + nameBytes)
                    };
                    Marshal.StructureToPtr(properties, buffers[i], false);
                }
                QueryAllTracesW(buffers, maxSessions, out uint count);
                for (int i = 0; i < count && i < maxSessions; i++)
                {
                    string name = Marshal.PtrToStringUni(IntPtr.Add(buffers[i], headerSize));
                    if (name == null || !name.StartsWith(SessionPrefix, StringComparison.Ordinal)) continue;
                    if (!int.TryParse(name.Substring(SessionPrefix.Length), out int pid)) continue;
                    // A session under this process's own ID predates it: the ID has been reused.
                    if (pid == OwnPid || !IsRunningInstance(pid)) StopSession(name);
                }
            }
            finally
            {
                foreach (IntPtr buffer in buffers)
                    if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }

        private static bool IsRunningInstance(int pid)
        {
            try
            {
                using (Process other = Process.GetProcessById(pid))
                using (Process self = Process.GetCurrentProcess())
                    return other.ProcessName == self.ProcessName;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        private static uint WithProperties(Func<IntPtr, uint> call)
        {
            int headerSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>();
            int totalSize = headerSize + 2 * 1024;     // room after the header for the session name
            IntPtr buffer = Marshal.AllocHGlobal(totalSize);
            try
            {
                for (int i = 0; i < totalSize; i += 4) Marshal.WriteInt32(buffer, i, 0);
                var properties = new EVENT_TRACE_PROPERTIES
                {
                    Wnode = new WNODE_HEADER
                    {
                        BufferSize = (uint)totalSize,
                        Guid = Guid.NewGuid(),
                        ClientContext = 1,      // timestamps from the performance counter
                        Flags = WNODE_FLAG_TRACED_GUID
                    },
                    BufferSize = 64,            // KB
                    LogFileMode = EVENT_TRACE_REAL_TIME_MODE,
                    FlushTimer = 1,             // seconds, so traffic shows up in the sample it happened in
                    LoggerNameOffset = (uint)headerSize
                };
                Marshal.StructureToPtr(properties, buffer, false);
                return call(buffer);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public void Dispose()
        {
            NetworkChange.NetworkAddressChanged -= OnAddressChanged;
            if (!sessionStarted) return;
            sessionStarted = false;
            StopSession(SessionName);
            if (traceHandle != INVALID_PROCESSTRACE_HANDLE) CloseTrace(traceHandle);
        }
    }
}
