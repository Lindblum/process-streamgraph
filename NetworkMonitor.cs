using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace ProcessStreamgraph
{
    /// <summary>
    /// Counts bytes sent and received per process from the Microsoft-Windows-Kernel-Network trace
    /// events (ETW), the only source Windows offers for per-process network traffic. Starting the
    /// trace session needs administrator rights or membership of the Performance Log Users group.
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

        // Data sent and received: TCP over IPv4 (10, 11) and IPv6 (26, 27), UDP over IPv4 (42, 43) and
        // IPv6 (58, 59). The provider's other events are connection bookkeeping.
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
        private const int RecordEventId = 40, RecordUserDataLength = 86, RecordUserData = 96;

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
        private ulong traceHandle = INVALID_PROCESSTRACE_HANDLE;
        private bool sessionStarted;

        /// <summary>True when the trace session is running and traffic is being counted.</summary>
        public bool Available { get; }

        /// <summary>True when the session could not be started for lack of rights.</summary>
        public bool AccessDenied { get; }

        public NetworkMonitor()
        {
            callback = OnEvent;
            if (!Environment.Is64BitProcess) return;

            StopStaleSessions();
            uint status = StartSession(out ulong session);
            if (status == ERROR_SUCCESS)
            {
                sessionStarted = true;
                Guid provider = KernelNetworkProvider;
                status = EnableTraceEx2(session, ref provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    TRACE_LEVEL_INFORMATION, 0, 0, 0, IntPtr.Zero);
            }
            AccessDenied = status == ERROR_ACCESS_DENIED;
            if (status != ERROR_SUCCESS)
            {
                Dispose();
                return;
            }

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
            Available = true;
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

        private void OnEvent(IntPtr record)
        {
            if (Array.IndexOf(DataEvents, Marshal.ReadInt16(record, RecordEventId)) < 0) return;
            if ((ushort)Marshal.ReadInt16(record, RecordUserDataLength) < 8) return;

            // All of these events start with the owning process ID followed by the byte count.
            IntPtr data = Marshal.ReadIntPtr(record, RecordUserData);
            int pid = Marshal.ReadInt32(data, 0);
            uint size = (uint)Marshal.ReadInt32(data, 4);
            lock (gate)
            {
                pending.TryGetValue(pid, out long bytes);
                pending[pid] = bytes + size;
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
            if (!sessionStarted) return;
            sessionStarted = false;
            StopSession(SessionName);
            if (traceHandle != INVALID_PROCESSTRACE_HANDLE) CloseTrace(traceHandle);
        }
    }
}
