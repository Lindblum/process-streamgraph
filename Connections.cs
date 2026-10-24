using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace ProcessStreamgraph
{
    /// <summary>
    /// An IPv4 or IPv6 address held as plain numbers, so the trace callback can count traffic by
    /// address without creating objects. The bytes are kept in network order, as they arrive.
    /// </summary>
    internal readonly struct IpAddr : IEquatable<IpAddr>
    {
        public readonly ulong Hi, Lo;       // IPv4: the four bytes in the low half of Lo
        public readonly bool V6;

        private IpAddr(ulong hi, ulong lo, bool v6)
        {
            Hi = hi;
            Lo = lo;
            V6 = v6;
        }

        public static IpAddr V4(uint raw) => new IpAddr(0, raw, false);

        /// <summary>An IPv6 address; one that only wraps an IPv4 address (::ffff:a.b.c.d) becomes that address.</summary>
        public static IpAddr V6Raw(ulong hi, ulong lo) =>
            hi == 0 && (uint)lo == 0xFFFF0000u ? V4((uint)(lo >> 32)) : new IpAddr(hi, lo, true);

        public static IpAddr From(IPAddress address)
        {
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            byte[] bytes = address.GetAddressBytes();
            return bytes.Length == 4
                ? V4(BitConverter.ToUInt32(bytes, 0))
                : V6Raw(BitConverter.ToUInt64(bytes, 0), BitConverter.ToUInt64(bytes, 8));
        }

        public IPAddress ToIPAddress()
        {
            if (!V6) return new IPAddress((long)(uint)Lo);
            var bytes = new byte[16];
            Array.Copy(BitConverter.GetBytes(Hi), 0, bytes, 0, 8);
            Array.Copy(BitConverter.GetBytes(Lo), 0, bytes, 8, 8);
            return new IPAddress(bytes);
        }

        public bool Equals(IpAddr other) => Hi == other.Hi && Lo == other.Lo && V6 == other.V6;
        public override bool Equals(object obj) => obj is IpAddr other && Equals(other);
        public override int GetHashCode() => unchecked((int)(Hi ^ (Hi >> 32) ^ Lo ^ (Lo >> 32)) * 31 + (V6 ? 1 : 0));
    }

    /// <summary>The far end of a connection: address, port and protocol.</summary>
    internal readonly struct Endpoint : IEquatable<Endpoint>
    {
        public readonly IpAddr Address;
        public readonly ushort Port;
        public readonly bool Udp;

        public Endpoint(IpAddr address, ushort port, bool udp)
        {
            Address = address;
            Port = port;
            Udp = udp;
        }

        public bool Equals(Endpoint other) => Port == other.Port && Udp == other.Udp && Address.Equals(other.Address);
        public override bool Equals(object obj) => obj is Endpoint other && Equals(other);
        public override int GetHashCode() => Address.GetHashCode() * 397 ^ Port * 2 ^ (Udp ? 1 : 0);
    }

    /// <summary>Traffic between a process and one remote endpoint since this program started watching.</summary>
    internal sealed class Connection
    {
        public Endpoint Endpoint;
        public long Sent, Received;     // bytes
        public DateTime LastActive;     // local time of the last traffic, or when it was last seen open
        public string State;            // TCP state from the connection table, when that is the source
        // Bytes moved in each sample that had any traffic, oldest first; quiet samples are left out,
        // since most endpoints are idle most of the time.
        public readonly List<Moved> History = new List<Moved>();

        internal void Record(long sample, long sent, long received, long oldest)
        {
            int last = History.Count - 1;
            if (last >= 0 && History[last].Sample == sample)
                History[last] = new Moved(sample, History[last].Sent + sent, History[last].Received + received);
            else History.Add(new Moved(sample, sent, received));
            int stale = 0;
            while (stale < History.Count && History[stale].Sample < oldest) stale++;
            if (stale > 0) History.RemoveRange(0, stale);
        }
    }

    /// <summary>The bytes a connection moved each way in one sample.</summary>
    internal readonly struct Moved
    {
        public readonly long Sample, Sent, Received;

        public Moved(long sample, long sent, long received)
        {
            Sample = sample;
            Sent = sent;
            Received = received;
        }
    }

    /// <summary>Names, labels and the connection table, for the Connections window.</summary>
    internal static class ConnectionInfo
    {
        /// <summary>A name for addresses that have no domain: this computer, the local network, multicast.</summary>
        public static string LocalLabel(IPAddress address)
        {
            if (IPAddress.IsLoopback(address)) return "This computer";
            byte[] b = address.GetAddressBytes();
            if (b.Length == 4)
            {
                if (b[0] == 239 && b[1] == 255 && b[2] == 255 && b[3] == 250) return "Device discovery (SSDP)";
                if (b[0] == 224 && b[1] == 0 && b[2] == 0 && b[3] == 251) return "Local name lookup (mDNS)";
                if (b[0] == 224 && b[1] == 0 && b[2] == 0 && b[3] == 252) return "Local name lookup (LLMNR)";
                if (b[0] >= 224 && b[0] <= 239) return "Multicast";
                if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return "Broadcast";
                if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)) return "Local network";
                if (b[0] == 169 && b[1] == 254) return "Local network (link-local)";
                if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return "Carrier or VPN network";
                return null;
            }
            if (address.IsIPv6Multicast) return b[1] == 0x02 && b[15] == 0xfb ? "Local name lookup (mDNS)" : "Multicast";
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || (b[0] & 0xfe) == 0xfc) return "Local network";
            return null;
        }

        /// <summary>Whether an address is on the internet ("Public"), this computer or a private network ("Private"), or a group ("Multicast", "Broadcast").</summary>
        public static string Scope(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            if (b.Length == 4 ? b[0] >= 224 && b[0] <= 239 : address.IsIPv6Multicast) return "Multicast";
            if (b.Length == 4 && b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return "Broadcast";
            return LocalLabel(address) != null ? "Private" : "Public";
        }

        /// <summary>What usually runs on a port, for the common ones.</summary>
        public static string PortName(ushort port, bool udp)
        {
            switch (port)
            {
                case 443: return udp ? "HTTPS (QUIC)" : "HTTPS";
                case 80: return "HTTP";
                case 53: return "DNS";
                case 853: return "DNS over TLS";
                case 123: return "Time (NTP)";
                case 5353: return "mDNS";
                case 5355: return "LLMNR";
                case 1900: return "SSDP";
                case 3478: case 19302: return "Call/STUN";
                case 22: return "SSH";
                case 25: case 465: case 587: return "Mail (SMTP)";
                case 993: return "Mail (IMAP)";
                case 995: return "Mail (POP3)";
                case 3389: return "Remote Desktop";
                case 445: return "File sharing (SMB)";
                case 137: case 138: case 139: return "NetBIOS";
                case 5228: return "Google push";
                case 27015: case 27036: return "Steam";
                case 8080: case 8000: return "HTTP (alternate)";
                case 8443: return "HTTPS (alternate)";
                case 21: return "File transfer (FTP)";
                case 23: return "Telnet";
                case 143: return "Mail (IMAP)";
                case 110: return "Mail (POP3)";
                case 5222: return "Chat (XMPP)";
                case 5223: return "Apple push";
                case 1883: case 8883: return "IoT messages (MQTT)";
                case 500: case 4500: return "VPN (IPsec)";
                case 1194: return "VPN (OpenVPN)";
                case 51820: return "VPN (WireGuard)";
                case 1701: return "VPN (L2TP)";
                case 1723: return "VPN (PPTP)";
                case 7680: return "Windows Update sharing";
                case 5938: return "TeamViewer";
                case 5900: return "Remote screen (VNC)";
                case 3074: return "Xbox Live";
                case 4070: return "Spotify";
                case 8009: return "Chromecast";
                case 554: return "Video stream (RTSP)";
                case 3306: return "Database (MySQL)";
                case 5432: return "Database (PostgreSQL)";
                case 1433: return "Database (SQL Server)";
                case 6379: return "Database (Redis)";
                case 27017: return "Database (MongoDB)";
                case 389: case 636: return "Directory (LDAP)";
                case 88: return "Sign-in (Kerberos)";
                case 67: case 68: return "Network setup (DHCP)";
                case 161: case 162: return "Device management (SNMP)";
                case 9100: case 631: return "Printing";
                case 6881: case 6882: case 6883: case 6884: case 6885: case 6886: case 6887: case 6888: case 6889: return "BitTorrent";
                default: return null;
            }
        }

        // Reverse lookups (address -> registered host name), the last resort for naming an address.
        // They are network queries, so each address is asked once, a few at a time, in the background.
        private static readonly Dictionary<IpAddr, string> reverse = new Dictionary<IpAddr, string>();
        private static readonly Queue<IpAddr> reverseQueue = new Queue<IpAddr>();
        private static int reverseWorkers;

        /// <summary>The reverse-lookup name of an address, or null while it is unknown; asks for it if not yet asked.</summary>
        public static string ReverseName(IpAddr address)
        {
            lock (reverse)
            {
                if (reverse.TryGetValue(address, out string name)) return name;
                reverse[address] = null;
                reverseQueue.Enqueue(address);
                if (reverseWorkers < 4)
                {
                    reverseWorkers++;
                    ThreadPool.QueueUserWorkItem(_ => ReverseWorker());
                }
                return null;
            }
        }

        private static void ReverseWorker()
        {
            while (true)
            {
                IpAddr next;
                lock (reverse)
                {
                    if (reverseQueue.Count == 0)
                    {
                        reverseWorkers--;
                        return;
                    }
                    next = reverseQueue.Dequeue();
                }
                string name = "";
                try
                {
                    string host = Dns.GetHostEntry(next.ToIPAddress()).HostName;
                    // A lookup that finds nothing hands back the address itself.
                    if (!IPAddress.TryParse(host, out _)) name = host;
                }
                catch (SocketException)
                {
                }
                catch (ArgumentException)
                {
                }
                lock (reverse) reverse[next] = name;
            }
        }

        private const int AF_INET = 2, AF_INET6 = 23, TCP_TABLE_OWNER_PID_ALL = 5;

        [DllImport("iphlpapi.dll")]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, int reserved);

        private static readonly string[] TcpStates =
        {
            "", "Closed", "Listening", "Opening", "Opening", "Open", "Closing", "Closing", "Closing", "Closing", "Closing", "Closing", "Closing"
        };

        /// <summary>
        /// Open TCP connections of the given processes, from the table Windows keeps for everyone to read.
        /// It needs no special rights but says nothing of how much was sent, nor anything of UDP.
        /// </summary>
        public static List<KeyValuePair<int, Connection>> TcpConnections(HashSet<int> pids)
        {
            var result = new List<KeyValuePair<int, Connection>>();
            foreach (int family in new[] { AF_INET, AF_INET6 })
            {
                int size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
                if (size == 0) continue;
                size += 4096;
                IntPtr table = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetExtendedTcpTable(table, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0) != 0) continue;
                    int count = Marshal.ReadInt32(table);
                    // MIB_TCPROW_OWNER_PID: state, local address, local port, remote address, remote port, PID.
                    // MIB_TCP6ROW_OWNER_PID: local address and scope, local port, remote address and scope,
                    // remote port, state, PID.
                    int rowSize = family == AF_INET ? 24 : 56;
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr row = IntPtr.Add(table, 4 + i * rowSize);
                        int state, pid;
                        IpAddr remote;
                        ushort port;
                        if (family == AF_INET)
                        {
                            state = Marshal.ReadInt32(row, 0);
                            remote = IpAddr.V4((uint)Marshal.ReadInt32(row, 12));
                            port = NetworkPort(Marshal.ReadInt32(row, 16));
                            pid = Marshal.ReadInt32(row, 20);
                        }
                        else
                        {
                            remote = IpAddr.V6Raw((ulong)Marshal.ReadInt64(row, 24), (ulong)Marshal.ReadInt64(row, 32));
                            port = NetworkPort(Marshal.ReadInt32(row, 44));
                            state = Marshal.ReadInt32(row, 48);
                            pid = Marshal.ReadInt32(row, 52);
                        }
                        // Listening sockets have no far end.
                        if (!pids.Contains(pid) || state == 2 || port == 0) continue;
                        result.Add(new KeyValuePair<int, Connection>(pid, new Connection
                        {
                            Endpoint = new Endpoint(remote, port, false),
                            State = state >= 0 && state < TcpStates.Length ? TcpStates[state] : "",
                            LastActive = DateTime.Now
                        }));
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(table);
                }
            }
            return result;
        }

        // Ports in the table are in network byte order in the low two bytes.
        private static ushort NetworkPort(int raw) => (ushort)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));
    }
}
