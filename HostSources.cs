using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;

namespace ProcessStreamgraph
{
    /// <summary>
    /// What the sources say about a remote host a process talks to: the malware-blocking DNS
    /// services for its domain, published lists of malware hosts and botnet servers for its domain
    /// and address, and VirusTotal when it has a key. Called on background threads.
    /// </summary>
    internal static class HostSources
    {
        public const string Cloudflare = "Cloudflare malware blocking";
        public const string Quad9 = "Quad9 threat blocking";
        public const string UrlHaus = "URLhaus";
        public const string IpLists = "Botnet and criminal network lists";

        private static SourceResult Result(string source, Safety verdict, string summary, string link = null) =>
            new SourceResult { Source = source, Verdict = verdict, Summary = summary, Link = link, Checked = DateTime.UtcNow };

        // ---- Malware-blocking DNS ----
        // Both services answer like ordinary DNS servers, except for domains on their threat lists:
        // Cloudflare's 1.1.1.2 then answers 0.0.0.0, and Quad9's 9.9.9.9 says the domain does not exist.
        // Asking Quad9's unfiltered 9.9.9.10 as well tells a blocked domain from one that is really gone.

        private static readonly IPAddress CloudflareFiltered = IPAddress.Parse("1.1.1.2");
        private static readonly IPAddress Quad9Filtered = IPAddress.Parse("9.9.9.9");
        private static readonly IPAddress Quad9Unfiltered = IPAddress.Parse("9.9.9.10");
        private const int NoError = 0, NameError = 3;

        public static SourceResult AskCloudflare(string domain)
        {
            if (!Query(CloudflareFiltered, domain, out int code, out List<IPAddress> addresses, out string error))
                return SafetySources.Failure(Cloudflare, "Could not reach Cloudflare's DNS at 1.1.1.2: " + error);
            if (addresses.Exists(a => a.Equals(IPAddress.Any)))
                return Result(Cloudflare, Safety.HighRisk, "Cloudflare's malware-blocking DNS (1.1.1.2) blocks this domain: its threat intelligence lists it as serving malware or phishing.",
                    "https://radar.cloudflare.com/domains/domain/" + domain);
            if (code == NameError)
                return Result(Cloudflare, Safety.Unrated, "The domain no longer exists, so Cloudflare has nothing to say about it.");
            if (code != NoError)
                return SafetySources.Failure(Cloudflare, "Cloudflare's DNS could not answer (code " + code + ").");
            return Result(Cloudflare, Safety.Safe, "Not blocked by Cloudflare's malware-blocking DNS (1.1.1.2).");
        }

        public static SourceResult AskQuad9(string domain)
        {
            if (!Query(Quad9Filtered, domain, out int code, out _, out string error))
                return SafetySources.Failure(Quad9, "Could not reach Quad9's DNS at 9.9.9.9: " + error);
            if (code == NoError)
                return Result(Quad9, Safety.Safe, "Not blocked by Quad9's threat-blocking DNS (9.9.9.9).");
            if (code != NameError)
                return SafetySources.Failure(Quad9, "Quad9's DNS could not answer (code " + code + ").");
            if (!Query(Quad9Unfiltered, domain, out int plainCode, out _, out error))
                return SafetySources.Failure(Quad9, "Could not reach Quad9's unfiltered DNS at 9.9.9.10: " + error);
            if (plainCode == NoError)
                return Result(Quad9, Safety.HighRisk, "Quad9's threat-blocking DNS (9.9.9.9) blocks this domain: its threat intelligence partners list it as malicious.",
                    "https://www.quad9.net/result/?url=" + Uri.EscapeDataString(domain));
            return Result(Quad9, Safety.Unrated, "The domain no longer exists, so Quad9 has nothing to say about it.");
        }

        /// <summary>One DNS question for a domain's IPv4 addresses, over UDP, with one retry.</summary>
        private static bool Query(IPAddress server, string domain, out int code, out List<IPAddress> addresses, out string error)
        {
            code = -1;
            addresses = new List<IPAddress>();
            error = null;
            byte[] question = BuildQuery(domain, out ushort id);
            if (question == null)
            {
                error = "not a valid domain name";
                return false;
            }
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    using (var udp = new UdpClient(server.AddressFamily))
                    {
                        udp.Client.ReceiveTimeout = 2500;
                        udp.Send(question, question.Length, new IPEndPoint(server, 53));
                        var from = new IPEndPoint(IPAddress.Any, 0);
                        byte[] answer = udp.Receive(ref from);
                        if (ParseAnswer(answer, id, out code, addresses)) return true;
                        error = "the answer could not be read";
                    }
                }
                catch (SocketException e)
                {
                    error = e.SocketErrorCode == SocketError.TimedOut ? "no answer (a firewall or VPN may block DNS to other servers)" : e.Message;
                }
            }
            return false;
        }

        private static readonly Random ids = new Random();

        private static byte[] BuildQuery(string domain, out ushort id)
        {
            lock (ids) id = (ushort)ids.Next(65536);
            var packet = new List<byte> { (byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };   // recursion wanted; one question
            foreach (string label in domain.TrimEnd('.').Split('.'))
            {
                byte[] bytes = Encoding.ASCII.GetBytes(label);
                if (bytes.Length == 0 || bytes.Length > 63) return null;
                packet.Add((byte)bytes.Length);
                packet.AddRange(bytes);
            }
            packet.AddRange(new byte[] { 0, 0, 1, 0, 1 });    // end of name; type A; class IN
            return packet.ToArray();
        }

        private static bool ParseAnswer(byte[] data, ushort id, out int code, List<IPAddress> addresses)
        {
            code = -1;
            if (data.Length < 12 || (data[0] << 8 | data[1]) != id) return false;
            code = data[3] & 0x0F;
            int questions = data[4] << 8 | data[5], answers = data[6] << 8 | data[7];
            int at = 12;
            for (int i = 0; i < questions; i++)
            {
                if (!SkipName(data, ref at)) return false;
                at += 4;
            }
            for (int i = 0; i < answers; i++)
            {
                if (!SkipName(data, ref at) || at + 10 > data.Length) return false;
                int type = data[at] << 8 | data[at + 1];
                int length = data[at + 8] << 8 | data[at + 9];
                at += 10;
                if (at + length > data.Length) return false;
                if (type == 1 && length == 4)
                    addresses.Add(new IPAddress(new[] { data[at], data[at + 1], data[at + 2], data[at + 3] }));
                at += length;
            }
            return true;
        }

        private static bool SkipName(byte[] data, ref int at)
        {
            while (at < data.Length)
            {
                byte length = data[at];
                if (length == 0)
                {
                    at++;
                    return true;
                }
                if ((length & 0xC0) == 0xC0)
                {
                    at += 2;    // a pointer to a name earlier in the message ends this one
                    return true;
                }
                at += length + 1;
            }
            return false;
        }

        // ---- Published lists, downloaded once a day ----

        /// <summary>Web addresses serving malware right now, from abuse.ch: about 30,000, as plain text.</summary>
        public static readonly Feed UrlHausFeed = new Feed("https://urlhaus.abuse.ch/downloads/text_online/", "urlhaus-online.txt", ParseUrlHaus);
        /// <summary>Botnet command-and-control servers, from abuse.ch's Feodo Tracker.</summary>
        public static readonly Feed FeodoFeed = new Feed("https://feodotracker.abuse.ch/downloads/ipblocklist.json", "feodo.json");
        /// <summary>Spamhaus's Don't Route Or Peer lists: networks hijacked or run by criminals, one JSON object a line.</summary>
        public static readonly Feed DropV4Feed = new Feed("https://www.spamhaus.org/drop/drop_v4.json", "drop-v4.json", ParseDrop);
        public static readonly Feed DropV6Feed = new Feed("https://www.spamhaus.org/drop/drop_v6.json", "drop-v6.json", ParseDrop);

        // Sites where anyone can put files up. Some of those files are always malware, so these hosts
        // are on URLhaus's list all the time, which says nothing about a connection to them.
        private static readonly HashSet<string> SharingSites = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "gist.githubusercontent.com",
            "release-assets.githubusercontent.com", "gitlab.com", "bitbucket.org", "codeberg.org",
            "drive.google.com", "docs.google.com", "drive.usercontent.google.com", "storage.googleapis.com", "sites.google.com",
            "cdn.discordapp.com", "media.discordapp.net", "dropbox.com", "www.dropbox.com", "dl.dropboxusercontent.com",
            "onedrive.live.com", "1drv.ms", "mediafire.com", "www.mediafire.com", "download1.mediafire.com",
            "img1.wsimg.com", "pastebin.com", "files.catbox.moe", "archive.org", "s3.amazonaws.com", "transfer.sh",
            "sourceforge.net", "downloads.sourceforge.net", "firebasestorage.googleapis.com", "telegra.ph",
        };

        private static object ParseUrlHaus(string text)
        {
            var hosts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (string line in text.Split('\n'))
            {
                string url = line.Trim();
                if (url.Length == 0 || url[0] == '#') continue;
                int start = url.IndexOf("://", StringComparison.Ordinal);
                if (start < 0) continue;
                start += 3;
                int end = url.IndexOfAny(new[] { '/', '?', '#' }, start);
                string host = end < 0 ? url.Substring(start) : url.Substring(start, end - start);
                if (host.StartsWith("[", StringComparison.Ordinal))
                    host = host.Substring(1, Math.Max(0, host.IndexOf(']') - 1));
                else if (host.IndexOf(':') >= 0)
                    host = host.Substring(0, host.IndexOf(':'));
                if (host.Length == 0) continue;
                hosts.TryGetValue(host, out int count);
                hosts[host] = count + 1;
            }
            if (hosts.Count == 0) throw new ArgumentException("The URLhaus list was empty.");
            return hosts;
        }

        /// <summary>A network, as its address bytes and prefix length.</summary>
        private sealed class Network
        {
            public byte[] Bytes;
            public int Prefix;
            public string Cidr, Id;

            public bool Contains(byte[] address)
            {
                if (address.Length != Bytes.Length) return false;
                int bits = Prefix;
                for (int i = 0; bits > 0; i++, bits -= 8)
                {
                    int mask = bits >= 8 ? 0xFF : 0xFF << (8 - bits) & 0xFF;
                    if ((address[i] & mask) != (Bytes[i] & mask)) return false;
                }
                return true;
            }
        }

        private static object ParseDrop(string text)
        {
            var networks = new List<Network>();
            foreach (string line in text.Split('\n'))
            {
                if (line.Trim().Length == 0) continue;
                string cidr = Json.Str(Json.Parse(line), "cidr");
                if (cidr == null) continue;     // the closing line describes the list itself
                string[] parts = cidr.Split('/');
                if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out IPAddress network) ||
                    !int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int prefix)) continue;
                networks.Add(new Network { Bytes = network.GetAddressBytes(), Prefix = prefix, Cidr = cidr, Id = Json.Str(Json.Parse(line), "sblid") });
            }
            if (networks.Count == 0) throw new ArgumentException("The Spamhaus list was empty.");
            return networks;
        }

        /// <summary>The domain, if there is one, and the address, against URLhaus's list of hosts serving malware.</summary>
        public static SourceResult CheckUrlHaus(string domain, IPAddress address)
        {
            if (!(UrlHausFeed.Load() is Dictionary<string, int> hosts))
                return SafetySources.Failure(UrlHaus, "Could not download the URLhaus list" + (UrlHausFeed.Error != null ? ": " + UrlHausFeed.Error : "."));
            foreach (string host in new[] { domain, address.ToString() })
            {
                if (host == null || !hosts.TryGetValue(host, out int count)) continue;
                string link = "https://urlhaus.abuse.ch/host/" + host + "/";
                string what = count == 1 ? "1 web address" : count.ToString("N0", CultureInfo.CurrentCulture) + " web addresses";
                if (SharingSites.Contains(host))
                    return Result(UrlHaus, Safety.Unrated,
                        $"URLhaus lists {what} on {host} serving malware right now. Anyone can share files there and some are always malware, " +
                        "so this says nothing about this connection on its own.", link);
                return Result(UrlHaus, Safety.HighRisk,
                    $"URLhaus lists {what} on {host} serving malware right now. Programs rarely have a good reason to talk to such a host.", link);
            }
            return Result(UrlHaus, Safety.Safe, "Not on URLhaus's list of hosts serving malware right now.");
        }

        /// <summary>The address against Feodo Tracker's botnet servers and Spamhaus's criminal networks.</summary>
        public static SourceResult CheckIpLists(IPAddress address)
        {
            object feodo = FeodoFeed.Load();
            object drop = (address.AddressFamily == AddressFamily.InterNetworkV6 ? DropV6Feed : DropV4Feed).Load();
            string text = address.ToString();
            foreach (object server in Json.Array(feodo))
            {
                if (Json.Str(server, "ip_address") != text) continue;
                string malware = Json.Str(server, "malware"), status = Json.Str(server, "status"), lastOnline = Json.Str(server, "last_online");
                // A server since taken down may have handed its address on to someone else.
                return Result(IpLists, status == "online" ? Safety.HighRisk : Safety.Caution,
                    "Feodo Tracker lists this address as a control server for " + (malware != null ? "the " + malware : "a") + " botnet" +
                    (status != null ? $" (now {status}" + (lastOnline != null ? ", last seen working " + lastOnline : "") + ")." : "."),
                    "https://feodotracker.abuse.ch/browse/host/" + text + "/");
            }
            if (drop is List<Network> networks)
            {
                byte[] bytes = address.GetAddressBytes();
                Network found = networks.Find(n => n.Contains(bytes));
                if (found != null)
                    return Result(IpLists, Safety.HighRisk,
                        $"It is in {found.Cidr}, a network that Spamhaus's Don't Route Or Peer list says is hijacked or run by criminals ({found.Id}).",
                        "https://check.spamhaus.org/results/?query=" + text);
            }
            if (feodo == null && drop == null)
                return SafetySources.Failure(IpLists, "Could not download the lists" + (FeodoFeed.Error != null ? ": " + FeodoFeed.Error : "."));
            return Result(IpLists, Safety.Safe, "Not a known botnet control server (Feodo Tracker), nor in a criminal network (Spamhaus DROP).");
        }

        // ---- VirusTotal, which also rates domains and addresses ----

        public const string DomainPrefix = "domain:", AddressPrefix = "ip:";

        /// <summary>The key a host is looked up and cached under: its domain if it has one, otherwise its address.</summary>
        public static string Subject(string domain, IPAddress address) => domain != null ? DomainPrefix + domain.ToLowerInvariant() : AddressPrefix + address;

        public static bool IsSubject(string key) => key.StartsWith(DomainPrefix, StringComparison.Ordinal) || key.StartsWith(AddressPrefix, StringComparison.Ordinal);

        public static SourceResult QueryVirusTotal(string subject, string key, out bool retryLater)
        {
            retryLater = false;
            const string source = SafetySources.VirusTotal;
            bool isDomain = subject.StartsWith(DomainPrefix, StringComparison.Ordinal);
            string host = subject.Substring(isDomain ? DomainPrefix.Length : AddressPrefix.Length);
            string link = "https://www.virustotal.com/gui/" + (isDomain ? "domain/" : "ip-address/") + host;
            var request = new HttpRequestMessage(HttpMethod.Get, "https://www.virustotal.com/api/v3/" + (isDomain ? "domains/" : "ip_addresses/") + host);
            request.Headers.Add("x-apikey", key);
            using (HttpResponseMessage response = SafetySources.Http.SendAsync(request).Result)
            {
                string body = response.Content.ReadAsStringAsync().Result;
                switch ((int)response.StatusCode)
                {
                    case 200: break;
                    case 404: return Result(source, Safety.Unrated, "VirusTotal has no information about this " + (isDomain ? "domain." : "address."));
                    case 401:
                    case 403: return SafetySources.Failure(source, "VirusTotal rejected the API key. Check it under Safety Sources.");
                    case 429:
                        retryLater = true;
                        return SafetySources.Failure(source, "Waiting for the VirusTotal request quota to free up.");
                    default: return SafetySources.Failure(source, $"VirusTotal answered {(int)response.StatusCode}: {Json.Str(Json.Parse(body), "error", "message")}");
                }
                object stats = Json.Get(Json.Parse(body), "data", "attributes", "last_analysis_stats");
                long malicious = Json.Long(stats, "malicious"), suspicious = Json.Long(stats, "suspicious");
                long vendors = malicious + suspicious + Json.Long(stats, "harmless") + Json.Long(stats, "undetected");
                if (malicious >= 5)
                    return Result(source, Safety.HighRisk, $"{malicious} of {vendors} security vendors flag it as malicious.", link);
                if (malicious >= 2)
                    return Result(source, Safety.Caution, $"{malicious} of {vendors} security vendors flag it as malicious. A few can be mistaken, but look at what is using it.", link);
                if (malicious == 1 || suspicious > 0)
                    return Result(source, Safety.LowRisk, $"{malicious + suspicious} of {vendors} security vendors flag it; a single flag is usually a mistake.", link);
                return Result(source, Safety.Safe, $"None of {vendors} security vendors flag it.", link);
            }
        }
    }
}
