using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ProcessStreamgraph
{
    /// <summary>Where a public address is, roughly, and who holds it.</summary>
    internal sealed class IpDetail
    {
        public string City, Region, Country;    // country as its two-letter code
        public string Owner;        // the organisation the address block is registered to
        public string Company;      // the company running the network it is on
        public long Asn;
        public string Domain;       // the network company's own domain
        public DateTime Checked;    // UTC

        /// <summary>"City, Region, CC", leaving out a region that repeats the city.</summary>
        public string Location
        {
            get
            {
                var parts = new List<string>();
                if (!string.IsNullOrEmpty(City)) parts.Add(City);
                if (!string.IsNullOrEmpty(Region) && !string.Equals(Region, City, StringComparison.OrdinalIgnoreCase)) parts.Add(Region);
                if (!string.IsNullOrEmpty(Country)) parts.Add(Country);
                return string.Join(", ", parts);
            }
        }
    }

    /// <summary>
    /// Location and owners of the public addresses in the Connections window, from ipwho.is (free, no
    /// account). An answer holds for the address's whole block, a /24 for IPv4 and a /48 for IPv6,
    /// since those are allocated and routed together; so each block is asked about once, and the
    /// answers are kept on disk for a month. Used from the UI thread; the lookups run on one
    /// background thread, one at a time.
    /// </summary>
    internal static class IpDetails
    {
        private static readonly TimeSpan Lifetime = TimeSpan.FromDays(30);
        private static readonly TimeSpan Spacing = TimeSpan.FromMilliseconds(400);
        private static string CacheFile => Path.Combine(SafetyStore.Folder, "ip-details.json");

        private static readonly object gate = new object();
        private static Dictionary<string, IpDetail> known;     // by block; null until loaded
        private static readonly Dictionary<string, IpAddr> queue = new Dictionary<string, IpAddr>();   // block -> an address in it
        private static readonly HashSet<string> failed = new HashSet<string>();     // not asked again this run
        private static bool working, dirty;
        private static DateTime pausedUntil;    // after the service says the limit is reached

        private static readonly HttpClient http = CreateClient();

        private static HttpClient CreateClient()
        {
            var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("ProcessStreamgraph/1.0");
            return client;
        }

        /// <summary>What is known of a public address, or null while it is being looked up or could not be.</summary>
        public static IpDetail Get(IpAddr address, out bool pending)
        {
            string block = BlockOf(address);
            lock (gate)
            {
                if (known == null) Load();
                pending = false;
                if (known.TryGetValue(block, out IpDetail detail) && DateTime.UtcNow - detail.Checked < Lifetime) return detail;
                if (failed.Contains(block) || DateTime.UtcNow < pausedUntil) return detail;      // an old answer beats none
                pending = true;
                if (!queue.ContainsKey(block)) queue[block] = address;
                if (!working)
                {
                    working = true;
                    new Thread(Work) { IsBackground = true, Name = "IP details", Priority = ThreadPriority.BelowNormal }.Start();
                }
                return detail;
            }
        }

        /// <summary>The block an address is looked up and kept under: "a.b.c.0/24", or the first 48 bits of an IPv6 address.</summary>
        private static string BlockOf(IpAddr address)
        {
            byte[] b = address.ToIPAddress().GetAddressBytes();
            if (b.Length == 4) return b[0] + "." + b[1] + "." + b[2] + ".0/24";
            return string.Format(CultureInfo.InvariantCulture, "{0:x2}{1:x2}:{2:x2}{3:x2}:{4:x2}{5:x2}::/48", b[0], b[1], b[2], b[3], b[4], b[5]);
        }

        private static void Work()
        {
            while (true)
            {
                string block;
                IpAddr address;
                lock (gate)
                {
                    if (queue.Count == 0 || DateTime.UtcNow < pausedUntil)
                    {
                        // Waiting addresses are asked for again by the next Get, after the pause.
                        queue.Clear();
                        working = false;
                        if (dirty) Save();
                        return;
                    }
                    var e = queue.GetEnumerator();
                    e.MoveNext();
                    block = e.Current.Key;
                    address = e.Current.Value;
                    queue.Remove(block);
                }
                IpDetail detail = Fetch(address, out bool limited);
                lock (gate)
                {
                    if (detail != null)
                    {
                        known[block] = detail;
                        dirty = true;
                    }
                    else if (limited) pausedUntil = DateTime.UtcNow.AddHours(1);
                    else failed.Add(block);
                    if (dirty && known.Count % 20 == 0) Save();
                }
                Thread.Sleep(Spacing);
            }
        }

        private static IpDetail Fetch(IpAddr address, out bool limited)
        {
            limited = false;
            try
            {
                string url = "https://ipwho.is/" + address.ToIPAddress() + "?fields=success,message,city,region,country_code,connection";
                using (HttpResponseMessage response = http.GetAsync(url).Result)
                {
                    if ((int)response.StatusCode == 429)
                    {
                        limited = true;
                        return null;
                    }
                    if (!response.IsSuccessStatusCode) return null;
                    object root = Json.Parse(response.Content.ReadAsStringAsync().Result);
                    if (!Json.Bool(root, "success"))
                    {
                        string message = Json.Str(root, "message") ?? "";
                        limited = message.IndexOf("limit", StringComparison.OrdinalIgnoreCase) >= 0;
                        return null;
                    }
                    return new IpDetail
                    {
                        City = Json.Str(root, "city"),
                        Region = Json.Str(root, "region"),
                        Country = Json.Str(root, "country_code"),
                        Owner = Json.Str(root, "connection", "org"),
                        Company = Json.Str(root, "connection", "isp"),
                        Asn = Json.Long(root, "connection", "asn"),
                        Domain = Json.Str(root, "connection", "domain"),
                        Checked = DateTime.UtcNow
                    };
                }
            }
            catch (Exception e) when (e is AggregateException || e is HttpRequestException || e is TaskCanceledException || e is InvalidOperationException)
            {
                return null;
            }
        }

        // Under the lock.
        private static void Load()
        {
            known = new Dictionary<string, IpDetail>();
            try
            {
                if (!File.Exists(CacheFile)) return;
                if (!(Json.Parse(File.ReadAllText(CacheFile)) is IDictionary<string, object> saved)) return;
                foreach (KeyValuePair<string, object> entry in saved)
                    known[entry.Key] = new IpDetail
                    {
                        City = Json.Str(entry.Value, "city"),
                        Region = Json.Str(entry.Value, "region"),
                        Country = Json.Str(entry.Value, "country"),
                        Owner = Json.Str(entry.Value, "owner"),
                        Company = Json.Str(entry.Value, "company"),
                        Asn = Json.Long(entry.Value, "asn"),
                        Domain = Json.Str(entry.Value, "domain"),
                        Checked = new DateTime(Json.Long(entry.Value, "checked"), DateTimeKind.Utc)
                    };
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is InvalidCastException || e is ArgumentException)
            {
                // A damaged cache only costs some repeated lookups.
            }
        }

        // Under the lock.
        private static void Save()
        {
            var saved = new Dictionary<string, object>();
            foreach (KeyValuePair<string, IpDetail> entry in known)
            {
                IpDetail d = entry.Value;
                if (DateTime.UtcNow - d.Checked >= Lifetime) continue;
                saved[entry.Key] = new Dictionary<string, object>
                {
                    ["city"] = d.City, ["region"] = d.Region, ["country"] = d.Country, ["owner"] = d.Owner,
                    ["company"] = d.Company, ["asn"] = d.Asn, ["domain"] = d.Domain, ["checked"] = d.Checked.Ticks
                };
            }
            try
            {
                Directory.CreateDirectory(SafetyStore.Folder);
                File.WriteAllText(CacheFile, Json.Write(saved));
                dirty = false;
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
            }
        }
    }
}
