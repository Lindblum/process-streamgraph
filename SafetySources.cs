using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web.Script.Serialization;

namespace ProcessStreamgraph
{
    /// <summary>What is known about a program file before any service is asked.</summary>
    internal sealed class FileFacts
    {
        public string Path;
        public string Name;
        public string Sha256;
        public string ProductName, FileDescription, CompanyName, ProductVersion;
        public string Signer;
        public SignatureState Signature;
        public DateTime WrittenUtc;

        /// <summary>Parts of Windows itself, which Windows Update keeps patched.</summary>
        public bool IsWindowsComponent =>
            Signature == SignatureState.Valid && (Signer == "Microsoft Windows" || Signer == "Microsoft Windows Publisher");
    }

    /// <summary>The services consulted for a safety rating, and how each one's answer becomes a verdict.</summary>
    internal static class SafetySources
    {
        public const string VirusTotal = "VirusTotal";
        public const string MetaDefender = "MetaDefender";
        public const string MalwareBazaar = "MalwareBazaar";
        public const string Kev = "CISA exploited vulnerabilities";
        public const string EndOfLife = "endoflife.date";
        public const string Signature = "Digital signature";
        public const string Notes = "Reviewed notes";

        /// <summary>Every source, in the order they are listed in a report.</summary>
        public static readonly string[] All =
        {
            VirusTotal, MetaDefender, MalwareBazaar, HostSources.UrlHaus, HostSources.IpLists, HostSources.Quad9, HostSources.Cloudflare,
            Kev, EndOfLife, Signature, Notes
        };

        private static readonly HttpClient http = CreateClient();

        public static HttpClient Http => http;

        private static HttpClient CreateClient()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("ProcessStreamgraph/1.0");
            return client;
        }

        private static SourceResult Result(string source, Safety verdict, string summary, string link = null) =>
            new SourceResult { Source = source, Verdict = verdict, Summary = summary, Link = link, Checked = DateTime.UtcNow };

        public static SourceResult Failure(string source, string summary) =>
            new SourceResult { Source = source, Verdict = Safety.Unrated, Summary = summary, Checked = DateTime.UtcNow, Failed = true };

        // ---- Local ----

        public static SourceResult FromSignature(FileFacts facts, string detail)
        {
            switch (facts.Signature)
            {
                case SignatureState.Valid:
                    return Result(Signature, Safety.Safe, "Signed by " + (facts.Signer ?? "a trusted publisher") + "; Windows verified the signature.");
                case SignatureState.Invalid:
                    return Result(Signature, Safety.HighRisk, detail);
                case SignatureState.Untrusted:
                    return Result(Signature, Safety.Caution, detail);
            }
            // Store apps are signed as a package, which Windows checks on install and then locks away.
            if (facts.Path != null && facts.Path.IndexOf(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) >= 0)
                return Result(Signature, Safety.Safe, "Installed from a signed app package (Microsoft Store or winget) into the protected WindowsApps folder.");
            return Result(Signature, Safety.LowRisk,
                "Not digitally signed, so its publisher cannot be verified. Common for small or in-house programs; worth a look if you don't recognise it.");
        }

        // ---- Malware scanners, by file hash ----

        public static SourceResult QueryVirusTotal(string sha256, string key, out bool retryLater)
        {
            retryLater = false;
            string link = "https://www.virustotal.com/gui/file/" + sha256;
            var request = new HttpRequestMessage(HttpMethod.Get, "https://www.virustotal.com/api/v3/files/" + sha256);
            request.Headers.Add("x-apikey", key);
            using (HttpResponseMessage response = http.SendAsync(request).Result)
            {
                string body = response.Content.ReadAsStringAsync().Result;
                switch ((int)response.StatusCode)
                {
                    case 200: break;
                    case 404: return Result(VirusTotal, Safety.Unrated, "VirusTotal has never seen this exact file, so it has no scan results for it.");
                    case 401:
                    case 403: return Failure(VirusTotal, "VirusTotal rejected the API key. Check it under Safety Sources.");
                    case 429:
                        retryLater = true;
                        return Failure(VirusTotal, "Waiting for the VirusTotal request quota to free up.");
                    default: return Failure(VirusTotal, $"VirusTotal answered {(int)response.StatusCode}: {Json.Str(Json.Parse(body), "error", "message")}");
                }

                object attributes = Json.Get(Json.Parse(body), "data", "attributes");
                long malicious = Json.Long(attributes, "last_analysis_stats", "malicious");
                long suspicious = Json.Long(attributes, "last_analysis_stats", "suspicious");
                long engines = malicious + suspicious + Json.Long(attributes, "last_analysis_stats", "undetected") +
                               Json.Long(attributes, "last_analysis_stats", "harmless");
                string label = Json.Str(attributes, "popular_threat_classification", "suggested_threat_label");
                string labelText = string.IsNullOrEmpty(label) ? "" : $" (most often as \"{label}\")";
                long scanned = Json.Long(attributes, "last_analysis_date");
                string when = scanned > 0 ? " Last scanned " + DateTimeOffset.FromUnixTimeSeconds(scanned).LocalDateTime.ToString("d") + "." : "";
                return ScannerVerdict(VirusTotal, malicious, suspicious, engines, labelText, when, link);
            }
        }

        public static SourceResult QueryMetaDefender(string sha256, string key, out bool retryLater)
        {
            retryLater = false;
            string link = "https://metadefender.com/results/hash/" + sha256;
            var request = new HttpRequestMessage(HttpMethod.Get, "https://api.metadefender.com/v4/hash/" + sha256);
            request.Headers.Add("apikey", key);
            using (HttpResponseMessage response = http.SendAsync(request).Result)
            {
                string body = response.Content.ReadAsStringAsync().Result;
                switch ((int)response.StatusCode)
                {
                    case 200: break;
                    case 404: return Result(MetaDefender, Safety.Unrated, "MetaDefender has never seen this exact file, so it has no scan results for it.");
                    case 401:
                    case 403: return Failure(MetaDefender, "MetaDefender rejected the API key. Check it under Safety Sources.");
                    case 429:
                        retryLater = true;
                        return Failure(MetaDefender, "Waiting for the MetaDefender request quota to free up.");
                    default: return Failure(MetaDefender, $"MetaDefender answered {(int)response.StatusCode}.");
                }

                object results = Json.Get(Json.Parse(body), "scan_results");
                long detected = Json.Long(results, "total_detected_avs");
                long engines = Json.Long(results, "total_avs");
                string verdict = Json.Str(results, "scan_all_result_a");
                string labelText = detected > 0 && !string.IsNullOrEmpty(verdict) ? $" (overall: {verdict})" : "";
                return ScannerVerdict(MetaDefender, detected, 0, engines, labelText, "", link);
            }
        }

        /// <summary>
        /// A handful of engines flagging a file is common for legitimate but unusual software, so only
        /// a broad consensus counts as high risk.
        /// </summary>
        private static SourceResult ScannerVerdict(string source, long malicious, long suspicious, long engines, string label, string when, string link)
        {
            if (malicious >= 5)
                return Result(source, Safety.HighRisk, $"{malicious} of {engines} antivirus engines detect it as malicious{label}.{when}", link);
            if (malicious >= 2)
                return Result(source, Safety.Caution, $"{malicious} of {engines} antivirus engines detect it as malicious{label}. A few detections can be false positives, but check where it came from.{when}", link);
            if (malicious == 1 || suspicious > 0)
                return Result(source, Safety.LowRisk, $"{malicious + suspicious} of {engines} engines flag it{label}; a single detection is usually a false positive.{when}", link);
            return Result(source, Safety.Safe, $"None of {engines} antivirus engines detect anything.{when}", link);
        }

        public static SourceResult QueryMalwareBazaar(string sha256, string key, out bool retryLater)
        {
            retryLater = false;
            var request = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["query"] = "get_info", ["hash"] = sha256 })
            };
            request.Headers.Add("Auth-Key", key);
            using (HttpResponseMessage response = http.SendAsync(request).Result)
            {
                string body = response.Content.ReadAsStringAsync().Result;
                if ((int)response.StatusCode == 401 || (int)response.StatusCode == 403)
                    return Failure(MalwareBazaar, "abuse.ch rejected the Auth-Key. Check it under Safety Sources.");
                if ((int)response.StatusCode == 429)
                {
                    retryLater = true;
                    return Failure(MalwareBazaar, "Waiting for the MalwareBazaar request quota to free up.");
                }
                object root = Json.Parse(body);
                string status = Json.Str(root, "query_status");
                if (status == "hash_not_found")
                    return Result(MalwareBazaar, Safety.Unrated, "Not in MalwareBazaar's collection of known malware samples.");
                if (status != "ok")
                    return Failure(MalwareBazaar, "MalwareBazaar could not answer: " + (status ?? $"HTTP {(int)response.StatusCode}"));

                object sample = Json.Get(root, "data", "0");
                string family = Json.Str(sample, "signature");
                return Result(MalwareBazaar, Safety.HighRisk,
                    "This exact file is a known malware sample in MalwareBazaar" + (string.IsNullOrEmpty(family) ? "." : $", identified as {family}.") +
                    " First reported " + Json.Str(sample, "first_seen") + ".",
                    "https://bazaar.abuse.ch/sample/" + sha256 + "/");
            }
        }

        // ---- Published lists, downloaded once a day ----

        public static readonly Feed KevFeed = new Feed("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "kev.json");
        public static readonly Feed EndOfLifeFeed = new Feed("https://endoflife.date/api/v1/products/full", "endoflife.json");

        /// <summary>
        /// CISA lists vulnerabilities that attackers are actively exploiting. One that was both found
        /// recently (going by its CVE year) and listed after this file was last written suggests the file
        /// predates the fix. CISA also adds old vulnerabilities years later, and those are long fixed in
        /// a newer file, so the CVE year matters as well as the listing date. The list does not say which versions
        /// are affected, so this stays a prompt to check rather than a verdict of high risk.
        /// </summary>
        public static SourceResult CheckKev(FileFacts facts, object kev)
        {
            if (facts.IsWindowsComponent)
                return Result(Kev, Safety.Unrated, "Part of Windows, which Windows Update keeps patched; not checked against the list.");

            var later = new List<object>();
            int earlier = 0;
            string product = null;
            foreach (object entry in Json.Array(kev, "vulnerabilities"))
            {
                string vendor = Json.Str(entry, "vendorProject"), name = Json.Str(entry, "product");
                if (!ProductMatches(facts, name, vendor)) continue;
                product = name.StartsWith(vendor, StringComparison.OrdinalIgnoreCase) ? name : vendor + " " + name;
                bool listedLater = DateTime.TryParse(Json.Str(entry, "dateAdded"), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime added) && added > facts.WrittenUtc;
                if (listedLater && CveYear(Json.Str(entry, "cveID")) >= facts.WrittenUtc.Year - 1)
                    later.Add(entry);
                else
                    earlier++;
            }

            string link = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
            if (product == null)
                return Result(Kev, Safety.Unrated, "No actively exploited vulnerabilities are listed for this product.", link);
            if (later.Count == 0)
                return Result(Kev, Safety.Unrated, $"{earlier} actively exploited {(earlier == 1 ? "vulnerability is" : "vulnerabilities are")} listed for {product}, all of them older than this file and most likely fixed in it.", link);

            later.Sort((a, b) => string.CompareOrdinal(Json.Str(b, "dateAdded"), Json.Str(a, "dateAdded")));
            object latest = later[0];
            string cve = Json.Str(latest, "cveID");
            var summary = new StringBuilder();
            summary.Append(later.Count == 1 ? "An actively exploited vulnerability in " : $"{later.Count} actively exploited vulnerabilities in ")
                   .Append(product).Append(later.Count == 1 ? " was" : " were")
                   .Append(" reported after this file's date, so it may be missing the fix. Latest: ")
                   .Append(cve).Append(" (").Append(Json.Str(latest, "dateAdded")).Append("): ")
                   .Append(Shorten(Json.Str(latest, "shortDescription"), 220));
            return Result(Kev, Safety.Caution, summary.ToString(), "https://nvd.nist.gov/vuln/detail/" + cve);
        }

        /// <summary>Whether the program's release is still supported, and whether a newer one is out.</summary>
        public static SourceResult CheckEndOfLife(FileFacts facts, object products)
        {
            int[] installed = ParseVersion(facts.ProductVersion);
            if (installed != null)
            {
                foreach (object product in Json.Array(products, "result"))
                {
                    string label = Json.Str(product, "label");
                    if (!ProductMatches(facts, label, null, allowSuffix: true)) continue;
                    foreach (object release in Json.Array(product, "releases"))
                    {
                        int[] cycle = ParseVersion(Json.Str(release, "name"));
                        if (cycle == null || !IsPrefix(cycle, installed)) continue;
                        return ReleaseVerdict(facts, product, release, label, installed);
                    }
                }
            }
            return Result(EndOfLife, Safety.Unrated, "This product's support lifecycle is not tracked by endoflife.date.");
        }

        private static SourceResult ReleaseVerdict(FileFacts facts, object product, object release, string label, int[] installed)
        {
            string link = Json.Str(product, "links", "html");
            string cycle = Json.Str(release, "label") ?? Json.Str(release, "name");
            string latest = Json.Str(release, "latest", "name");
            if (Json.Bool(release, "isEol"))
            {
                string newest = null;
                foreach (object other in Json.Array(product, "releases"))
                    if (!Json.Bool(other, "isEol")) { newest = Json.Str(other, "latest", "name"); break; }
                return Result(EndOfLife, Safety.Caution,
                    $"{label} {cycle} reached end of life on {Json.Str(release, "eolFrom")} and no longer gets security fixes." +
                    (newest != null ? $" The newest supported version is {newest}." : ""), link);
            }
            int[] newestInCycle = ParseVersion(latest);
            if (newestInCycle != null && Compare(newestInCycle, installed) > 0)
                return Result(EndOfLife, Safety.LowRisk,
                    $"{label} {cycle} is still supported, but {latest} is out and this is {facts.ProductVersion}. Updating picks up any security fixes since.", link);
            return Result(EndOfLife, Safety.Safe, $"{label} {cycle} is supported and this is its latest version.", link);
        }

        /// <summary>
        /// Matches a listed product to the file's own description of itself, by whole name only: loose
        /// matching would pin every vulnerability in "Windows" or "Office" on unrelated programs.
        /// </summary>
        private static bool ProductMatches(FileFacts facts, string product, string vendor, bool allowSuffix = false)
        {
            string target = Normalize(product);
            if (target.Length < 3) return false;
            string withVendor = vendor != null ? Normalize(vendor + " " + product) : null;
            foreach (string own in new[] { facts.ProductName, facts.FileDescription })
            {
                string name = Normalize(own);
                if (name.Length == 0) continue;
                if (name == target || name == withVendor) return true;
                // "MySQL Server" is MySQL, "Microsoft SQL Server" is itself.
                if (allowSuffix && name.StartsWith(target + " ", StringComparison.Ordinal) && name.Split(' ').Length <= target.Split(' ').Length + 1)
                    return true;
            }
            return false;
        }

        private static string Normalize(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            var builder = new StringBuilder();
            bool space = false;
            foreach (char c in text.ToLowerInvariant())
            {
                if (char.IsLetterOrDigit(c) || c == '+' || c == '#')
                {
                    if (space && builder.Length > 0) builder.Append(' ');
                    builder.Append(c);
                    space = false;
                }
                else if (c != '®' && c != '™' && c != '©')
                {
                    space = true;
                }
            }
            return builder.ToString();
        }

        private static int CveYear(string cve)
        {
            // "CVE-2025-12345"
            string[] parts = (cve ?? "").Split('-');
            return parts.Length >= 2 && int.TryParse(parts[1], out int year) ? year : 0;
        }

        private static int[] ParseVersion(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            var parts = new List<int>();
            foreach (string part in text.Trim().Split('.'))
            {
                int digits = 0;
                while (digits < part.Length && char.IsDigit(part[digits])) digits++;
                if (digits == 0 || !int.TryParse(part.Substring(0, digits), out int value)) break;
                parts.Add(value);
                if (digits < part.Length) break;    // "1.2-beta": stop at the suffix
            }
            return parts.Count > 0 ? parts.ToArray() : null;
        }

        private static bool IsPrefix(int[] cycle, int[] version)
        {
            if (cycle.Length > version.Length) return false;
            for (int i = 0; i < cycle.Length; i++)
                if (cycle[i] != version[i]) return false;
            return true;
        }

        private static int Compare(int[] a, int[] b)
        {
            for (int i = 0; i < Math.Max(a.Length, b.Length); i++)
            {
                int x = i < a.Length ? a[i] : 0, y = i < b.Length ? b[i] : 0;
                if (x != y) return x.CompareTo(y);
            }
            return 0;
        }

        private static string Shorten(string text, int length)
        {
            if (string.IsNullOrEmpty(text) || text.Length <= length) return text;
            int cut = text.LastIndexOf(' ', length);
            return text.Substring(0, cut > length / 2 ? cut : length) + "…";
        }
    }

    /// <summary>A published list, cached on disk and fetched again once it is a day old.</summary>
    internal sealed class Feed
    {
        private static readonly TimeSpan MaxAge = TimeSpan.FromDays(1);
        private readonly string url, file;
        private readonly Func<string, object> parse;
        private readonly object gate = new object();
        private object data;
        private DateTime loadedUtc;

        /// <param name="parse">Turns the downloaded text into what Load returns; JSON by default.</param>
        public Feed(string url, string fileName, Func<string, object> parse = null)
        {
            this.url = url;
            file = Path.Combine(SafetyStore.Folder, fileName);
            this.parse = parse ?? Json.Parse;
        }

        public string Error { get; private set; }

        /// <summary>The parsed list, or null when it could not be fetched and no earlier copy exists.</summary>
        public object Load()
        {
            // Lists are checked from more than one thread; one download is enough.
            lock (gate) return LoadOnce();
        }

        private object LoadOnce()
        {
            if (data != null && DateTime.UtcNow - loadedUtc < MaxAge) return data;
            Error = null;
            bool fresh = File.Exists(file) && DateTime.UtcNow - File.GetLastWriteTimeUtc(file) < MaxAge;
            if (!fresh)
            {
                try
                {
                    string text = SafetySources.Http.GetStringAsync(url).Result;
                    object parsed = parse(text);
                    Directory.CreateDirectory(Path.GetDirectoryName(file));
                    File.WriteAllText(file, text);
                    data = parsed;
                    loadedUtc = DateTime.UtcNow;
                    return data;
                }
                catch (Exception e) when (e is AggregateException || e is HttpRequestException || e is IOException || e is ArgumentException || e is InvalidOperationException)
                {
                    Error = (e.InnerException ?? e).Message;
                    // Fall back on yesterday's copy, if there is one.
                }
            }
            try
            {
                if (File.Exists(file))
                {
                    data = parse(File.ReadAllText(file));
                    loadedUtc = DateTime.UtcNow;
                }
            }
            catch (Exception e) when (e is IOException || e is ArgumentException || e is InvalidOperationException)
            {
                Error = e.Message;
            }
            return data;
        }
    }

    /// <summary>Navigation over the dictionaries and arrays that JavaScriptSerializer produces.</summary>
    internal static class Json
    {
        private static readonly JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 256 };

        public static object Parse(string text)
        {
            try
            {
                return serializer.DeserializeObject(text);
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        public static string Write(object value) => serializer.Serialize(value);

        public static object Get(object node, params string[] path)
        {
            foreach (string key in path)
            {
                if (node is IDictionary<string, object> map) node = map.TryGetValue(key, out object value) ? value : null;
                else if (node is object[] list && int.TryParse(key, out int index)) node = index < list.Length ? list[index] : null;
                else return null;
            }
            return node;
        }

        public static string Str(object node, params string[] path) => Get(node, path) is object value ? Convert.ToString(value, CultureInfo.InvariantCulture) : null;

        public static long Long(object node, params string[] path)
        {
            object value = Get(node, path);
            try
            {
                return value == null ? 0 : Convert.ToInt64(value, CultureInfo.InvariantCulture);
            }
            catch (Exception e) when (e is FormatException || e is InvalidCastException || e is OverflowException)
            {
                return 0;
            }
        }

        public static bool Bool(object node, params string[] path) => Get(node, path) is bool value && value;

        public static object[] Array(object node, params string[] path) => Get(node, path) as object[] ?? new object[0];
    }
}
