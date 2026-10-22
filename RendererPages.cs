using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProcessStreamgraph
{
    /// <summary>
    /// Guesses the site and page title each browser page renderer is showing, from its memory and its
    /// browser's. Browsers say nothing about it outside themselves: a renderer has no window, and its
    /// command line names no site.
    ///
    /// The site: with site isolation each renderer only ever shows pages of one site, and that site's
    /// own address (alone, without a path, as pages name themselves in requests and checks) turns up in
    /// its memory far more than any other.
    ///
    /// The title: the renderer holds it as one of its many strings, and the browser holds it too, in
    /// many copies (tab strip, history, session), while the browser sees little else of a page's text.
    /// So of the renderer's strings, the one the browser holds most is the title.
    ///
    /// Either is shown only when one candidate clearly leads.
    /// </summary>
    internal static class RendererPages
    {
        // Browsers only: apps built on Chromium show their own pages, which the addresses would misname.
        private static readonly HashSet<string> Browsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe", "chromium.exe", "thorium.exe", "arc.exe"
        };

        // Sites that serve parts of pages (scripts, images, fonts, ads, analytics) but never pages.
        private static readonly HashSet<string> PartsOnly = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "gstatic.com", "googleapis.com", "googleusercontent.com", "ggpht.com", "ytimg.com", "googlevideo.com",
            "googleadservices.com", "googlesyndication.com", "doubleclick.net", "googletagmanager.com",
            "google-analytics.com", "withgoogle.com", "amazonaws.com", "cloudfront.net", "cloudflare.com",
            "akamaihd.net", "fastly.net", "jsdelivr.net", "unpkg.com", "cdnjs.com", "w3.org", "schema.org",
            "openfontlicense.org", "githubassets.com", "githubusercontent.com", "licdn.com", "oaistatic.com",
            "fbcdn.net", "twimg.com", "redditstatic.com", "sentry.io", "pendo.io", "adblockplus.org",
            "getadblock.com", "invalid"
        };

        /// <summary>Most memory read from one process; a busy one can hold gigabytes, mostly not text.</summary>
        private const long MaxScanBytes = 512L << 20;

        /// <summary>Most renderers read in one round, so a round stays short.</summary>
        private const int MaxPerRound = 8;

        private const int MinTitle = 4, MaxTitle = 160;

        /// <summary>What one read of a renderer found.</summary>
        private sealed class Reading
        {
            public int Pid;
            public readonly Dictionary<string, int> Sites = new Dictionary<string, int>(StringComparer.Ordinal);
            public readonly Dictionary<string, int> BareHosts = new Dictionary<string, int>(StringComparer.Ordinal);
            public readonly HashSet<string> Strings = new HashSet<string>(StringComparer.Ordinal);
            public Dictionary<string, int> InBrowser;     // how many copies of each of Strings its browser holds
        }

        private sealed class Entry
        {
            public Reading Reading;
            public DateTime Read;           // when it was last read; MinValue before the first time
            public long CpuAtRead;          // its processor time then, to tell whether it has done anything since
        }

        private static readonly Dictionary<ProcInfo, Entry> entries = new Dictionary<ProcInfo, Entry>();
        private static Task<List<Reading>> running;

        /// <summary>
        /// Takes in a finished round of reading and starts the next. A renderer is first read a few
        /// seconds after it starts, once its page has loaded. After that it is read again at most every
        /// half minute, and only when it has been busy (as a new page or title takes some work) or its
        /// site is still unknown, as blank tabs and spares are waiting for a page.
        /// </summary>
        public static void Update(ProcessMonitor monitor)
        {
            DateTime now = DateTime.UtcNow;
            if (running != null && running.IsCompleted)
            {
                if (running.Status == TaskStatus.RanToCompletion) Apply(monitor, running.Result);
                running = null;
            }
            foreach (ProcInfo p in monitor.Removed) entries.Remove(p);

            var due = new List<ProcInfo>();
            foreach (ProcInfo p in monitor.Processes)
            {
                if (!p.Alive || !IsPageRenderer(p)) continue;
                if (!entries.TryGetValue(p, out Entry entry)) entries.Add(p, entry = new Entry { Read = DateTime.MinValue });
                bool isDue = entry.Read == DateTime.MinValue
                    ? now >= DateTime.FromFileTimeUtc(p.CreateTime).AddSeconds(5)
                    : now >= entry.Read.AddSeconds(30) && (p.Site == null || p.LastCpuTime - entry.CpuAtRead >= 10_000_000);
                if (isDue) due.Add(p);
            }
            if (running != null || due.Count == 0) return;

            // Those never read first, then those waiting longest.
            due.Sort((a, b) => entries[a].Read.CompareTo(entries[b].Read));
            if (due.Count > MaxPerRound) due.RemoveRange(MaxPerRound, due.Count - MaxPerRound);
            var work = new List<KeyValuePair<int, int>>();      // renderer, its browser
            foreach (ProcInfo p in due)
            {
                entries[p].Read = now;
                entries[p].CpuAtRead = p.LastCpuTime;
                work.Add(new KeyValuePair<int, int>(p.Pid, p.ParentPid));
            }
            running = Task.Run(() =>
            {
                // Reading is a background chore; it should never take processor time from what is in front.
                Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
                try
                {
                    return ReadRound(work);
                }
                finally
                {
                    Thread.CurrentThread.Priority = ThreadPriority.Normal;
                }
            });
        }

        private static bool IsPageRenderer(ProcInfo p) =>
            p.Role == ProcessRoles.PageRenderer && Browsers.Contains(p.Name) && ProcessRoles.IsChromiumHelper(p.CommandLine);

        /// <summary>Reads the renderers, then counts their strings in each of their browsers.</summary>
        private static List<Reading> ReadRound(List<KeyValuePair<int, int>> work)
        {
            var readings = new List<Reading>();
            var byBrowser = new Dictionary<int, List<Reading>>();
            foreach (KeyValuePair<int, int> renderer in work)
            {
                Reading reading = ReadRenderer(renderer.Key);
                if (reading == null) continue;
                readings.Add(reading);
                if (!byBrowser.TryGetValue(renderer.Value, out List<Reading> group)) byBrowser[renderer.Value] = group = new List<Reading>();
                group.Add(reading);
            }
            foreach (KeyValuePair<int, List<Reading>> browser in byBrowser)
            {
                var wanted = new HashSet<string>(StringComparer.Ordinal);
                foreach (Reading reading in browser.Value) wanted.UnionWith(reading.Strings);
                Dictionary<string, int> counts = CountInBrowser(browser.Key, wanted);
                foreach (Reading reading in browser.Value) reading.InBrowser = counts;
            }
            return readings;
        }

        /// <summary>Takes in a round's readings, and picks again for every renderer of the browsers read.</summary>
        private static void Apply(ProcessMonitor monitor, List<Reading> readings)
        {
            var browsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Reading reading in readings)
            {
                ProcInfo p = monitor.FindLive(reading.Pid);
                if (p == null || !entries.TryGetValue(p, out Entry entry)) continue;
                entry.Reading = reading;
                browsers.Add(p.Name);
            }
            foreach (string browser in browsers) Pick(browser);
        }

        /// <summary>Picks a site and title for each of one browser's renderers that has been read.</summary>
        private static void Pick(string browser)
        {
            var group = new List<KeyValuePair<ProcInfo, Entry>>();
            foreach (KeyValuePair<ProcInfo, Entry> pair in entries)
                if (pair.Value.Reading != null && string.Equals(pair.Key.Name, browser, StringComparison.OrdinalIgnoreCase))
                    group.Add(pair);

            // What every renderer carries whatever its site, such as the browser's own scripts: the
            // typical count across them, once there are enough to tell.
            var baseline = new Dictionary<string, int>(StringComparer.Ordinal);
            if (group.Count >= 5)
            {
                var seen = new Dictionary<string, List<int>>(StringComparer.Ordinal);
                foreach (KeyValuePair<ProcInfo, Entry> pair in group)
                    foreach (KeyValuePair<string, int> site in pair.Value.Reading.Sites)
                    {
                        if (!seen.TryGetValue(site.Key, out List<int> counts)) seen[site.Key] = counts = new List<int>();
                        counts.Add(site.Value);
                    }
                foreach (KeyValuePair<string, List<int>> site in seen)
                {
                    List<int> counts = site.Value;
                    while (counts.Count < group.Count) counts.Add(0);
                    counts.Sort();
                    baseline[site.Key] = counts[counts.Count / 2];
                }
            }

            // Strings many renderers hold, such as font names, are the browser's, not any one page's.
            var holders = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (KeyValuePair<ProcInfo, Entry> pair in group)
                foreach (string s in pair.Value.Reading.Strings)
                {
                    holders.TryGetValue(s, out int n);
                    holders[s] = n + 1;
                }

            foreach (KeyValuePair<ProcInfo, Entry> pair in group)
            {
                ProcInfo p = pair.Key;
                Reading reading = pair.Value.Reading;
                string site = PickSite(reading, baseline);
                string label = site == null ? null : Label(site, reading);
                string title = PickTitle(reading, holders, site);
                if (p.Site == label && p.PageTitle == title) continue;
                p.Site = label;
                p.PageTitle = title;
                p.RefreshDetails();
            }
        }

        /// <summary>The site that clearly leads, or null when none does.</summary>
        private static string PickSite(Reading reading, Dictionary<string, int> baseline)
        {
            var bareSites = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, int> host in reading.BareHosts)
            {
                string site = Site(host.Key);
                bareSites.TryGetValue(site, out int n);
                bareSites[site] = n + host.Value;
            }
            string best = null;
            double bestScore = 0, second = 0;
            foreach (KeyValuePair<string, int> site in reading.Sites)
            {
                if (PartsOnly.Contains(site.Key)) continue;
                baseline.TryGetValue(site.Key, out int usual);
                int extra = site.Value - usual;
                if (extra <= 0) continue;
                bareSites.TryGetValue(site.Key, out int bare);
                double score = extra * (1 + Math.Log(1 + bare));
                if (score > bestScore)
                {
                    second = bestScore;
                    bestScore = score;
                    best = site.Key;
                }
                else if (score > second) second = score;
            }
            return bestScore >= 100 && bestScore >= 2 * second ? best : null;
        }

        /// <summary>
        /// The site's host the page names itself by, such as docs.google.com, when one clearly leads the
        /// site's others; else the site, as a big site's pages name many of its hosts.
        /// </summary>
        private static string Label(string site, Reading reading)
        {
            string label = site;
            int most = 0, second = 0;
            foreach (KeyValuePair<string, int> host in reading.BareHosts)
            {
                if (Site(host.Key) != site) continue;
                if (host.Value > most)
                {
                    second = most;
                    most = host.Value;
                    label = host.Key;
                }
                else if (host.Value > second) second = host.Value;
            }
            if (most < 3 || most < 2 * second) label = site;
            return label.StartsWith("www.", StringComparison.Ordinal) ? label.Substring(4) : label;
        }

        /// <summary>
        /// The renderer's string its browser holds the most copies of, when it clearly leads; or null.
        /// One another renderer also holds counts for less, being more likely the site's own wording, such
        /// as a menu; one naming the site counts for more, as titles mostly do. A title with the site's
        /// name added ("Query - Brave Search") wins over the bare one it starts with.
        /// </summary>
        private static string PickTitle(Reading reading, Dictionary<string, int> holders, string site)
        {
            if (reading.InBrowser == null) return null;
            string brand = site == null ? null : Letters(Site(site).Split('.')[0]);
            string best = null;
            double bestScore = 0, second = 0;
            int bestCount = 0, candidates = 0;
            foreach (string s in reading.Strings)
            {
                if (holders[s] > 2 || !reading.InBrowser.TryGetValue(s, out int count) || count < 2 || Fonts.Value.Contains(s)) continue;
                bool named = brand != null && Letters(s).Contains(brand);
                // A short phrase not naming the site, such as "Learn more", is a button's, not a title.
                if (!named && s.Length < 16 && s.Split(' ').Length < 3) continue;
                candidates++;
                double score = (double)count / holders[s] * (named ? 2 : 1);
                if (score > bestScore)
                {
                    second = bestScore;
                    bestScore = score;
                    bestCount = count;
                    best = s;
                }
                else if (score > second) second = score;
            }
            if (best == null || !(candidates == 1 || (bestCount >= 3 && bestScore >= 1.5 * second))) return null;
            foreach (string s in reading.Strings)
                if (s.Length > best.Length && s.Length <= best.Length + 40 && s.StartsWith(best + " ", StringComparison.Ordinal) &&
                    holders[s] <= 2 && reading.InBrowser.TryGetValue(s, out int count) && count >= 2)
                    return s;
            return best;
        }

        // Pages that list fonts leave the names in both processes, much as a title.
        private static readonly Lazy<HashSet<string>> Fonts = new Lazy<HashSet<string>>(() =>
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (var fonts = new System.Drawing.Text.InstalledFontCollection())
                foreach (System.Drawing.FontFamily family in fonts.Families)
                {
                    names.Add(family.Name);
                    foreach (string style in new[] { " Bold", " Italic", " Bold Italic", " Semibold", " Light" }) names.Add(family.Name + style);
                }
            return names;
        });

        // "Remote Rocketship" -> "remoterocketship", to find a site's name in text.
        private static string Letters(string s)
        {
            var letters = new StringBuilder(s.Length);
            foreach (char c in s)
                if (char.IsLetterOrDigit(c)) letters.Append(char.ToLowerInvariant(c));
            return letters.ToString();
        }

        /// <summary>
        /// The site a host belongs to: its last two labels, or three under the likes of co.uk. Not the
        /// full public suffix list, but close enough to group a page's hosts.
        /// </summary>
        private static string Site(string host)
        {
            string[] labels = host.Split('.');
            int n = labels.Length;
            if (n >= 3 && labels[n - 2].Length <= 3 && labels[n - 1].Length == 2)
                return labels[n - 3] + "." + labels[n - 2] + "." + labels[n - 1];
            return n >= 2 ? labels[n - 2] + "." + labels[n - 1] : host;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress, AllocationBase;
            public uint AllocationProtect;
            private uint alignment1;
            public IntPtr RegionSize;
            public uint State, Protect, Type;
            private uint alignment2;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MEMORY_BASIC_INFORMATION info, IntPtr length);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, IntPtr size, out IntPtr read);

        /// <summary>
        /// Calls back with each piece of the process's private, writable memory, where programs keep
        /// their data, up to <see cref="MaxScanBytes"/>. False when Windows will not let this process
        /// read it. 64-bit only, like the other memory reads.
        /// </summary>
        private static bool ReadMemory(int pid, Action<byte[], int> chunk)
        {
            if (IntPtr.Size != 8) return false;
            const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, PROCESS_VM_READ = 0x10;
            const uint MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000, PAGE_READWRITE = 0x04, PAGE_GUARD = 0x100;
            IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid);
            if (process == IntPtr.Zero) return false;
            try
            {
                var buffer = new byte[1 << 20];
                long address = 0, total = 0;
                var size = (IntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                while (total < MaxScanBytes && VirtualQueryEx(process, (IntPtr)address, out MEMORY_BASIC_INFORMATION region, size) != IntPtr.Zero)
                {
                    long regionSize = region.RegionSize.ToInt64();
                    if (region.State == MEM_COMMIT && region.Type == MEM_PRIVATE &&
                        (region.Protect & PAGE_READWRITE) != 0 && (region.Protect & PAGE_GUARD) == 0)
                    {
                        for (long offset = 0; offset < regionSize && total < MaxScanBytes; offset += buffer.Length)
                        {
                            int length = (int)Math.Min(buffer.Length, regionSize - offset);
                            if (!ReadProcessMemory(process, (IntPtr)(region.BaseAddress.ToInt64() + offset), buffer, (IntPtr)length, out IntPtr read)) break;
                            int got = read.ToInt32();
                            total += got;
                            chunk(buffer, got);
                        }
                    }
                    long next = region.BaseAddress.ToInt64() + regionSize;
                    if (next <= address) break;
                    address = next;
                }
                return true;
            }
            finally
            {
                CloseHandle(process);
            }
        }

        /// <summary>The https addresses in a renderer's memory, and its strings that could be a title.</summary>
        private static Reading ReadRenderer(int pid)
        {
            var reading = new Reading { Pid = pid };
            return ReadMemory(pid, (buffer, length) =>
            {
                FindAddresses(buffer, length, 1, reading);
                FindAddresses(buffer, length, 2, reading);
                FindStrings(buffer, length, reading.Strings);
            }) ? reading : null;
        }

        /// <summary>How many copies of each wanted string the browser holds, as UTF-16 text standing alone.</summary>
        private static Dictionary<string, int> CountInBrowser(int pid, HashSet<string> wanted)
        {
            var counts = new Dictionary<string, int>(StringComparer.Ordinal);
            var lengths = new bool[MaxTitle + 1];
            foreach (string s in wanted) lengths[s.Length] = true;
            var run = new StringBuilder(MaxTitle);
            ReadMemory(pid, (b, n) =>
            {
                run.Clear();
                bool tooLong = false;
                for (int i = 0; i + 1 < n; i += 2)
                {
                    char c = (char)(b[i] | b[i + 1] << 8);
                    if (c >= ' ' && c != 0x7F && c < 0xFFF0)
                    {
                        if (run.Length < MaxTitle) run.Append(c);
                        else tooLong = true;
                        continue;
                    }
                    if (!tooLong && run.Length >= MinTitle && lengths[run.Length])
                    {
                        string s = run.ToString();
                        if (wanted.Contains(s))
                        {
                            counts.TryGetValue(s, out int count);
                            counts[s] = count + 1;
                        }
                    }
                    run.Clear();
                    tooLong = false;
                }
            });
            return counts;
        }

        /// <summary>
        /// Strings that read like a title, laid out as Blink keeps them: a reference count, the length,
        /// hash and flags (the lowest flag marking 8-bit text), then the characters.
        /// </summary>
        private static void FindStrings(byte[] b, int n, HashSet<string> found)
        {
            for (int i = 0; i + 12 < n; i += 4)
            {
                uint refs = BitConverter.ToUInt32(b, i), length = BitConverter.ToUInt32(b, i + 4);
                if (refs == 0 || refs > 64 || length < MinTitle || length > MaxTitle) continue;
                bool eightBit = (b[i + 8] & 1) != 0;
                int bytes = (int)length * (eightBit ? 1 : 2);
                if (i + 12 + bytes > n) continue;
                string s = eightBit ? Latin1.GetString(b, i + 12, bytes) : Encoding.Unicode.GetString(b, i + 12, bytes);
                if (IsTitleLike(s)) found.Add(s);
            }
        }

        private static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

        // Words of text: spaced, mostly letters, and none of the marks of code or markup.
        private static bool IsTitleLike(string s)
        {
            if (s.IndexOf(' ') < 0 || s[0] == ' ' || s[s.Length - 1] == ' ' || s.Contains("  ") || s.Contains("://")) return false;
            int letters = 0;
            foreach (char c in s)
            {
                if (c < ' ' || c == 0x7F || "{}<>=;\\`$[]".IndexOf(c) >= 0) return false;
                if (char.IsLetter(c)) letters++;
            }
            return letters * 2 >= s.Length;
        }

        private static bool IsHostChar(byte c) => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';

        // What can follow a host inside an address; anything else means the address ended with the host.
        private static bool IsAddressChar(byte c) => IsHostChar(c) || (c >= 'A' && c <= 'Z') || "/:?#%@_~&=+".IndexOf((char)c) >= 0;

        /// <summary>Counts "https://host" in the buffer, as 8-bit text (step 1) or UTF-16 (step 2).</summary>
        private static void FindAddresses(byte[] b, int n, int step, Reading reading)
        {
            const string lead = "https://";
            int leadLength = lead.Length * step;
            var host = new StringBuilder(64);
            for (int i = 0; i + leadLength < n; i += step)
            {
                if (b[i] != 'h' || (step == 2 && b[i + 1] != 0)) continue;
                bool match = true;
                for (int k = 1; k < lead.Length && match; k++)
                    match = b[i + k * step] == lead[k] && (step == 1 || b[i + k * step + 1] == 0);
                if (!match) continue;

                int j = i + leadLength;
                host.Clear();
                while (j + step - 1 < n && IsHostChar(b[j]) && (step == 1 || b[j + 1] == 0) && host.Length < 100)
                {
                    host.Append((char)b[j]);
                    j += step;
                }
                i = j - step;
                string name = host.ToString().TrimEnd('.', '-');
                if (!IsHostName(name)) continue;
                byte after = j + step - 1 < n ? (step == 1 || b[j + 1] == 0 ? b[j] : (byte)'x') : (byte)0;
                Add(reading.Sites, Site(name));
                if (!IsAddressChar(after)) Add(reading.BareHosts, name);
            }
        }

        // A dotted name ending in letters: not an IP address, nor a fragment cut off mid-name.
        private static bool IsHostName(string name)
        {
            int dot = name.LastIndexOf('.');
            if (dot <= 0 || name.Length - dot - 1 < 2) return false;
            for (int i = dot + 1; i < name.Length; i++)
                if (name[i] < 'a' || name[i] > 'z') return false;
            return true;
        }

        private static void Add(Dictionary<string, int> counts, string key)
        {
            counts.TryGetValue(key, out int n);
            counts[key] = n + 1;
        }
    }
}
