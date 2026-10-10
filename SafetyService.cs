using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProcessStreamgraph
{
    /// <summary>API keys and choices for the online sources. Kept encrypted for the current Windows user.</summary>
    internal sealed class SafetySettings
    {
        public string VirusTotalKey = "";
        public string MetaDefenderKey = "";
        public string AbuseChKey = "";
        public bool UseLists = true;     // CISA's exploited-vulnerability list, endoflife.date and the malware host lists; no account needed
        public bool AskDnsFilters = true;    // ask Cloudflare's and Quad9's malware-blocking DNS about the domains processes talk to

        public string KeyFor(string source)
        {
            switch (source)
            {
                case SafetySources.VirusTotal: return VirusTotalKey;
                case SafetySources.MetaDefender: return MetaDefenderKey;
                case SafetySources.MalwareBazaar: return AbuseChKey;
                default: return "";
            }
        }

        public SafetySettings Clone() => (SafetySettings)MemberwiseClone();
    }

    /// <summary>Where the safety data lives: settings, downloaded lists and cached results.</summary>
    internal static class SafetyStore
    {
        public static readonly string Folder =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ProcessStreamgraph");

        private static string SettingsFile => Path.Combine(Folder, "safety-settings.dat");
        public static string CacheFile => Path.Combine(Folder, "safety-cache.json");
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("ProcessStreamgraph safety settings");

        public static SafetySettings LoadSettings()
        {
            var settings = new SafetySettings();
            try
            {
                if (!File.Exists(SettingsFile)) return settings;
                byte[] plain = ProtectedData.Unprotect(File.ReadAllBytes(SettingsFile), Entropy, DataProtectionScope.CurrentUser);
                object root = Json.Parse(Encoding.UTF8.GetString(plain));
                settings.VirusTotalKey = Json.Str(root, "virusTotal") ?? "";
                settings.MetaDefenderKey = Json.Str(root, "metaDefender") ?? "";
                settings.AbuseChKey = Json.Str(root, "abuseCh") ?? "";
                settings.UseLists = Json.Get(root, "useLists") is bool useLists ? useLists : true;
                settings.AskDnsFilters = Json.Get(root, "askDnsFilters") is bool askDns ? askDns : true;
            }
            catch (Exception e) when (e is IOException || e is CryptographicException || e is UnauthorizedAccessException)
            {
                // Unreadable settings, perhaps from another Windows account: start afresh.
            }
            return settings;
        }

        public static void SaveSettings(SafetySettings settings)
        {
            string json = Json.Write(new Dictionary<string, object>
            {
                ["virusTotal"] = settings.VirusTotalKey,
                ["metaDefender"] = settings.MetaDefenderKey,
                ["abuseCh"] = settings.AbuseChKey,
                ["useLists"] = settings.UseLists,
                ["askDnsFilters"] = settings.AskDnsFilters
            });
            Directory.CreateDirectory(Folder);
            File.WriteAllBytes(SettingsFile, ProtectedData.Protect(Encoding.UTF8.GetBytes(json), Entropy, DataProtectionScope.CurrentUser));
        }
    }

    /// <summary>
    /// File hashes, signature checks and the online services' answers, saved between runs so each file
    /// is examined once a week rather than every start. Used from several threads.
    /// </summary>
    internal sealed class SafetyCache
    {
        public static readonly TimeSpan Lifetime = TimeSpan.FromDays(7);

        /// <summary>What is known about one program file, valid while its size and date are unchanged.</summary>
        private sealed class FileRecord
        {
            public long Size, Ticks;
            public string Sha256;
            // Verifying a signature takes around 0.2 s a file, so the answer is kept too, and checked
            // again after a week in case the certificate has since been revoked.
            public SignatureState? Signature;
            public string Signer, Detail;
            public DateTime SignatureChecked;
        }

        private readonly object gate = new object();
        private readonly Dictionary<string, FileRecord> files = new Dictionary<string, FileRecord>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Dictionary<string, SourceResult>> results =
            new Dictionary<string, Dictionary<string, SourceResult>>(StringComparer.OrdinalIgnoreCase);
        private bool dirty;

        public SafetyCache()
        {
            try
            {
                if (!File.Exists(SafetyStore.CacheFile)) return;
                object root = Json.Parse(File.ReadAllText(SafetyStore.CacheFile));
                if (Json.Get(root, "files") is IDictionary<string, object> saved)
                {
                    foreach (KeyValuePair<string, object> file in saved)
                    {
                        var record = new FileRecord
                        {
                            Size = Json.Long(file.Value, "size"),
                            Ticks = Json.Long(file.Value, "ticks"),
                            Sha256 = Json.Str(file.Value, "sha256"),
                            Signer = Json.Str(file.Value, "signer"),
                            Detail = Json.Str(file.Value, "signatureDetail"),
                            SignatureChecked = new DateTime(Json.Long(file.Value, "signatureChecked"), DateTimeKind.Utc)
                        };
                        if (Json.Get(file.Value, "signature") != null) record.Signature = (SignatureState)Json.Long(file.Value, "signature");
                        files[file.Key] = record;
                    }
                }
                if (Json.Get(root, "results") is IDictionary<string, object> bySha)
                {
                    foreach (KeyValuePair<string, object> entry in bySha)
                    {
                        var bySource = new Dictionary<string, SourceResult>();
                        foreach (object r in Json.Array(entry.Value))
                        {
                            var result = new SourceResult
                            {
                                Source = Json.Str(r, "source"),
                                Verdict = (Safety)Json.Long(r, "verdict"),
                                Summary = Json.Str(r, "summary"),
                                Link = Json.Str(r, "link"),
                                Checked = new DateTime(Json.Long(r, "checked"), DateTimeKind.Utc)
                            };
                            if (result.Source != null) bySource[result.Source] = result;
                        }
                        results[entry.Key] = bySource;
                    }
                }
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is InvalidCastException || e is ArgumentException)
            {
                // A damaged cache only costs some repeated lookups.
            }
        }

        // The record for a file as it is now, or a fresh one when the file is new or has changed.
        private FileRecord Current(string path)
        {
            var info = new FileInfo(path);
            long size = info.Length, ticks = info.LastWriteTimeUtc.Ticks;
            lock (gate)
            {
                if (files.TryGetValue(path, out FileRecord known) && known.Size == size && known.Ticks == ticks) return known;
                var record = new FileRecord { Size = size, Ticks = ticks };
                files[path] = record;
                dirty = true;
                return record;
            }
        }

        /// <summary>The file's SHA-256, worked out again only if the file has changed since last time.</summary>
        public string HashOf(string path)
        {
            FileRecord record = Current(path);
            lock (gate)
            {
                if (record.Sha256 != null) return record.Sha256;
            }
            using (FileStream stream = FileSignature.OpenShared(path))
            {
                if (stream == null) return null;
                string sha;
                using (SHA256 algorithm = SHA256.Create())
                    sha = BitConverter.ToString(algorithm.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                lock (gate)
                {
                    record.Sha256 = sha;
                    dirty = true;
                }
                return sha;
            }
        }

        /// <summary>The file's signature, verified again only if the file has changed or a week has passed.</summary>
        public SignatureState SignatureOf(string path, out string signer, out string detail)
        {
            FileRecord record = Current(path);
            lock (gate)
            {
                if (record.Signature.HasValue && DateTime.UtcNow - record.SignatureChecked < Lifetime)
                {
                    signer = record.Signer;
                    detail = record.Detail;
                    return record.Signature.Value;
                }
            }
            SignatureState state = FileSignature.Check(path, out signer, out detail);
            lock (gate)
            {
                record.Signature = state;
                record.Signer = signer;
                record.Detail = detail;
                record.SignatureChecked = DateTime.UtcNow;
                dirty = true;
            }
            return state;
        }

        public SourceResult Fresh(string sha256, string source)
        {
            lock (gate)
            {
                return results.TryGetValue(sha256, out var bySource) && bySource.TryGetValue(source, out SourceResult r) &&
                       DateTime.UtcNow - r.Checked < Lifetime ? r : null;
            }
        }

        public void Store(string sha256, SourceResult result)
        {
            lock (gate)
            {
                if (!results.TryGetValue(sha256, out var bySource)) results[sha256] = bySource = new Dictionary<string, SourceResult>();
                bySource[result.Source] = result;
                dirty = true;
            }
        }

        public void Save()
        {
            string json;
            lock (gate)
            {
                if (!dirty) return;
                var saved = new Dictionary<string, object>();
                foreach (var file in files)
                {
                    FileRecord r = file.Value;
                    var entry = new Dictionary<string, object> { ["size"] = r.Size, ["ticks"] = r.Ticks, ["sha256"] = r.Sha256 };
                    if (r.Signature.HasValue)
                    {
                        entry["signature"] = (int)r.Signature.Value;
                        entry["signer"] = r.Signer;
                        entry["signatureDetail"] = r.Detail;
                        entry["signatureChecked"] = r.SignatureChecked.Ticks;
                    }
                    saved[file.Key] = entry;
                }
                var bySha = new Dictionary<string, object>();
                foreach (var entry in results)
                {
                    var list = new List<object>();
                    foreach (SourceResult r in entry.Value.Values)
                        list.Add(new Dictionary<string, object>
                        {
                            ["source"] = r.Source, ["verdict"] = (int)r.Verdict, ["summary"] = r.Summary,
                            ["link"] = r.Link, ["checked"] = r.Checked.Ticks
                        });
                    bySha[entry.Key] = list;
                }
                json = Json.Write(new Dictionary<string, object> { ["files"] = saved, ["results"] = bySha });
                dirty = false;
            }
            try
            {
                Directory.CreateDirectory(SafetyStore.Folder);
                File.WriteAllText(SafetyStore.CacheFile, json);
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                lock (gate) dirty = true;
            }
        }
    }

    /// <summary>
    /// Rates each program file from every available source: its signature, the published vulnerability
    /// and support lists, and the malware scanners an API key has been given for. Work happens on
    /// background threads; reports are only changed on the UI thread.
    /// </summary>
    internal sealed class SafetyService : IDisposable
    {
        private readonly SynchronizationContext ui;
        private readonly Dictionary<string, SafetyReport> reports = new Dictionary<string, SafetyReport>(StringComparer.OrdinalIgnoreCase);
        private readonly SafetyCache cache = new SafetyCache();
        private readonly BlockingCollection<Action> localWork = new BlockingCollection<Action>();
        // Hosts have their own queue, so that slow DNS answers never hold up the checks of programs.
        private readonly BlockingCollection<Action> hostWork = new BlockingCollection<Action>();
        private readonly ConcurrentDictionary<string, SourceResult> dnsAnswers = new ConcurrentDictionary<string, SourceResult>();
        private readonly Dictionary<string, Lookup> lookups = new Dictionary<string, Lookup>();
        private readonly CancellationTokenSource stop = new CancellationTokenSource();
        private readonly Timer saveTimer;
        private volatile SafetySettings settings = SafetyStore.LoadSettings();

        public SafetyService()
        {
            ui = SynchronizationContext.Current ?? throw new InvalidOperationException("SafetyService must be created on the UI thread.");
            new Thread(() =>
            {
                try
                {
                    foreach (Action work in localWork.GetConsumingEnumerable(stop.Token)) work();
                }
                catch (OperationCanceledException)
                {
                }
            }) { IsBackground = true, Name = "Safety checks", Priority = ThreadPriority.BelowNormal }.Start();
            new Thread(() =>
            {
                try
                {
                    foreach (Action work in hostWork.GetConsumingEnumerable(stop.Token)) work();
                }
                catch (OperationCanceledException)
                {
                }
            }) { IsBackground = true, Name = "Host safety checks", Priority = ThreadPriority.BelowNormal }.Start();

            // The free tiers allow about 4 requests a minute at VirusTotal; the others are more generous.
            // VirusTotal is asked about hosts too, in the same queue, so that they share its quota.
            AddLookup(SafetySources.VirusTotal, TimeSpan.FromSeconds(16), (string subject, string key, out bool retryLater) =>
                HostSources.IsSubject(subject)
                    ? HostSources.QueryVirusTotal(subject, key, out retryLater)
                    : SafetySources.QueryVirusTotal(subject, key, out retryLater));
            AddLookup(SafetySources.MetaDefender, TimeSpan.FromSeconds(3), SafetySources.QueryMetaDefender);
            AddLookup(SafetySources.MalwareBazaar, TimeSpan.FromSeconds(2), SafetySources.QueryMalwareBazaar);

            saveTimer = new Timer(_ => cache.Save(), null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
        }

        /// <summary>Raised on the UI thread whenever any report changes.</summary>
        public event Action Updated;

        public SafetySettings Settings => settings.Clone();

        public void ApplySettings(SafetySettings changed)
        {
            SafetySettings old = settings;
            settings = changed.Clone();
            SafetyStore.SaveSettings(settings);

            foreach (SafetyReport report in reports.Values)
            {
                // Drop the answers of sources that have been switched off.
                foreach (string source in new[] { SafetySources.VirusTotal, SafetySources.MetaDefender, SafetySources.MalwareBazaar })
                    if (string.IsNullOrWhiteSpace(changed.KeyFor(source))) report.Remove(source);
                if (!changed.UseLists)
                {
                    report.Remove(SafetySources.Kev);
                    report.Remove(SafetySources.EndOfLife);
                    report.Remove(HostSources.UrlHaus);
                    report.Remove(HostSources.IpLists);
                }
                if (!changed.AskDnsFilters)
                {
                    report.Remove(HostSources.Cloudflare);
                    report.Remove(HostSources.Quad9);
                }
            }
            bool newKey = false;
            foreach (string source in new[] { SafetySources.VirusTotal, SafetySources.MetaDefender, SafetySources.MalwareBazaar })
                if (changed.KeyFor(source).Trim() != old.KeyFor(source).Trim() && !string.IsNullOrWhiteSpace(changed.KeyFor(source))) newKey = true;
            if (newKey || (changed.UseLists && !old.UseLists))
                foreach (SafetyReport report in reports.Values) Examine(report, false);
            else if (changed.AskDnsFilters && !old.AskDnsFilters)
                foreach (SafetyReport report in reports.Values)
                    if (report.IsHost) Examine(report, false);
        }

        /// <summary>
        /// The report for a remote host, started the first time it is asked for. The domain is the one
        /// the process looked up, or null when there is none; the address is checked either way.
        /// </summary>
        public SafetyReport ReportForHost(string domain, System.Net.IPAddress address)
        {
            string key = "host:" + (domain ?? "").ToLowerInvariant() + "|" + address;
            if (reports.TryGetValue(key, out SafetyReport report)) return report;
            report = new SafetyReport { Name = domain ?? address.ToString(), Domain = domain, Address = address.ToString() };
            report.Changed += () => Updated?.Invoke();
            reports[key] = report;
            Examine(report, false);
            return report;
        }

        /// <summary>The report for a process's program, started the first time the program is seen.</summary>
        public SafetyReport ReportFor(ProcInfo process)
        {
            string key = process.Path ?? "name:" + process.Name;
            if (reports.TryGetValue(key, out SafetyReport report)) return report;

            report = new SafetyReport { Path = process.Path, Name = process.Name };
            report.Changed += () => Updated?.Invoke();
            reports[key] = report;

            AppRating notes = AppRatings.Find(process.Name, process.Path);
            if (notes != null) report.Set(AppRatings.ToResult(notes));
            if (process.Path == null)
            {
                report.Set(new SourceResult
                {
                    Source = SafetySources.Signature, Verdict = Safety.Unrated, Checked = DateTime.UtcNow,
                    Summary = process.Pid == 0 || process.Pid == 4 || process.Name == "Registry" || process.Name == "Memory Compression" || process.Name == "Secure System"
                        ? "Part of the Windows kernel, with no program file of its own to check."
                        : "Its program file could not be located, so it cannot be checked. Running as administrator usually reveals it."
                });
                return report;
            }
            Examine(report, false);
            return report;
        }

        /// <summary>Checks a program again, asking the online services afresh rather than using cached answers.</summary>
        public void Recheck(SafetyReport report)
        {
            if (report.Path != null || report.IsHost) Examine(report, true);
        }

        private void Examine(SafetyReport report, bool fresh)
        {
            if (report.IsHost)
            {
                ExamineHost(report, fresh);
                return;
            }
            SafetySettings current = settings;
            Interlocked.Increment(ref report.Pending);
            report.NotifyChanged();
            string path = report.Path, name = report.Name;
            localWork.Add(() =>
            {
                try
                {
                    ExamineFile(report, path, name, current, fresh);
                }
                catch (Exception e) when (!(e is OutOfMemoryException))
                {
                    Post(report, new SourceResult
                    {
                        Source = SafetySources.Signature, Verdict = Safety.Unrated, Checked = DateTime.UtcNow,
                        Summary = "The file could not be checked: " + e.Message
                    });
                }
                finally
                {
                    Done(report);
                }
            });
        }

        // On the local worker thread.
        private void ExamineFile(SafetyReport report, string path, string name, SafetySettings current, bool fresh)
        {
            if (!File.Exists(path))
            {
                Post(report, new SourceResult
                {
                    Source = SafetySources.Signature, Verdict = Safety.Unrated, Checked = DateTime.UtcNow,
                    Summary = "The program file is not accessible, so it cannot be checked."
                });
                return;
            }

            FileVersionInfo version = FileVersionInfo.GetVersionInfo(path);
            var facts = new FileFacts
            {
                Path = path,
                Name = name,
                ProductName = version.ProductName?.Trim(),
                FileDescription = version.FileDescription?.Trim(),
                CompanyName = version.CompanyName?.Trim(),
                ProductVersion = version.ProductVersion?.Trim(),
                WrittenUtc = File.GetLastWriteTimeUtc(path)
            };
            facts.Signature = cache.SignatureOf(path, out facts.Signer, out string detail);
            facts.Sha256 = cache.HashOf(path);
            SourceResult signature = SafetySources.FromSignature(facts, detail);
            string publisher = facts.Signer ?? (string.IsNullOrEmpty(facts.CompanyName) ? null : facts.CompanyName);
            ui.Post(_ =>
            {
                report.Sha256 = facts.Sha256;
                report.Publisher = publisher;
                report.Set(signature);
            }, null);

            if (current.UseLists)
            {
                object kev = SafetySources.KevFeed.Load();
                Post(report, kev != null ? SafetySources.CheckKev(facts, kev) : Unreachable(SafetySources.Kev, SafetySources.KevFeed.Error));
                object eol = SafetySources.EndOfLifeFeed.Load();
                Post(report, eol != null ? SafetySources.CheckEndOfLife(facts, eol) : Unreachable(SafetySources.EndOfLife, SafetySources.EndOfLifeFeed.Error));
            }

            if (facts.Sha256 == null) return;
            // Windows' own files are the least likely to be a problem, so they wait at the back of the queue.
            int priority = facts.IsWindowsComponent ? 2 : facts.Signature == SignatureState.Valid ? 1 : 0;
            foreach (Lookup lookup in lookups.Values)
            {
                if (string.IsNullOrWhiteSpace(current.KeyFor(lookup.Source))) continue;
                SourceResult known = fresh ? null : cache.Fresh(facts.Sha256, lookup.Source);
                if (known != null)
                {
                    Post(report, known);
                    continue;
                }
                Interlocked.Increment(ref report.Pending);
                lookup.Enqueue(facts.Sha256, report, priority);
            }
        }

        private void ExamineHost(SafetyReport report, bool fresh)
        {
            SafetySettings current = settings;
            var address = System.Net.IPAddress.Parse(report.Address);
            string domain = report.Domain;
            Interlocked.Increment(ref report.Pending);
            report.NotifyChanged();
            hostWork.Add(() =>
            {
                try
                {
                    if (current.UseLists)
                    {
                        Post(report, HostSources.CheckUrlHaus(domain, address));
                        Post(report, HostSources.CheckIpLists(address));
                    }
                    if (current.AskDnsFilters && domain != null)
                    {
                        // A day's answer will do: hosts come and go from the lists more slowly than that.
                        foreach (string source in new[] { HostSources.Cloudflare, HostSources.Quad9 })
                        {
                            string key = source + "|" + domain.ToLowerInvariant();
                            if (fresh || !dnsAnswers.TryGetValue(key, out SourceResult known) || DateTime.UtcNow - known.Checked > TimeSpan.FromDays(1))
                            {
                                known = source == HostSources.Cloudflare ? HostSources.AskCloudflare(domain) : HostSources.AskQuad9(domain);
                                if (!known.Failed) dnsAnswers[key] = known;
                            }
                            Post(report, known);
                        }
                    }
                }
                catch (Exception e) when (!(e is OutOfMemoryException))
                {
                    Post(report, SafetySources.Failure(HostSources.IpLists, "The host could not be checked: " + e.Message));
                }
                finally
                {
                    Done(report);
                }
            });

            if (lookups.TryGetValue(SafetySources.VirusTotal, out Lookup virusTotal) && !string.IsNullOrWhiteSpace(current.VirusTotalKey))
            {
                string subject = HostSources.Subject(domain, address);
                SourceResult known = fresh ? null : cache.Fresh(subject, SafetySources.VirusTotal);
                if (known != null)
                {
                    report.Set(known);
                    return;
                }
                // After programs: their files are the more likely threat, and the quota is small.
                Interlocked.Increment(ref report.Pending);
                virusTotal.Enqueue(subject, report, 3);
            }
        }

        private static SourceResult Unreachable(string source, string error) =>
            SafetySources.Failure(source, "Could not download the list" + (string.IsNullOrEmpty(error) ? "." : ": " + error));

        private void Post(SafetyReport report, SourceResult result) => ui.Post(_ => report.Set(result), null);

        private void Done(SafetyReport report)
        {
            Interlocked.Decrement(ref report.Pending);
            ui.Post(_ => report.NotifyChanged(), null);
        }

        private void AddLookup(string source, TimeSpan interval, Query query)
        {
            lookups[source] = new Lookup(this, source, interval, query);
        }

        public void Dispose()
        {
            stop.Cancel();
            foreach (Lookup lookup in lookups.Values) lookup.Wake();
            saveTimer.Dispose();
            cache.Save();
        }

        private delegate SourceResult Query(string sha256, string key, out bool retryLater);

        /// <summary>One online service, asked one file at a time and no faster than its free tier allows.</summary>
        private sealed class Lookup
        {
            private readonly SafetyService owner;
            private readonly TimeSpan interval;
            private readonly Query query;
            private readonly object gate = new object();
            // Waiting files by hash, each with the reports that want the answer and the most urgent priority asked for.
            private readonly Dictionary<string, (int Priority, long Order, List<SafetyReport> Reports)> waiting =
                new Dictionary<string, (int, long, List<SafetyReport>)>();
            private readonly SemaphoreSlim signal = new SemaphoreSlim(0);
            private long order;

            public Lookup(SafetyService owner, string source, TimeSpan interval, Query query)
            {
                this.owner = owner;
                Source = source;
                this.interval = interval;
                this.query = query;
                new Thread(Run) { IsBackground = true, Name = source + " lookups" }.Start();
            }

            public string Source { get; }

            public void Enqueue(string sha256, SafetyReport report, int priority)
            {
                lock (gate)
                {
                    if (waiting.TryGetValue(sha256, out var entry))
                    {
                        entry.Reports.Add(report);
                        waiting[sha256] = (Math.Min(priority, entry.Priority), entry.Order, entry.Reports);
                        // The existing entry already has a turn coming; this report's pending count still needs settling.
                        return;
                    }
                    waiting[sha256] = (priority, order++, new List<SafetyReport> { report });
                }
                signal.Release();
            }

            public void Wake() => signal.Release();

            private void Run()
            {
                CancellationToken token = owner.stop.Token;
                while (!token.IsCancellationRequested)
                {
                    signal.Wait();
                    if (token.IsCancellationRequested) return;

                    string sha256;
                    List<SafetyReport> reports;
                    lock (gate)
                    {
                        sha256 = null;
                        (int Priority, long Order, List<SafetyReport> Reports) best = default;
                        foreach (var entry in waiting)
                        {
                            if (sha256 == null || entry.Value.Priority < best.Priority ||
                                (entry.Value.Priority == best.Priority && entry.Value.Order < best.Order))
                            {
                                sha256 = entry.Key;
                                best = entry.Value;
                            }
                        }
                        if (sha256 == null) continue;
                        waiting.Remove(sha256);
                        reports = best.Reports;
                    }

                    string key = owner.settings.KeyFor(Source).Trim();
                    SourceResult result = null;
                    bool retry = false;
                    if (key.Length > 0)
                    {
                        try
                        {
                            result = query(sha256, key, out retry);
                        }
                        catch (Exception e) when (e is AggregateException || e is HttpRequestException || e is TaskCanceledException || e is InvalidOperationException)
                        {
                            Exception inner = e is AggregateException aggregate ? aggregate.GetBaseException() : e;
                            result = SafetySources.Failure(Source, $"Could not reach {Source}: {inner.Message}");
                        }
                    }

                    if (retry)
                    {
                        // Over the quota: show why it is waiting, then try the same file again in a minute.
                        foreach (SafetyReport report in reports) owner.ui.Post(_ => report.Set(result), null);
                        lock (gate)
                        {
                            waiting[sha256] = (-1, order++, reports);
                        }
                        signal.Release();
                        token.WaitHandle.WaitOne(TimeSpan.FromMinutes(1));
                        continue;
                    }

                    // Answers about the file are kept; failures to get one are not.
                    if (result != null && !result.Failed) owner.cache.Store(sha256, result);
                    foreach (SafetyReport report in reports)
                    {
                        if (result != null) owner.Post(report, result);
                        owner.Done(report);
                    }
                    if (key.Length > 0) token.WaitHandle.WaitOne(interval);
                }
            }
        }
    }
}
