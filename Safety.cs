using System;
using System.Collections.Generic;
using System.Drawing;

namespace ProcessStreamgraph
{
    /// <summary>Safety rating of a program, from best to worst; Unrated sits below them all.</summary>
    internal enum Safety { Unrated = -1, Safe, LowRisk, Caution, HighRisk }

    /// <summary>What one source says about a program file or a remote host.</summary>
    internal sealed class SourceResult
    {
        public string Source;       // e.g. "VirusTotal"
        public Safety Verdict;      // Unrated when the source has no opinion, such as a hash it has never seen
        public string Summary;      // a sentence or two on what the source found
        public string Link;         // the source's own page for this file or issue; may be null
        public DateTime Checked;    // UTC
        public bool Failed;         // the source could not be asked; not worth keeping
    }

    /// <summary>
    /// The combined safety picture for one program file, shared by every process running it, or for
    /// one remote host that processes talk to. Only touched on the UI thread.
    /// </summary>
    internal sealed class SafetyReport
    {
        private readonly List<SourceResult> results = new List<SourceResult>();

        public string Path;             // null for processes whose file cannot be found
        public string Name;
        public string Sha256;           // lower-case hex; null until hashed
        public string Publisher;        // the signer, or failing that the company in the version information
        public int Pending;             // lookups still under way
        public string Domain;           // for a remote host: its domain, or null when it has none
        public string Address;          // for a remote host: its address; null for a program

        public bool IsHost => Address != null;

        public IReadOnlyList<SourceResult> Results => results;

        /// <summary>
        /// The rating to show: the worst of what the sources found. One alarming finding is reason
        /// enough to look closer, however many others are clean.
        /// </summary>
        public Safety Overall { get; private set; } = Safety.Unrated;

        public event Action Changed;

        public void Set(SourceResult result)
        {
            int index = results.FindIndex(r => r.Source == result.Source);
            if (index >= 0) results[index] = result;
            else results.Add(result);
            results.Sort((a, b) => SourceOrder(a.Source).CompareTo(SourceOrder(b.Source)));

            Safety overall = Safety.Unrated;
            foreach (SourceResult r in results)
                if (r.Verdict > overall) overall = r.Verdict;
            Overall = overall;
            Changed?.Invoke();
        }

        public SourceResult Find(string source) => results.Find(r => r.Source == source);

        public void Remove(string source)
        {
            if (results.RemoveAll(r => r.Source == source) == 0) return;
            Safety overall = Safety.Unrated;
            foreach (SourceResult r in results)
                if (r.Verdict > overall) overall = r.Verdict;
            Overall = overall;
            Changed?.Invoke();
        }

        public void NotifyChanged() => Changed?.Invoke();

        // Malware scanners first, then vulnerability and support status, then the file itself.
        private static int SourceOrder(string source)
        {
            int index = Array.IndexOf(SafetySources.All, source);
            return index < 0 ? int.MaxValue : index;
        }
    }

    internal static class SafetyStyle
    {
        public static string Title(Safety safety)
        {
            switch (safety)
            {
                case Safety.Safe: return "Safe";
                case Safety.LowRisk: return "Low risk";
                case Safety.Caution: return "Caution";
                case Safety.HighRisk: return "High risk";
                default: return "Unrated";
            }
        }

        public static Color ColorOf(Safety safety, bool dark)
        {
            switch (safety)
            {
                case Safety.Safe: return dark ? Color.FromArgb(0x3f, 0xb9, 0x5f) : Color.FromArgb(0x23, 0x8a, 0x42);
                case Safety.LowRisk: return dark ? Color.FromArgb(0x9c, 0xc9, 0x4a) : Color.FromArgb(0x6e, 0x9e, 0x22);
                case Safety.Caution: return dark ? Color.FromArgb(0xf0, 0xb4, 0x3c) : Color.FromArgb(0xe0, 0x9a, 0x10);
                case Safety.HighRisk: return dark ? Color.FromArgb(0xf0, 0x5d, 0x5d) : Color.FromArgb(0xd0, 0x3a, 0x3a);
                default: return dark ? Color.FromArgb(0x6a, 0x6a, 0x66) : Color.FromArgb(0xa8, 0xa7, 0xa0);
            }
        }

        /// <summary>Black or white, whichever reads better on the given badge colour.</summary>
        public static Color InkOn(Color color) =>
            color.R * 0.299 + color.G * 0.587 + color.B * 0.114 > 150 ? Color.FromArgb(0x1a, 0x1a, 0x19) : Color.White;
    }
}
