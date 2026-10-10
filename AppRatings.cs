using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace ProcessStreamgraph
{
#pragma warning disable CS0649   // the fields below are filled in by the JSON serializer
    [DataContract]
    internal sealed class AppRating
    {
        [DataMember(Name = "name")] public string Name;              // image name, e.g. "brave.exe"
        [DataMember(Name = "path", EmitDefaultValue = false)] public string PathContains;   // optional, for names shared by two programs
        [DataMember(Name = "app")] public string App;
        [DataMember(Name = "publisher")] public string Publisher;
        [DataMember(Name = "rating")] public string RatingText;
        [DataMember(Name = "notes")] public string Notes;
        [DataMember(Name = "source", EmitDefaultValue = false)] public string Source;

        public Safety Rating;
    }

    [DataContract]
    internal sealed class AppRatingFile
    {
        [DataMember(Name = "checked")] public string Checked;
        [DataMember(Name = "apps")] public List<AppRating> Apps;
    }
#pragma warning restore CS0649

    /// <summary>
    /// Hand-written ratings of known programs, kept in AppRatings.json next to the executable. They add
    /// what the online sources cannot know, such as a program being abandoned, and are one source
    /// among several in a program's safety report.
    /// </summary>
    internal static class AppRatings
    {
        public const string FileName = "AppRatings.json";

        private static readonly Dictionary<string, List<AppRating>> byName = Load();

        public static string Checked { get; private set; }

        /// <summary>The rating for a program, or null when it has not been rated.</summary>
        public static AppRating Find(string name, string path)
        {
            if (name == null || !byName.TryGetValue(name, out List<AppRating> entries)) return null;
            AppRating fallback = null;
            foreach (AppRating entry in entries)
            {
                if (entry.PathContains == null) fallback = fallback ?? entry;
                else if (path != null && path.IndexOf(entry.PathContains, StringComparison.OrdinalIgnoreCase) >= 0) return entry;
            }
            return fallback;
        }

        public static SourceResult ToResult(AppRating rating)
        {
            DateTime.TryParse(Checked, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out DateTime checkedUtc);
            string notes = string.IsNullOrEmpty(rating.Notes) ? "" : " " + rating.Notes;
            return new SourceResult
            {
                Source = SafetySources.Notes,
                Verdict = rating.Rating,
                Summary = $"{rating.App}, rated {SafetyStyle.Title(rating.Rating).ToLowerInvariant()} in {FileName}" +
                          (string.IsNullOrEmpty(Checked) ? "." : $" on {Checked}.") + notes,
                Link = string.IsNullOrEmpty(rating.Source) ? null : rating.Source,
                Checked = checkedUtc
            };
        }

        private static Safety Parse(string text)
        {
            switch ((text ?? "").Replace(" ", "").ToLowerInvariant())
            {
                case "safe": return Safety.Safe;
                case "lowrisk": return Safety.LowRisk;
                case "caution": return Safety.Caution;
                case "highrisk": return Safety.HighRisk;
                default: return Safety.Unrated;
            }
        }

        private static Dictionary<string, List<AppRating>> Load()
        {
            var map = new Dictionary<string, List<AppRating>>(StringComparer.OrdinalIgnoreCase);
            string file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, FileName);
            try
            {
                AppRatingFile data;
                using (FileStream stream = File.OpenRead(file))
                    data = (AppRatingFile)new DataContractJsonSerializer(typeof(AppRatingFile)).ReadObject(stream);
                Checked = data.Checked;
                foreach (AppRating entry in data.Apps ?? new List<AppRating>())
                {
                    if (string.IsNullOrEmpty(entry.Name)) continue;
                    entry.Rating = Parse(entry.RatingText);
                    if (!map.TryGetValue(entry.Name, out List<AppRating> list)) map[entry.Name] = list = new List<AppRating>();
                    list.Add(entry);
                }
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is SerializationException)
            {
                // Without the file every program is simply unrated.
            }
            return map;
        }
    }
}
