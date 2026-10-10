using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace ProcessStreamgraph
{
    /// <summary>
    /// Site icons for the domains in the Connections window, fetched from each site's own
    /// /favicon.ico (or, failing that, its parent domain's) rather than from an icon service, so no
    /// third party learns which domains are being looked at. Kept on disk for a week, including the
    /// domains that have none.
    /// </summary>
    internal static class Favicons
    {
        private const int Size = 32;
        private const int MaxBytes = 512 * 1024;
        private static readonly TimeSpan MaxAge = TimeSpan.FromDays(7);
        private static readonly string Folder = Path.Combine(SafetyStore.Folder, "favicons");

        private static readonly object gate = new object();
        private static readonly Dictionary<string, Bitmap> known = new Dictionary<string, Bitmap>(StringComparer.OrdinalIgnoreCase);   // null: has none
        private static readonly HashSet<string> queued = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly BlockingCollection<string> work = new BlockingCollection<string>();
        private static readonly HttpClient http = CreateClient();
        private static int workers;

        // Second-level names under which sites register, as in example.co.uk.
        private static readonly HashSet<string> SecondLevels = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "co", "com", "net", "org", "gov", "ac", "edu", "ne", "or", "go"
        };

        /// <summary>Raised on a background thread when an icon has been fetched.</summary>
        public static event Action Loaded;

        private static HttpClient CreateClient()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var handler = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate };
            var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(6) };
            // Some sites turn away requests that do not look like they come from a browser.
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProcessStreamgraph/1.0");
            client.DefaultRequestHeaders.Accept.ParseAdd("image/*");
            return client;
        }

        /// <summary>The domain's icon, or null when it has none or it is still being fetched.</summary>
        public static Bitmap Get(string domain)
        {
            if (string.IsNullOrEmpty(domain) || IPAddress.TryParse(domain, out _) || domain.IndexOf('.') < 0) return null;
            lock (gate)
            {
                if (known.TryGetValue(domain, out Bitmap icon)) return icon;
                if (!queued.Add(domain)) return null;
                // A few at a time: some sites take seconds to answer, or never do.
                if (workers < 3)
                {
                    workers++;
                    new Thread(Work) { IsBackground = true, Name = "Favicons", Priority = ThreadPriority.BelowNormal }.Start();
                }
            }
            work.Add(domain);
            return null;
        }

        private static void Work()
        {
            foreach (string domain in work.GetConsumingEnumerable())
            {
                Bitmap icon = null;
                try
                {
                    icon = FromDisk(domain, out bool cached) ?? (cached ? null : Fetch(domain));
                }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException || e is ExternalException)
                {
                }
                lock (gate)
                {
                    known[domain] = icon;
                    queued.Remove(domain);
                }
                if (icon != null) Loaded?.Invoke();
            }
        }

        private static string FileFor(string domain, bool none) => Path.Combine(Folder, domain.ToLowerInvariant() + (none ? ".none" : ".png"));

        // A stored icon, or null; cached is true when the disk has a recent answer, either way.
        private static Bitmap FromDisk(string domain, out bool cached)
        {
            cached = false;
            foreach (bool none in new[] { false, true })
            {
                string file = FileFor(domain, none);
                if (!File.Exists(file) || DateTime.UtcNow - File.GetLastWriteTimeUtc(file) > MaxAge) continue;
                cached = true;
                if (none) return null;
                using (var stream = new MemoryStream(File.ReadAllBytes(file)))
                using (Image image = Image.FromStream(stream))
                    return Measured(new Bitmap(image));
            }
            return null;
        }

        private static Bitmap Fetch(string domain)
        {
            Bitmap icon = null;
            foreach (string site in Candidates(domain))
            {
                icon = Download("https://" + site + "/favicon.ico");
                if (icon != null) break;
            }
            Directory.CreateDirectory(Folder);
            if (icon != null) icon.Save(FileFor(domain, false), ImageFormat.Png);
            else File.WriteAllBytes(FileFor(domain, true), new byte[0]);
            return icon;
        }

        /// <summary>The domain itself, then the name it is registered under: api.github.com, then github.com.</summary>
        private static IEnumerable<string> Candidates(string domain)
        {
            yield return domain;
            string[] parts = domain.TrimEnd('.').Split('.');
            int keep = parts.Length >= 3 && parts[parts.Length - 1].Length == 2 && SecondLevels.Contains(parts[parts.Length - 2]) ? 3 : 2;
            if (parts.Length > keep) yield return string.Join(".", parts, parts.Length - keep, keep);
        }

        private static Bitmap Download(string url)
        {
            try
            {
                using (HttpResponseMessage response = http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).Result)
                {
                    if (!response.IsSuccessStatusCode) return null;
                    if (response.Content.Headers.ContentLength > MaxBytes) return null;
                    byte[] data = response.Content.ReadAsByteArrayAsync().Result;
                    return data.Length > MaxBytes ? null : Decode(data);
                }
            }
            catch (Exception e) when (e is AggregateException || e is HttpRequestException || e is TaskCanceledException || e is InvalidOperationException)
            {
                return null;
            }
        }

        /// <summary>An icon file, or a PNG, GIF, JPEG or BMP image (which servers often send instead), at 32 pixels.</summary>
        private static Bitmap Decode(byte[] data)
        {
            if (data.Length < 8) return null;
            try
            {
                if (data[0] == 0 && data[1] == 0 && data[2] == 1 && data[3] == 0) return FromIco(data);
                bool image = (data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') ||
                             (data[0] == 'G' && data[1] == 'I' && data[2] == 'F') ||
                             (data[0] == 0xFF && data[1] == 0xD8) ||
                             (data[0] == 'B' && data[1] == 'M');
                return image ? FromImage(data, 0, data.Length) : null;     // anything else is usually an error page
            }
            catch (Exception e) when (e is ArgumentException || e is ExternalException || e is IndexOutOfRangeException || e is OutOfMemoryException)  // GDI+ reports unreadable images as out of memory
            {
                return null;
            }
        }

        // The image nearest 32 pixels across, at least as big when there is one.
        private static Bitmap FromIco(byte[] data)
        {
            int count = BitConverter.ToUInt16(data, 4), best = -1, bestWidth = 0;
            for (int i = 0; i < count && 6 + i * 16 + 16 <= data.Length; i++)
            {
                int width = data[6 + i * 16] == 0 ? 256 : data[6 + i * 16];
                bool better = best < 0 || (bestWidth < Size ? width > bestWidth : width >= Size && width < bestWidth);
                if (better)
                {
                    best = i;
                    bestWidth = width;
                }
            }
            if (best < 0) return null;
            int entry = 6 + best * 16;
            int length = BitConverter.ToInt32(data, entry + 8), offset = BitConverter.ToInt32(data, entry + 12);
            if (offset < 0 || length <= 0 || offset + length > data.Length) return null;
            // Newer icons hold PNG images, which the Icon class cannot always read.
            if (data[offset] == 0x89 && data[offset + 1] == 'P') return FromImage(data, offset, length);
            using (var stream = new MemoryStream(data))
            using (var icon = new Icon(stream, bestWidth, bestWidth))
            using (Bitmap bitmap = icon.ToBitmap())
                return Scaled(bitmap);
        }

        private static Bitmap FromImage(byte[] data, int offset, int length)
        {
            using (var stream = new MemoryStream(data, offset, length))
            using (Image image = Image.FromStream(stream))
                return Scaled(image);
        }

        private static Bitmap Scaled(Image image)
        {
            var result = new Bitmap(Size, Size, PixelFormat.Format32bppArgb);
            using (Graphics g = Graphics.FromImage(result))
            {
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                g.DrawImage(image, new Rectangle(0, 0, Size, Size));
            }
            return Measured(result);
        }

        /// <summary>
        /// How light the icon's visible pixels are, from 0 for black to 1 for white, kept in its Tag:
        /// a black logo cannot be seen on a dark row, nor a white one on a light row.
        /// </summary>
        public static float Lightness(Bitmap icon) => icon.Tag is float lightness ? lightness : 0.5f;

        private static Bitmap Measured(Bitmap icon)
        {
            double sum = 0, weight = 0;
            for (int y = 0; y < icon.Height; y++)
                for (int x = 0; x < icon.Width; x++)
                {
                    Color c = icon.GetPixel(x, y);
                    double alpha = c.A / 255.0;
                    sum += alpha * (c.R * 0.299 + c.G * 0.587 + c.B * 0.114) / 255;
                    weight += alpha;
                }
            icon.Tag = weight > 0 ? (float)(sum / weight) : 0.5f;
            return icon;
        }
    }
}
