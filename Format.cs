using System.Globalization;

namespace ProcessStreamgraph
{
    internal static class Format
    {
        public static string Cpu(double percent)
        {
            if (percent <= 0) return "";
            if (percent < 0.05) return "< 0.1";
            return percent.ToString("0.0", CultureInfo.CurrentCulture);
        }

        public static string CpuPercent(double percent)
        {
            if (percent > 0 && percent < 0.05) return "< 0.1%";
            return percent.ToString("0.0", CultureInfo.CurrentCulture) + "%";
        }

        public static string Memory(double megabytes)
        {
            if (megabytes >= 1024) return (megabytes / 1024).ToString("0.00", CultureInfo.CurrentCulture) + " GB";
            if (megabytes >= 1) return megabytes.ToString("0.0", CultureInfo.CurrentCulture) + " MB";
            return (megabytes * 1024).ToString("0", CultureInfo.CurrentCulture) + " KB";
        }

        /// <summary>Transfer rate given in KB/s.</summary>
        public static string Rate(double kilobytesPerSecond)
        {
            if (kilobytesPerSecond >= 1024) return (kilobytesPerSecond / 1024).ToString("0.00", CultureInfo.CurrentCulture) + " MB/s";
            if (kilobytesPerSecond >= 1) return kilobytesPerSecond.ToString("0.0", CultureInfo.CurrentCulture) + " KB/s";
            return (kilobytesPerSecond * 1024).ToString("0", CultureInfo.CurrentCulture) + " B/s";
        }

        /// <summary>Compact rate for axis ticks, which are always round numbers.</summary>
        public static string RateTick(double kilobytesPerSecond)
        {
            if (kilobytesPerSecond >= 1024) return (kilobytesPerSecond / 1024).ToString("0.##", CultureInfo.CurrentCulture) + " MB/s";
            return kilobytesPerSecond.ToString("0.##", CultureInfo.CurrentCulture) + " KB/s";
        }

        public static string Value(Metric metric, double value) =>
            metric == Metric.Cpu ? CpuPercent(value) : metric == Metric.Memory ? Memory(value) : Rate(value);
    }
}
