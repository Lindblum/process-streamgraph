using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    /// <summary>One layer of the Connections window's graph: the traffic with one domain, or one address that has none.</summary>
    internal sealed class GraphSeries
    {
        public string Key;          // what the layer stands for; the same key in every update
        public string Name;
        public string About;        // beside the name in the tooltip, such as the owner
        public string Detail;       // the tooltip's last line
        public Color Color;
        public Bitmap Icon;         // site icon, or null
        public float[] Values;      // KB/s in each sample from the data's first
        public long Total;          // bytes graphed (sent, received or both) since Process Streamgraph started
        public double Sum;
        public float Peak;
    }

    /// <summary>The orders the Connections graph can stack its layers in, from the bottom up.</summary>
    internal enum ConnectionSort { Domain, Owner, Rate, Total }

    /// <summary>Which way the Connections graph counts traffic.</summary>
    internal enum TrafficDirection { Both, Sent, Received }

    /// <summary>
    /// Streamgraph of a process's traffic by remote host, drawn as the main window's graphs are: layers
    /// stacked from zero, biggest first, against a rate scale that fits the visible peak, panning
    /// smoothly about one refresh interval behind the newest sample.
    /// </summary>
    internal sealed class ConnectionGraph : Control
    {
        private const float MinDrawnThickness = 0.4f;   // px; thinner stretches are left to the silhouette
        private const float MinSeparatedThickness = 3f; // px; thinner stretches get no separator line
        private const double ScaleEaseSeconds = 0.15;   // how quickly the value axis follows a new peak

        private readonly ProcessMonitor monitor;
        private Theme theme = Theme.Light;
        private ConnectionSort sortMode = ConnectionSort.Rate;
        private bool reverse;
        private string selected;
        private TrafficDirection direction;

        // The data as last handed over: values for count samples from dataFirst.
        private List<GraphSeries> series = new List<GraphSeries>();
        private long dataFirst;

        // Model built by Rebuild(); cum holds (layers + 1) rows of n boundary values each.
        private GraphSeries[] layers = new GraphSeries[0];
        private float[] cum = new float[0];
        private float[] total = new float[0];
        private int n;
        private long firstSample;
        private int visibleSeconds = 30;
        private double scaleMax = 1, tickStep = 1;
        private double shownMax;                // the scale as drawn, eased towards scaleMax; 0 before the first
        private RectangleF plot;
        private float[] xs = new float[0];
        private float pixelsPerUnit;
        private bool smooth;
        private Bitmap cache;                   // heading and axes
        private Bitmap strip;                   // the layers, over xs coordinates from stripLeft
        private int stripLeft;
        private Font boldFont;

        private double refreshSeconds = 1;
        private double anchorTime, viewTime = double.NaN, lastFrame;
        private int pan;

        private bool mouseInside;
        private Point mouse;
        private GraphSeries hover;
        private int hoverSample;

        /// <summary>Raised by a click on a layer, with its key.</summary>
        public event Action<string> SeriesClicked;

        /// <summary>Raised by a right-click on a layer, with its key and the screen point for a menu.</summary>
        public event Action<string, Point> SeriesMenuRequested;

        /// <summary>Raised by a click on the notice shown when traffic needs administrator rights.</summary>
        public event Action ElevationRequested;

        public ConnectionGraph(ProcessMonitor monitor)
        {
            this.monitor = monitor;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = theme.Surface;
        }

        public Theme Theme
        {
            get => theme;
            set { theme = value; BackColor = theme.Surface; Rebuild(); }
        }

        public ConnectionSort SortMode
        {
            get => sortMode;
            set { sortMode = value; Rebuild(); }
        }

        /// <summary>Which way the data handed over counts traffic, for the heading.</summary>
        public TrafficDirection Direction
        {
            get => direction;
            set { direction = value; Rebuild(); }
        }

        public bool Reverse
        {
            get => reverse;
            set { reverse = value; Rebuild(); }
        }

        /// <summary>Forgets the data, as when another process is shown.</summary>
        public void Clear()
        {
            series = new List<GraphSeries>();
            selected = null;
            hover = null;
            Rebuild();
        }

        public int VisibleSeconds
        {
            get => visibleSeconds;
            set { visibleSeconds = value; Rebuild(); }
        }

        /// <summary>The sampling interval, which sets how far the display trails the newest sample.</summary>
        public double RefreshSeconds
        {
            get => refreshSeconds;
            set => refreshSeconds = value;
        }

        /// <summary>Key of the layer outlined, normally that of the row selected in the list.</summary>
        public string Selected
        {
            get => selected;
            set
            {
                if (selected == value) return;
                selected = value;
                Invalidate();
            }
        }

        /// <summary>Hands over new data and redraws.</summary>
        public void SetData(long first, List<GraphSeries> data)
        {
            dataFirst = first;
            series = data;
            Rebuild();
        }

        private double Lag => Math.Min(refreshSeconds + 0.15, MaxLag);
        private double MaxLag => Math.Min(Math.Max(3, 3 * refreshSeconds), visibleSeconds);
        private float PixelsPerSecond => plot.Width / visibleSeconds;
        private float DpiScale => DeviceDpi / 96f;
        private bool Unavailable => !monitor.NetworkAvailable;
        private bool CanElevate => Unavailable && monitor.NetworkAccessDenied;
        private Font BoldFont => boldFont ?? (boldFont = new Font(Font, FontStyle.Bold));

        public void Rebuild()
        {
            if (!IsHandleCreated) return;
            ComputeLayout();
            BuildModel();
            RenderCache();
            UpdateHover();
            Invalidate();
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Rebuild();
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            Rebuild();
        }

        protected override void OnFontChanged(EventArgs e)
        {
            base.OnFontChanged(e);
            boldFont?.Dispose();
            boldFont = null;
            Rebuild();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                cache?.Dispose();
                strip?.Dispose();
                boldFont?.Dispose();
            }
            base.Dispose(disposing);
        }

        // ---------------------------------------------------------------- model

        private void ComputeLayout()
        {
            float s = DpiScale;
            int fontHeight = Font.Height;
            plot = RectangleF.FromLTRB(66 * s, fontHeight + 16 * s, Width - 14 * s, Height - fontHeight - 10 * s);
        }

        private float ValueOf(GraphSeries layer, long sample)
        {
            long i = sample - dataFirst;
            return i >= 0 && i < layer.Values.Length ? layer.Values[i] : 0f;
        }

        private void BuildModel()
        {
            long latest = monitor.SampleIndex;
            int available = monitor.SampleCount;
            double now = available > 0 ? monitor.SampleSeconds(latest) : 0;
            n = 0;
            while (n < available && now - monitor.SampleSeconds(latest - n) <= visibleSeconds + MaxLag) n++;
            if (n < available) n++;
            firstSample = latest - n + 1;
            anchorTime = now;
            if (double.IsNaN(viewTime)) viewTime = now;
            ClampViewTime();
            pan = (int)Math.Round((anchorTime - viewTime) * PixelsPerSecond);

            if (xs.Length < n) xs = new float[n];
            float pixelsPerSecond = PixelsPerSecond;
            for (int i = 0; i < n; i++)
                xs[i] = plot.Right - (float)(now - monitor.SampleSeconds(firstSample + i)) * pixelsPerSecond;
            smooth = n < 2 || (xs[n - 1] - xs[0]) / (n - 1) >= 1.5f;

            var list = new List<GraphSeries>();
            foreach (GraphSeries layer in series)
            {
                double sum = 0;
                float peak = 0;
                for (int i = 0; i < n; i++)
                {
                    float v = ValueOf(layer, firstSample + i);
                    sum += v;
                    if (v > peak) peak = v;
                }
                layer.Sum = sum;
                layer.Peak = peak;
                if (sum > 0) list.Add(layer);
            }
            list.Sort(CompareLayers);
            if (reverse) list.Reverse();
            layers = list.ToArray();

            if (cum.Length < (layers.Length + 1) * n) cum = new float[(layers.Length + 1) * n];
            if (total.Length < n) total = new float[n];
            Array.Clear(total, 0, n);
            Array.Clear(cum, 0, n);
            for (int l = 0; l < layers.Length; l++)
            {
                int below = l * n, row = (l + 1) * n;
                for (int i = 0; i < n; i++)
                {
                    float v = ValueOf(layers[l], firstSample + i);
                    total[i] += v;
                    cum[row + i] = cum[below + i] + v;
                }
            }

            float maxTotal = 0;
            for (int i = 0; i < n; i++) maxTotal = Math.Max(maxTotal, total[i]);
            double top = Math.Max(maxTotal, 8);
            double unit = top >= 1024 ? 1024 : 1;
            tickStep = NiceStep(top / unit / 4) * unit;
            scaleMax = Math.Ceiling(top / tickStep) * tickStep;
            // A new scale is eased into by Animate rather than jumped to, unless there is nothing drawn yet.
            if (shownMax <= 0 || !HasPlot) shownMax = scaleMax;
            pixelsPerUnit = (float)(plot.Height / shownMax);
        }

        // As in the main window's graphs: the biggest at the bottom, names from A at the bottom up.
        private int CompareLayers(GraphSeries a, GraphSeries b)
        {
            int result = 0;
            switch (sortMode)
            {
                case ConnectionSort.Domain: result = string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase); break;
                case ConnectionSort.Owner:
                    // Unknown owners after the known ones, and a site's own layers together within each owner.
                    bool aNone = string.IsNullOrEmpty(a.About), bNone = string.IsNullOrEmpty(b.About);
                    result = aNone != bNone ? aNone.CompareTo(bNone) : string.Compare(a.About, b.About, StringComparison.CurrentCultureIgnoreCase);
                    if (result == 0) result = string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase);
                    break;
                case ConnectionSort.Rate: result = b.Sum.CompareTo(a.Sum); break;
                case ConnectionSort.Total: result = b.Total.CompareTo(a.Total); break;
            }
            return result != 0 ? result : string.CompareOrdinal(a.Key, b.Key);
        }

        private static double NiceStep(double raw)
        {
            double magnitude = Math.Pow(10, Math.Floor(Math.Log10(raw)));
            double fraction = raw / magnitude;
            return (fraction < 1.5 ? 1 : fraction < 3.5 ? 2 : fraction < 7.5 ? 5 : 10) * magnitude;
        }

        // ---------------------------------------------------------------- panning

        /// <summary>Advances the display time; called by the window's animation timer.</summary>
        public void Animate()
        {
            double clock = (double)Stopwatch.GetTimestamp() / Stopwatch.Frequency;
            double elapsed = lastFrame > 0 ? Math.Min(clock - lastFrame, 0.25) : 0;
            lastFrame = clock;
            if (!HasPlot || double.IsNaN(viewTime)) return;
            if (shownMax != scaleMax) EaseScale(elapsed);
            double behind = clock - Lag - viewTime;
            double speed = Math.Max(0, Math.Min(3, 1 + behind));
            viewTime += elapsed * speed;
            ClampViewTime();
            int value = (int)Math.Round((anchorTime - viewTime) * PixelsPerSecond);
            if (value == pan) return;
            pan = value;
            if (mouseInside) UpdateHover();
            if (hover != null) Invalidate();
            else Invalidate(Rectangle.FromLTRB((int)plot.Left, 0, (int)Math.Ceiling(plot.Right) + 1, Height));
        }

        /// <summary>
        /// Moves the drawn scale towards the one the data needs, by a share of the remaining ratio each
        /// frame: quick at first, gentle at the end, and as smooth for a tenfold change as a twofold one.
        /// </summary>
        private void EaseScale(double elapsed)
        {
            double gap = Math.Log(scaleMax / shownMax) * Math.Exp(-elapsed / ScaleEaseSeconds);
            shownMax = Math.Abs(gap) < 0.003 ? scaleMax : scaleMax / Math.Exp(gap);
            pixelsPerUnit = (float)(plot.Height / shownMax);
            RenderCache();
            if (mouseInside) UpdateHover();
            Invalidate();
        }

        private void ClampViewTime()
        {
            if (viewTime > anchorTime) viewTime = anchorTime;
            if (viewTime < anchorTime - MaxLag) viewTime = anchorTime - MaxLag;
        }

        private float X(int index) => xs[index];

        private float Y(float value) => plot.Bottom - value * pixelsPerUnit;

        private bool HasPlot => n >= 2 && plot.Width > 20 && plot.Height > 20 && !Unavailable;

        private void AddBand(GraphicsPath path, int lowRow, int highRow, int first, int last)
        {
            path.StartFigure();
            if (smooth)
            {
                path.AddBeziers(EdgePoints(highRow, first, last, false));
                path.AddBeziers(EdgePoints(lowRow, first, last, true));
            }
            else
            {
                path.AddLines(EdgePoints(highRow, first, last, false));
                path.AddLines(EdgePoints(lowRow, first, last, true));
            }
            path.CloseFigure();
        }

        // As in the main window's graphs: Beziers with flat tangents at each sample, so bands never cross.
        private PointF[] EdgePoints(int row, int first, int last, bool reversed)
        {
            int count = last - first + 1, offset = row * n;
            if (!smooth)
            {
                var vertices = new PointF[count];
                for (int j = 0; j < count; j++)
                {
                    int i = reversed ? last - j : first + j;
                    vertices[j] = new PointF(X(i), Y(cum[offset + i]));
                }
                return vertices;
            }
            int step = reversed ? -1 : 1;
            var points = new PointF[3 * (count - 1) + 1];
            for (int j = 0; j < count; j++)
            {
                int i = reversed ? last - j : first + j;
                float x = X(i), y = Y(cum[offset + i]);
                points[3 * j] = new PointF(x, y);
                if (j < count - 1) points[3 * j + 1] = new PointF((x + X(i + step)) / 2, y);
                if (j > 0) points[3 * j - 1] = new PointF((x + X(i - step)) / 2, y);
            }
            return points;
        }

        private void ForEachRun(int layer, float minThickness, Action<int, int> run)
        {
            int low = layer * n, high = (layer + 1) * n;
            float minValue = minThickness / pixelsPerUnit;
            bool Thick(int i) => cum[high + i] - cum[low + i] >= minValue;
            for (int i = 0; i < n; i++)
            {
                if (!Thick(i)) continue;
                int end = i + 1;
                while (end < n && (Thick(end) || (end + 1 < n && Thick(end + 1)))) end++;
                run(i, end - 1);
                i = end;
            }
        }

        private GraphicsPath BuildLayerPath(int layer)
        {
            var path = new GraphicsPath();
            if (layers[layer].Peak * pixelsPerUnit < MinDrawnThickness) return path;
            ForEachRun(layer, MinDrawnThickness, (first, last) =>
                AddBand(path, layer, layer + 1, Math.Max(first - 1, 0), Math.Min(last + 1, n - 1)));
            return path;
        }

        private bool HitTest(Point point, out int layer, out int sample)
        {
            layer = sample = -1;
            if (!HasPlot || layers.Length == 0 || point.Y < plot.Top || point.Y > plot.Bottom) return false;
            if (point.X < plot.Left || point.X > plot.Right) return false;
            point.X -= pan;
            if (point.X < X(0) || point.X > X(n - 1)) return false;

            int i = 0, above = n - 1;
            while (above - i > 1)
            {
                int mid = (i + above) / 2;
                if (X(mid) <= point.X) i = mid; else above = mid;
            }
            float width = X(i + 1) - X(i);
            float u = width > 0 ? (point.X - X(i)) / width : 0, blend = u;
            if (smooth)
            {
                float t = u;
                for (int iteration = 0; iteration < 5; iteration++)
                    t -= (1.5f * t - 1.5f * t * t + t * t * t - u) / (1.5f - 3f * t + 3f * t * t);
                blend = t * t * (3 - 2 * t);
            }

            float value = (plot.Bottom - point.Y) / pixelsPerUnit;
            float Boundary(int row) => cum[row * n + i] * (1 - blend) + cum[row * n + i + 1] * blend;
            if (value < Boundary(0) || value >= Boundary(layers.Length)) return false;
            int low = 0, high = layers.Length;
            while (high - low > 1)
            {
                int mid = (low + high) / 2;
                if (Boundary(mid) <= value) low = mid; else high = mid;
            }
            layer = low;
            sample = u < 0.5f ? i : i + 1;
            return true;
        }

        private int IndexOf(string key)
        {
            if (key == null) return -1;
            for (int l = 0; l < layers.Length; l++)
                if (layers[l].Key == key) return l;
            return -1;
        }

        // ---------------------------------------------------------------- rendering

        private void RenderCache()
        {
            if (Width <= 0 || Height <= 0) return;
            if (cache == null || cache.Width != Width || cache.Height != Height)
            {
                cache?.Dispose();
                cache = new Bitmap(Width, Height, PixelFormat.Format32bppPArgb);
            }
            bool layersShown = false;
            using (Graphics g = Graphics.FromImage(cache))
            {
                g.Clear(theme.Surface);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
                DrawHeading(g);
                if (plot.Width > 20 && plot.Height > 20)
                {
                    if (Unavailable)
                    {
                        DrawNotice(g, CanElevate
                            ? "Data rates by host need administrator rights.\nClick here to restart as administrator."
                            : "Data rates by host are not available on this system.");
                    }
                    else
                    {
                        DrawAxes(g);
                        if (n < 2) DrawNotice(g, "Collecting samples…");
                        else layersShown = true;
                    }
                }
            }
            if (layersShown) RenderStrip();
        }

        private void RenderStrip()
        {
            stripLeft = (int)Math.Floor(plot.Left - MaxLag * PixelsPerSecond) - 2;
            int width = (int)Math.Ceiling(plot.Right) - stripLeft + 2;
            if (strip == null || strip.Width != width || strip.Height != Height)
            {
                strip?.Dispose();
                strip = new Bitmap(width, Height, PixelFormat.Format32bppPArgb);
            }
            using (Graphics g = Graphics.FromImage(strip))
            {
                g.Clear(Color.Transparent);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TranslateTransform(-stripLeft, 0);
                DrawLayers(g);
            }
        }

        private RectangleF PlotClip => RectangleF.FromLTRB(plot.Left, 0, plot.Right, Height);

        private void DrawNotice(Graphics g, string text)
        {
            using (var brush = new SolidBrush(theme.MutedInk))
            using (var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                g.DrawString(text, Font, brush, plot, format);
        }

        private void DrawHeading(Graphics g)
        {
            float s = DpiScale;
            string summary = "";
            if (!Unavailable && n > 0)
            {
                int active = 0;
                foreach (GraphSeries layer in layers)
                    if (ValueOf(layer, firstSample + n - 1) > 0) active++;
                summary = $"{Format.Rate(total[n - 1])} {(direction == TrafficDirection.Sent ? "sent" : direction == TrafficDirection.Received ? "received" : "sent and received")}  ·  {active} of {layers.Length} host{(layers.Length == 1 ? "" : "s")} active";
            }
            using (var primary = new SolidBrush(theme.PrimaryInk))
            using (var secondary = new SolidBrush(theme.SecondaryInk))
            {
                float x = 12 * s, y = 8 * s;
                const string title = "Data Rates";
                g.DrawString(title, BoldFont, primary, x, y);
                x += g.MeasureString(title, BoldFont).Width + 4 * s;
                g.DrawString(summary, Font, secondary, x, y);
            }
        }

        private void DrawAxes(Graphics g)
        {
            float s = DpiScale;
            using (var grid = new Pen(theme.Grid, 1))
            using (var axis = new Pen(theme.Axis, 1))
            using (var muted = new SolidBrush(theme.MutedInk))
            using (var centered = new StringFormat { Alignment = StringAlignment.Center })
            using (var far = new StringFormat { Alignment = StringAlignment.Far })
            using (var farMiddle = new StringFormat { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center })
            {
                g.SmoothingMode = SmoothingMode.None;
                bool inSeconds = visibleSeconds < 180;
                int step = 60;
                if (inSeconds)
                {
                    foreach (int candidate in new[] { 1, 2, 5, 10, 15, 20, 30, 60 })
                    {
                        step = candidate;
                        if (visibleSeconds / candidate <= 8) break;
                    }
                }
                float pixelsPerSecond = plot.Width / visibleSeconds;
                for (int t = 0; t <= visibleSeconds; t += step)
                {
                    float x = (float)Math.Round(plot.Right - t * pixelsPerSecond);
                    g.DrawLine(grid, x, plot.Top, x, plot.Bottom);
                    if (t == 0)
                        g.DrawString("now", Font, muted, plot.Right + 2 * s, plot.Bottom + 4 * s, far);
                    else
                        g.DrawString(inSeconds ? $"−{t} s" : $"−{t / 60} min", Font, muted, x, plot.Bottom + 4 * s, centered);
                }
                int ticks = (int)Math.Floor(shownMax / tickStep + 0.001);     // those below the top while the scale eases
                for (int tick = 0; tick <= ticks; tick++)
                {
                    float y = (float)Math.Round(Y((float)(tick * tickStep)));
                    g.DrawLine(tick == 0 ? axis : grid, plot.Left, y, plot.Right, y);
                    g.DrawString(tick == 0 ? "0" : Format.RateTick(tick * tickStep), Font, muted, plot.Left - 6 * s, y, farMiddle);
                }
                g.SmoothingMode = SmoothingMode.AntiAlias;
            }
        }

        private void DrawLayers(Graphics g)
        {
            using (var silhouette = new GraphicsPath())
            using (var brush = new SolidBrush(theme.Silhouette))
            {
                AddBand(silhouette, 0, layers.Length, 0, n - 1);
                g.FillPath(brush, silhouette);
            }
            for (int l = 0; l < layers.Length; l++)
            {
                using (GraphicsPath path = BuildLayerPath(l))
                {
                    if (path.PointCount == 0) continue;
                    using (var brush = new SolidBrush(layers[l].Color))
                        g.FillPath(brush, path);
                }
            }
            using (var separators = new GraphicsPath())
            using (var pen = new Pen(Color.FromArgb(200, theme.Surface), 1f))
            {
                for (int l = 0; l < layers.Length - 1; l++)
                {
                    if (layers[l].Peak * pixelsPerUnit < MinSeparatedThickness) continue;
                    int row = l + 1;
                    ForEachRun(l, MinSeparatedThickness, (first, last) =>
                    {
                        if (last == first) return;
                        separators.StartFigure();
                        if (smooth) separators.AddBeziers(EdgePoints(row, first, last, false));
                        else separators.AddLines(EdgePoints(row, first, last, false));
                    });
                }
                if (separators.PointCount > 0) g.DrawPath(pen, separators);
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            // GDI+ fails now and then while the display is asleep or locked; the next frame paints normally.
            try { PaintFrame(e); }
            catch (System.Runtime.InteropServices.ExternalException) { }
        }

        private void PaintFrame(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            if (cache == null)
            {
                g.Clear(theme.Surface);
                return;
            }
            Rectangle clip = Rectangle.Intersect(e.ClipRectangle, new Rectangle(0, 0, cache.Width, cache.Height));
            g.DrawImage(cache, clip, clip, GraphicsUnit.Pixel);
            if (!HasPlot || strip == null) return;

            GraphicsState plain = g.Save();
            g.SetClip(PlotClip);
            g.DrawImageUnscaled(strip, stripLeft + pan, 0);
            g.TranslateTransform(pan, 0);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            int selectedLayer = IndexOf(selected);
            if (selectedLayer >= 0) OutlineLayer(g, selectedLayer, false);
            int hoverLayer = Array.IndexOf(layers, hover);
            if (hoverLayer >= 0) OutlineLayer(g, hoverLayer, true);
            g.Restore(plain);

            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            if (hoverLayer < 0) return;
            float x = (float)Math.Round(Math.Min(Math.Max(X(hoverSample) + pan, plot.Left), plot.Right));
            using (var crosshair = new Pen(Color.FromArgb(110, theme.PrimaryInk), 1))
            {
                g.SmoothingMode = SmoothingMode.None;
                g.DrawLine(crosshair, x, plot.Top, x, plot.Bottom);
                g.SmoothingMode = SmoothingMode.AntiAlias;
            }
            DrawTooltip(g, layers[hoverLayer]);
        }

        private void OutlineLayer(Graphics g, int layer, bool hovered)
        {
            float s = DpiScale;
            using (GraphicsPath path = BuildLayerPath(layer))
            {
                if (path.PointCount == 0) return;
                if (hovered)
                {
                    using (var wash = new SolidBrush(Color.FromArgb(80, Color.White)))
                    using (var ink = new Pen(theme.PrimaryInk, s) { LineJoin = LineJoin.Round })
                    {
                        g.FillPath(wash, path);
                        g.DrawPath(ink, path);
                    }
                }
                else
                {
                    using (var halo = new Pen(Color.FromArgb(210, theme.Surface), 3.5f * s) { LineJoin = LineJoin.Round })
                    using (var ink = new Pen(theme.PrimaryInk, 1.5f * s) { LineJoin = LineJoin.Round })
                    {
                        g.DrawPath(halo, path);
                        g.DrawPath(ink, path);
                    }
                }
            }
        }

        private void DrawTooltip(Graphics g, GraphSeries layer)
        {
            float s = DpiScale;
            long sample = firstSample + hoverSample;
            string value = Format.Rate(ValueOf(layer, sample));
            string when = "  at " + monitor.SampleTime(sample).ToString("T");
            string about = string.IsNullOrEmpty(layer.About) ? "" : "  " + (layer.About.Length <= 60 ? layer.About : layer.About.Substring(0, 59) + "…");
            string detail = layer.Detail ?? "";

            Image icon = layer.Icon;
            float iconSize = icon != null ? 32 * s : 0, pad = 10 * s, gap = icon != null ? 10 * s : 0, key = 4 * s;
            float lineHeight = Font.GetHeight(g) + 2 * s;
            int lines = detail.Length > 0 ? 3 : 2;
            SizeF nameSize = g.MeasureString(layer.Name, BoldFont);
            SizeF aboutSize = g.MeasureString(about, Font);
            nameSize.Width += about.Length == 0 ? 0 : aboutSize.Width - 4 * s;
            SizeF valueSize = g.MeasureString(value, BoldFont);
            SizeF whenSize = g.MeasureString(when, Font);
            SizeF detailSize = g.MeasureString(detail, Font);
            float textWidth = Math.Max(nameSize.Width, Math.Max(valueSize.Width + whenSize.Width, detailSize.Width));
            float width = key + pad + iconSize + gap + textWidth + pad;
            float height = pad + Math.Max(iconSize, lineHeight * lines) + pad;

            float offset = 16 * s;
            float left = mouse.X + offset, top = mouse.Y + offset;
            if (left + width > Width - 4) left = mouse.X - offset - width;
            if (top + height > Height - 4) top = mouse.Y - offset / 2 - height;
            left = Math.Max(4, Math.Min(left, Width - 4 - width));
            top = Math.Max(4, Math.Min(top, Height - 4 - height));
            var bounds = new RectangleF(left, top, width, height);

            using (GraphicsPath shadow = RoundedRect(new RectangleF(left + 1, top + 2 * s, width, height), 6 * s))
            using (GraphicsPath box = RoundedRect(bounds, 6 * s))
            using (var shadowBrush = new SolidBrush(Color.FromArgb(theme.IsDark ? 90 : 36, 0, 0, 0)))
            using (var back = new SolidBrush(theme.TooltipBack))
            using (var border = new Pen(Color.FromArgb(60, theme.PrimaryInk), 1))
            using (var keyBrush = new SolidBrush(layer.Color))
            using (var primary = new SolidBrush(theme.PrimaryInk))
            using (var secondary = new SolidBrush(theme.SecondaryInk))
            {
                g.FillPath(shadowBrush, shadow);
                g.FillPath(back, box);
                GraphicsState state = g.Save();
                g.SetClip(box, CombineMode.Intersect);
                g.FillRectangle(keyBrush, left, top, key, height);
                g.Restore(state);
                g.DrawPath(border, box);

                if (icon != null)
                {
                    InterpolationMode interpolation = g.InterpolationMode;
                    g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                    g.DrawImage(icon, left + key + pad, top + (height - iconSize) / 2, iconSize, iconSize);
                    g.InterpolationMode = interpolation;
                }

                float textLeft = left + key + pad + iconSize + gap;
                float textTop = top + (height - lineHeight * lines) / 2;
                g.DrawString(layer.Name, BoldFont, primary, textLeft, textTop);
                if (about.Length > 0)
                    g.DrawString(about, Font, secondary, textLeft + nameSize.Width - aboutSize.Width, textTop);
                g.DrawString(value, BoldFont, primary, textLeft, textTop + lineHeight);
                g.DrawString(when, Font, secondary, textLeft + valueSize.Width - 4 * s, textTop + lineHeight);
                if (detail.Length > 0) g.DrawString(detail, Font, secondary, textLeft, textTop + lineHeight * 2);
            }
        }

        private static GraphicsPath RoundedRect(RectangleF r, float radius)
        {
            float d = radius * 2;
            var path = new GraphicsPath();
            path.AddArc(r.Left, r.Top, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        // ---------------------------------------------------------------- interaction

        private void UpdateHover()
        {
            if (mouseInside && HitTest(mouse, out int layer, out int sample))
            {
                hover = layers[layer];
                hoverSample = sample;
            }
            else
            {
                hover = null;
            }
            Cursor = hover != null || CanElevate ? Cursors.Hand : Cursors.Default;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            bool wasHovering = hover != null;
            mouseInside = true;
            mouse = e.Location;
            UpdateHover();
            if (wasHovering || hover != null) Invalidate();
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            mouseInside = false;
            if (hover != null)
            {
                hover = null;
                Invalidate();
            }
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button != MouseButtons.Left && e.Button != MouseButtons.Right) return;
            if (e.Button == MouseButtons.Left && CanElevate)
            {
                ElevationRequested?.Invoke();
                return;
            }
            mouseInside = true;
            mouse = e.Location;
            UpdateHover();
            if (hover == null) return;
            if (e.Button == MouseButtons.Left) SeriesClicked?.Invoke(hover.Key);
            else SeriesMenuRequested?.Invoke(hover.Key, PointToScreen(e.Location));
        }
    }
}
