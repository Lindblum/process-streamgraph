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
    internal enum SortMode { Usage, StartTime, Name, Pid }

    /// <summary>
    /// Streamgraph of one metric over the monitor's history window, one layer per process.
    /// Layers are stacked up from zero in the current sort order. CPU and memory are drawn against a
    /// percentage scale, network traffic against a rate scale that fits the visible peak.
    ///
    /// The graph pans smoothly rather than stepping once per sample: it shows the data as of a display
    /// time that runs with the clock about one refresh interval behind the newest sample, so each new
    /// sample slides in from the right. The layers are drawn once per sample into a strip wider than
    /// the plot, and each animation frame only shifts that strip.
    /// </summary>
    internal sealed class StreamGraphControl : Control
    {
        private const float MinDrawnThickness = 0.4f;   // px; thinner stretches are left to the silhouette
        private const float MinSeparatedThickness = 3f; // px; thinner stretches get no separator line

        private struct Layer
        {
            public ProcInfo Process;
            public double Sum;
            public float Peak;
        }

        private readonly ProcessMonitor monitor;
        private readonly IconCache icons;
        private readonly Metric metric;
        private readonly string title;

        private SortMode sortMode = SortMode.Usage;
        private bool reverse;
        private Theme theme = Theme.Light;
        private bool collapsed;
        private ProcInfo selected;

        // Model built by Rebuild(). cum holds (layers + 1) rows of n boundary values each:
        // row l is the bottom edge of layer l, row l + 1 its top edge.
        private Layer[] layers = new Layer[0];
        private float[] cum = new float[0];
        private readonly float[] total = new float[ProcessMonitor.HistoryLength];
        private int n;
        private long firstSample;
        private readonly double fullScale;      // the value that reads as 100%; unused for network
        private int visibleSeconds = ProcessMonitor.HistorySeconds;
        private double scaleMax = 1, tickStep = 1;
        private RectangleF plot;
        private float[] xs = new float[0];      // x of each sample were the newest at the plot's right edge
        private float pixelsPerUnit;
        private bool smooth;
        private Bitmap cache;                   // heading and axes
        private Bitmap strip;                   // the layers, over xs coordinates from stripLeft
        private int stripLeft;
        private Font boldFont;

        // Panning. anchorTime is when the newest sample was taken; viewTime is the moment shown at the
        // right edge, which trails it. Both are seconds on the monitor's steady clock.
        private double refreshSeconds = 1;
        private double anchorTime, viewTime = double.NaN, lastFrame;
        private int pan;                        // px the layers are shifted right: (anchorTime - viewTime) in pixels

        private bool mouseInside;
        private Point mouse;
        private ProcInfo hoverProcess;
        private Image hoverIcon;
        private int hoverSample;

        public event Action<ProcInfo> ProcessClicked;

        /// <summary>Raised by a right-click on a layer, with the screen position for a menu.</summary>
        public event Action<ProcInfo, Point> ProcessMenuRequested;

        /// <summary>Raised when the toggle in the heading collapses or expands the graph.</summary>
        public event Action CollapsedChanged;

        /// <summary>Raised by a click on the notice shown when network data needs administrator rights.</summary>
        public event Action ElevationRequested;

        public StreamGraphControl(ProcessMonitor monitor, IconCache icons, Metric metric)
        {
            this.monitor = monitor;
            this.icons = icons;
            this.metric = metric;
            title = metric.ToString();
            if (metric == Metric.Cpu) title = "CPU";
            fullScale = metric == Metric.Cpu ? 100 : monitor.TotalPhysicalMemory / 1048576.0;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = theme.Surface;
        }

        public SortMode SortMode
        {
            get => sortMode;
            set { sortMode = value; Rebuild(); }
        }

        public bool Reverse
        {
            get => reverse;
            set { reverse = value; Rebuild(); }
        }

        public Theme Theme
        {
            get => theme;
            set { theme = value; BackColor = theme.Surface; Rebuild(); }
        }

        /// <summary>A collapsed graph shows only its heading line, which still reports the current total.</summary>
        public bool Collapsed
        {
            get => collapsed;
            set
            {
                if (collapsed == value) return;
                collapsed = value;
                Rebuild();
                CollapsedChanged?.Invoke();
            }
        }

        /// <summary>Height of the heading line, which is all a collapsed graph needs.</summary>
        public int HeadingHeight => (int)(Font.Height + 16 * DpiScale);

        /// <summary>Length of the time axis, which always ends at the latest sample.</summary>
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

        // How far behind the newest sample the display aims to run: one interval plus slack for timer
        // jitter, so the next sample normally arrives before the display catches up with this one.
        private double Lag => Math.Min(refreshSeconds + 0.15, MaxLag);

        // How far behind it may fall before giving up and jumping ahead, e.g. after the computer sleeps.
        // Bounded by the visible span so the strip stays at most twice the plot's width.
        private double MaxLag => Math.Min(Math.Max(3, 3 * refreshSeconds), visibleSeconds);

        private float PixelsPerSecond => plot.Width / visibleSeconds;

        /// <summary>Process whose layer is outlined, normally the one selected in the tree.</summary>
        public ProcInfo Selected
        {
            get => selected;
            set { selected = value; Invalidate(); }
        }

        private float DpiScale => DeviceDpi / 96f;

        // Network traffic can only be attributed to processes with administrator rights.
        private bool Unavailable => metric == Metric.Network && !monitor.NetworkAvailable;

        private bool CanElevate => Unavailable && monitor.NetworkAccessDenied;

        private Font BoldFont => boldFont ?? (boldFont = new Font(Font, FontStyle.Bold));

        /// <summary>Recomputes the layer stack from the monitor's current history and redraws.</summary>
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

        private void BuildModel()
        {
            // Every sample inside the time span, widened by how far the display may trail the newest
            // sample, plus one older one so the bands run on to the left edge, where they are clipped.
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
            // The layer coordinates below move with the new anchor; the pan must move with them in the
            // same paint, or the layers would flick left for a frame each time a sample arrives.
            pan = (int)Math.Round((anchorTime - viewTime) * PixelsPerSecond);

            if (xs.Length < n) xs = new float[n];
            float pixelsPerSecond = PixelsPerSecond;
            for (int i = 0; i < n; i++)
                xs[i] = plot.Right - (float)(now - monitor.SampleSeconds(firstSample + i)) * pixelsPerSecond;
            // Curves are not worth their cost once samples are packed closer than the eye can follow.
            smooth = n < 2 || (xs[n - 1] - xs[0]) / (n - 1) >= 1.5f;

            var list = new List<Layer>();
            foreach (ProcInfo p in monitor.Processes)
            {
                if (p.LastSample < firstSample) continue;
                double sum = 0;
                for (int i = 0; i < n; i++) sum += p.Value(metric, firstSample + i);
                if (sum > 0) list.Add(new Layer { Process = p, Sum = sum });
            }
            list.Sort(CompareLayers);
            if (reverse) list.Reverse();
            layers = list.ToArray();

            if (cum.Length < (layers.Length + 1) * n) cum = new float[(layers.Length + 1) * n];
            Array.Clear(total, 0, total.Length);
            for (int l = 0; l < layers.Length; l++)
            {
                ProcInfo p = layers[l].Process;
                int row = (l + 1) * n;
                float peak = 0;
                for (int i = 0; i < n; i++)
                {
                    float v = p.Value(metric, firstSample + i);
                    cum[row + i] = v;
                    total[i] += v;
                    if (v > peak) peak = v;
                }
                layers[l].Peak = peak;
            }

            float maxTotal = 0;
            for (int i = 0; i < n; i++) maxTotal = Math.Max(maxTotal, total[i]);
            if (metric == Metric.Network)
            {
                // No natural ceiling, so the axis fits the visible peak, in round KB/s or MB/s steps.
                double top = Math.Max(maxTotal, 8);
                double unit = top >= 1024 ? 1024 : 1;
                tickStep = NiceStep(top / unit / 4) * unit;
                scaleMax = Math.Ceiling(top / tickStep) * tickStep;
            }
            else
            {
                // The axis runs from zero to the first 10% step at or above the visible peak, so the
                // gridlines always sit on whole multiples of 10%.
                tickStep = fullScale / 10;
                scaleMax = Math.Max(1, Math.Ceiling(maxTotal / tickStep)) * tickStep;
            }
            pixelsPerUnit = (float)(plot.Height / scaleMax);

            Array.Clear(cum, 0, n);
            for (int l = 0; l < layers.Length; l++)
            {
                int below = l * n, row = (l + 1) * n;
                for (int i = 0; i < n; i++) cum[row + i] += cum[below + i];
            }
        }

        private int CompareLayers(Layer a, Layer b)
        {
            int result = 0;
            switch (sortMode)
            {
                case SortMode.Usage: result = b.Sum.CompareTo(a.Sum); break;
                case SortMode.StartTime: result = a.Process.CreateTime.CompareTo(b.Process.CreateTime); break;
                case SortMode.Name: result = string.Compare(a.Process.Name, b.Process.Name, StringComparison.OrdinalIgnoreCase); break;
            }
            if (result == 0) result = a.Process.Pid.CompareTo(b.Process.Pid);
            if (result == 0) result = a.Process.CreateTime.CompareTo(b.Process.CreateTime);
            return result;
        }

        // ---------------------------------------------------------------- panning

        /// <summary>
        /// Advances the display time by the time elapsed since the last frame, and repaints when that
        /// moves the layers by a pixel or more. Called by the window's animation timer.
        /// </summary>
        public void Animate()
        {
            double clock = (double)Stopwatch.GetTimestamp() / Stopwatch.Frequency;
            // A stalled UI thread should not send the graph racing to catch up in one frame.
            double elapsed = lastFrame > 0 ? Math.Min(clock - lastFrame, 0.25) : 0;
            lastFrame = clock;
            if (!HasPlot || double.IsNaN(viewTime)) return;

            // Run with the clock, eased towards the target lag: faster when behind it, slower when
            // ahead, and never backwards, so the motion stays steady when the interval changes.
            double behind = clock - Lag - viewTime;
            double speed = Math.Max(0, Math.Min(3, 1 + behind));
            viewTime += elapsed * speed;
            ClampViewTime();
            UpdatePan();
        }

        // The display never runs ahead of the data, which would leave a gap at the right edge, and
        // jumps forward when it has fallen hopelessly behind.
        private void ClampViewTime()
        {
            if (viewTime > anchorTime) viewTime = anchorTime;
            if (viewTime < anchorTime - MaxLag) viewTime = anchorTime - MaxLag;
        }

        private void UpdatePan()
        {
            int value = (int)Math.Round((anchorTime - viewTime) * PixelsPerSecond);
            if (value == pan) return;
            pan = value;
            // The layers move under a still pointer, so what it is over can change, and its tooltip
            // can reach beyond the plot. Otherwise only the plot needs repainting.
            if (mouseInside) UpdateHover();
            if (hoverProcess != null) Invalidate();
            else Invalidate(Rectangle.FromLTRB((int)plot.Left, 0, (int)Math.Ceiling(plot.Right) + 1, Height));
        }

        private static double NiceStep(double raw)
        {
            double magnitude = Math.Pow(10, Math.Floor(Math.Log10(raw)));
            double fraction = raw / magnitude;
            return (fraction < 1.5 ? 1 : fraction < 3.5 ? 2 : fraction < 7.5 ? 5 : 10) * magnitude;
        }

        // In layer coordinates; the layers are drawn shifted right by pan.
        private float X(int index) => xs[index];

        private float Y(float value) => plot.Bottom - value * pixelsPerUnit;

        private bool HasPlot => n >= 2 && plot.Width > 20 && plot.Height > 20 && !Unavailable && !collapsed;

        /// <summary>Adds the closed area between two boundary rows over the samples first..last.</summary>
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

        /// <summary>
        /// Points of one boundary row: Bezier control points when smoothing, plain vertices otherwise.
        /// Each span is a Bezier with horizontal tangents at both samples and its control points midway
        /// between them; every boundary uses the same easing, so bands can neither overshoot nor cross.
        /// </summary>
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

        /// <summary>
        /// Calls back with each stretch of samples where the layer is at least minThickness pixels thick.
        /// Stretches separated by a single thinner sample are joined.
        /// </summary>
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

        /// <summary>Area of a layer, skipping the stretches where it is too thin to see.</summary>
        private GraphicsPath BuildLayerPath(int layer)
        {
            var path = new GraphicsPath();
            if (layers[layer].Peak * pixelsPerUnit < MinDrawnThickness) return path;
            // One extra sample each side so the band tapers in and out instead of starting abruptly.
            ForEachRun(layer, MinDrawnThickness, (first, last) =>
                AddBand(path, layer, layer + 1, Math.Max(first - 1, 0), Math.Min(last + 1, n - 1)));
            return path;
        }

        /// <summary>Finds the layer under a point, using the same interpolation the bands are drawn with.</summary>
        private bool HitTest(Point point, out int layer, out int sample)
        {
            layer = sample = -1;
            if (!HasPlot || layers.Length == 0 || point.Y < plot.Top || point.Y > plot.Bottom) return false;
            if (point.X < plot.Left || point.X > plot.Right) return false;
            point.X -= pan;
            if (point.X < X(0) || point.X > X(n - 1)) return false;

            // The pair of samples the point lies between, and how far along from the first it is.
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
                // Invert the curve's x(t) = 1.5t - 1.5t^2 + t^3, then take its y easing 3t^2 - 2t^3.
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

        private int IndexOf(ProcInfo process)
        {
            if (process == null) return -1;
            for (int l = 0; l < layers.Length; l++)
                if (layers[l].Process == process) return l;
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
                if (!collapsed && plot.Width > 20 && plot.Height > 20)
                {
                    if (Unavailable)
                    {
                        DrawNotice(g, CanElevate
                            ? "Per-process network usage needs administrator rights.\nClick here to restart as administrator."
                            : "Per-process network usage is not available on this system.");
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

        /// <summary>
        /// Draws the layers onto a transparent strip that reaches as far left of the plot as the display
        /// can trail the data, so shifting it right while panning never uncovers an empty edge.
        /// </summary>
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

        // The plot, with slack above and below so that outlines on its edge are not cut. Left and right
        // it is exact, since the layers run on past both edges while panning.
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
            float latest = n > 0 ? total[n - 1] : 0;
            string summary;
            if (Unavailable)
                summary = "";
            else if (metric == Metric.Cpu)
                summary = $"{Format.CpuPercent(latest)} of {monitor.ProcessorCount} logical processors";
            else if (metric == Metric.Memory)
                summary = $"{Format.Memory(latest)} private working set in {monitor.LiveCount} processes, " +
                          $"{latest / fullScale * 100:0}% of {Format.Memory(fullScale)} RAM";
            else
                summary = $"{Format.Rate(latest)} sent and received";
            using (var primary = new SolidBrush(theme.PrimaryInk))
            using (var secondary = new SolidBrush(theme.SecondaryInk))
            using (var chevron = new Pen(theme.SecondaryInk, 1.4f * s) { LineJoin = LineJoin.Round, StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                float x = 12 * s, y = 8 * s;

                // Collapse toggle: pointing down while the graph is open, right while it is collapsed.
                float r = 3.5f * s, cx = x + r, cy = y + Font.GetHeight(g) / 2;
                g.DrawLines(chevron, collapsed
                    ? new[] { new PointF(cx - r / 2, cy - r), new PointF(cx + r / 2, cy), new PointF(cx - r / 2, cy + r) }
                    : new[] { new PointF(cx - r, cy - r / 2), new PointF(cx, cy + r / 2), new PointF(cx + r, cy - r / 2) });
                x += 2 * r + 5 * s;

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

                // Time axis, labelled relative to now: minutes for spans of three minutes and up,
                // seconds below that.
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

                // Value axis, with the zero line at the bottom: a gridline every 10% of the full scale,
                // or at each rate step for network traffic.
                int ticks = (int)Math.Round(scaleMax / tickStep);
                for (int tick = 0; tick <= ticks; tick++)
                {
                    float y = (float)Math.Round(Y((float)(tick * tickStep)));
                    g.DrawLine(tick == 0 ? axis : grid, plot.Left, y, plot.Right, y);
                    string label = metric != Metric.Network ? tick * 10 + "%" : tick == 0 ? "0" : Format.RateTick(tick * tickStep);
                    g.DrawString(label, Font, muted, plot.Left - 6 * s, y, farMiddle);
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
                    using (var brush = new SolidBrush(layers[l].Process.Color))
                        g.FillPath(brush, path);
                }
            }

            // Surface-coloured hairlines along the top of each layer keep neighbours apart, which matters
            // most when several instances of one program (and so one hue) are stacked together. Thin
            // stretches go without, since the line would swallow them.
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
            Graphics g = e.Graphics;
            if (cache == null)
            {
                g.Clear(theme.Surface);
                return;
            }
            // Only the invalid part of the cached heading and axes; while panning that is just the plot.
            Rectangle clip = Rectangle.Intersect(e.ClipRectangle, new Rectangle(0, 0, cache.Width, cache.Height));
            g.DrawImage(cache, clip, clip, GraphicsUnit.Pixel);
            if (!HasPlot || strip == null) return;

            // Whole-pixel shifts keep the strip crisp; the layer coordinates follow with the same offset.
            GraphicsState plain = g.Save();
            g.SetClip(PlotClip);
            g.DrawImageUnscaled(strip, stripLeft + pan, 0);
            g.TranslateTransform(pan, 0);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            int selectedLayer = IndexOf(selected);
            if (selectedLayer >= 0)
                OutlineLayer(g, selectedLayer, false);
            int hoverLayer = IndexOf(hoverProcess);
            if (hoverLayer >= 0)
                OutlineLayer(g, hoverLayer, true);
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
            DrawTooltip(g, layers[hoverLayer].Process);
        }

        private void OutlineLayer(Graphics g, int layer, bool hover)
        {
            float s = DpiScale;
            using (GraphicsPath path = BuildLayerPath(layer))
            {
                if (path.PointCount == 0) return;
                GraphicsState state = g.Save();
                if (hover)
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
                    // Surface-coloured halo under the line so the outline reads against any neighbouring colour.
                    using (var halo = new Pen(Color.FromArgb(210, theme.Surface), 3.5f * s) { LineJoin = LineJoin.Round })
                    using (var ink = new Pen(theme.PrimaryInk, 1.5f * s) { LineJoin = LineJoin.Round })
                    {
                        g.DrawPath(halo, path);
                        g.DrawPath(ink, path);
                    }
                }
                g.Restore(state);
            }
        }

        private void DrawTooltip(Graphics g, ProcInfo process)
        {
            float s = DpiScale;
            long sample = firstSample + hoverSample;
            string value = Format.Value(metric, process.Value(metric, sample));
            string when = "  at " + monitor.SampleTime(sample).ToString("T");
            string detail = (process.DisplayName != process.Name ? process.Name + "  ·  " : "") + "PID " + process.Pid;
            DateTime? started = process.StartTime;
            if (started.HasValue) detail += "  ·  started " + started.Value.ToString(started.Value.Date == DateTime.Today ? "T" : "g");
            if (!process.Alive) detail += "  ·  exited";

            Image icon = hoverIcon;
            float iconSize = 32 * s, pad = 10 * s, gap = 10 * s, key = 4 * s;
            float lineHeight = Font.GetHeight(g) + 2 * s;
            // What the process is for, beside its name, to tell it from siblings running the same program.
            string about = process.Details.Length == 0 ? "" : "  " + (process.Details.Length <= 60 ? process.Details : process.Details.Substring(0, 59) + "…");
            SizeF nameSize = g.MeasureString(process.DisplayName, BoldFont);
            SizeF aboutSize = g.MeasureString(about, Font);
            nameSize.Width += about.Length == 0 ? 0 : aboutSize.Width - 4 * s;
            SizeF valueSize = g.MeasureString(value, BoldFont);
            SizeF whenSize = g.MeasureString(when, Font);
            SizeF detailSize = g.MeasureString(detail, Font);
            float textWidth = Math.Max(nameSize.Width, Math.Max(valueSize.Width + whenSize.Width, detailSize.Width));
            float width = key + pad + iconSize + gap + textWidth + pad;
            float height = pad + Math.Max(iconSize, lineHeight * 3) + pad;

            // Beside the pointer, flipped to whichever side keeps it inside the control.
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
            using (var keyBrush = new SolidBrush(process.Color))
            using (var primary = new SolidBrush(theme.PrimaryInk))
            using (var secondary = new SolidBrush(theme.SecondaryInk))
            {
                g.FillPath(shadowBrush, shadow);
                g.FillPath(back, box);
                // Colour key tying the readout to its layer.
                GraphicsState state = g.Save();
                g.SetClip(box, CombineMode.Intersect);
                g.FillRectangle(keyBrush, left, top, key, height);
                g.Restore(state);
                g.DrawPath(border, box);

                float iconTop = top + (height - iconSize) / 2;
                InterpolationMode interpolation = g.InterpolationMode;
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                g.DrawImage(icon, left + key + pad, iconTop, iconSize, iconSize);
                g.InterpolationMode = interpolation;

                float textLeft = left + key + pad + iconSize + gap;
                float textTop = top + (height - lineHeight * 3) / 2;
                g.DrawString(process.DisplayName, BoldFont, primary, textLeft, textTop);
                if (about.Length > 0)
                    g.DrawString(about, Font, secondary, textLeft + nameSize.Width - aboutSize.Width, textTop);
                g.DrawString(value, BoldFont, primary, textLeft, textTop + lineHeight);
                g.DrawString(when, Font, secondary, textLeft + valueSize.Width - 4 * s, textTop + lineHeight);
                g.DrawString(detail, Font, secondary, textLeft, textTop + lineHeight * 2);
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
                // Shell icon lookups can pump messages, so they are done here rather than while painting.
                if (layers[layer].Process != hoverProcess) hoverIcon = icons.GetLarge(layers[layer].Process.Path);
                hoverProcess = layers[layer].Process;
                hoverSample = sample;
            }
            else
            {
                hoverProcess = null;
            }
            bool overToggle = mouseInside && mouse.Y < HeadingHeight;
            Cursor = hoverProcess != null || overToggle || (CanElevate && !collapsed) ? Cursors.Hand : Cursors.Default;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            bool wasHovering = hoverProcess != null;
            mouseInside = true;
            mouse = e.Location;
            UpdateHover();
            // The tooltip follows the pointer, so any move over a layer needs a repaint.
            if (wasHovering || hoverProcess != null) Invalidate();
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            mouseInside = false;
            if (hoverProcess != null)
            {
                hoverProcess = null;
                Invalidate();
            }
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button != MouseButtons.Left && e.Button != MouseButtons.Right) return;
            if (e.Button == MouseButtons.Left && e.Y < HeadingHeight)
            {
                Collapsed = !collapsed;     // anywhere on the heading line works as the toggle
                return;
            }
            if (e.Button == MouseButtons.Left && CanElevate)
            {
                ElevationRequested?.Invoke();
                return;
            }
            mouseInside = true;
            mouse = e.Location;
            UpdateHover();
            if (hoverProcess == null) return;
            if (e.Button == MouseButtons.Left) ProcessClicked?.Invoke(hoverProcess);
            else ProcessMenuRequested?.Invoke(hoverProcess, PointToScreen(e.Location));
        }
    }
}
