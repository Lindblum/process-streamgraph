using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    internal static class SafetyDrawing
    {
        /// <summary>A rounded badge in the rating's colour; unrated ones are drawn as an outline.</summary>
        public static void DrawBadge(Graphics g, Rectangle badge, Safety safety, string text, Font font, bool dark, float scale)
        {
            Color color = SafetyStyle.ColorOf(safety, dark);
            SmoothingMode smoothing = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (GraphicsPath path = RoundedRect(badge, badge.Height / 2f))
            {
                if (safety == Safety.Unrated)
                {
                    using (var pen = new Pen(color, scale))
                        g.DrawPath(pen, path);
                }
                else
                {
                    using (var brush = new SolidBrush(color))
                        g.FillPath(brush, path);
                }
            }
            g.SmoothingMode = smoothing;
            Color ink = safety == Safety.Unrated ? color : SafetyStyle.InkOn(color);
            TextRenderer.DrawText(g, text, font, badge, ink,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
        }

        /// <summary>Width that fits the longest rating, so badges line up as a column.</summary>
        public static int BadgeWidth(Graphics g, Font font, float scale) =>
            Math.Max(TextRenderer.MeasureText(g, SafetyStyle.Title(Safety.HighRisk), font).Width,
                     TextRenderer.MeasureText(g, "Checking…", font).Width) + (int)(10 * scale);

        private static GraphicsPath RoundedRect(RectangleF r, float radius)
        {
            float d = Math.Min(radius * 2, Math.Min(r.Width, r.Height));
            var path = new GraphicsPath();
            path.AddArc(r.Left, r.Top, d, d, 180, 90);
            path.AddArc(r.Right - d - 1, r.Top, d, d, 270, 90);
            path.AddArc(r.Right - d - 1, r.Bottom - d - 1, d, d, 0, 90);
            path.AddArc(r.Left, r.Bottom - d - 1, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        /// <summary>The badge's label: the rating, or a note that the sources are still being asked.</summary>
        public static string BadgeText(SafetyReport report)
        {
            if (report == null) return SafetyStyle.Title(Safety.Unrated);
            return report.Overall == Safety.Unrated && report.Pending > 0 ? "Checking…" : SafetyStyle.Title(report.Overall);
        }

        public static void OpenLink(IWin32Window owner, string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();
            }
            catch (Exception e) when (e is System.ComponentModel.Win32Exception || e is InvalidOperationException)
            {
                MessageBox.Show(owner, "Could not open " + url + ": " + e.Message, "Process Streamgraph", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public static void Style(Control root, Theme theme)
        {
            root.BackColor = theme.Control;
            root.ForeColor = theme.ControlText;
            foreach (Control control in root.Controls) StyleChild(control, theme);
        }

        private static void StyleChild(Control control, Theme theme)
        {
            switch (control)
            {
                case TextBox box:
                    box.BackColor = theme.IsDark ? theme.InactiveSelection : theme.Window;
                    box.ForeColor = theme.WindowText;
                    box.BorderStyle = theme.IsDark ? BorderStyle.FixedSingle : BorderStyle.Fixed3D;
                    break;
                case LinkLabel link:
                    link.LinkColor = theme.IsDark ? Color.FromArgb(0x7a, 0xb4, 0xff) : Color.FromArgb(0x0b, 0x5c, 0xc4);
                    link.ActiveLinkColor = link.VisitedLinkColor = link.LinkColor;
                    break;
                case Button button:
                    button.FlatStyle = theme.IsDark ? FlatStyle.Flat : FlatStyle.Standard;
                    button.BackColor = theme.IsDark ? theme.InactiveSelection : SystemColors.Control;
                    button.ForeColor = theme.ControlText;
                    if (theme.IsDark) button.FlatAppearance.BorderColor = theme.Border;
                    break;
            }
            foreach (Control child in control.Controls) StyleChild(child, theme);
        }
    }

    /// <summary>A badge on its own, for the report window.</summary>
    internal sealed class SafetyBadge : Control
    {
        private readonly bool dark;
        private Safety safety;

        public SafetyBadge(bool dark)
        {
            this.dark = dark;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer |
                     ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
        }

        public void Set(Safety value, string text)
        {
            safety = value;
            Text = text;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            float scale = DeviceDpi / 96f;
            int width = Math.Min(Width, SafetyDrawing.BadgeWidth(e.Graphics, Font, scale));
            SafetyDrawing.DrawBadge(e.Graphics, new Rectangle(0, 0, width, Height), safety, Text, Font, dark, scale);
        }
    }

    /// <summary>What each source says about one program, with links to their own pages.</summary>
    internal sealed class SafetyReportForm : Form
    {
        private readonly SafetyReport report;
        private readonly SafetyService service;
        private readonly Theme theme;
        private readonly float scale;
        private readonly TableLayoutPanel sources;
        private readonly SafetyBadge overall;
        private readonly Label status, details;

        /// <param name="font">The main window's font, so that text here is the same size.</param>
        public SafetyReportForm(SafetyReport report, SafetyService service, Theme theme, int dpi, Font font)
        {
            this.report = report;
            this.service = service;
            this.theme = theme;
            scale = dpi / 96f;

            Text = "Safety Report: " + report.Name;
            Font = font;
            AutoScaleMode = AutoScaleMode.None;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimizeBox = MaximizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(S(760), S(560));
            MinimumSize = new Size(S(480), S(320));

            var heading = new Label { Text = report.Name, AutoSize = true, Font = new Font(Font.FontFamily, Font.Size * 1.35f, FontStyle.Bold), Margin = new Padding(0, 0, S(12), 0) };
            overall = new SafetyBadge(theme.IsDark) { Font = Font, Size = new Size(S(96), Font.Height + S(4)), Anchor = AnchorStyles.Left, Margin = new Padding(0, S(4), S(12), 0) };
            status = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, S(4), 0, 0) };
            var top = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Top, Padding = new Padding(S(14), S(12), S(14), 0) };
            top.Controls.AddRange(new Control[] { heading, overall, status });

            details = new Label { AutoSize = true, Dock = DockStyle.Top, Padding = new Padding(S(14), S(6), S(14), S(8)) };

            sources = new TableLayoutPanel
            {
                ColumnCount = 3,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Dock = DockStyle.Top,
                Padding = new Padding(S(14), 0, S(14), S(8))
            };
            sources.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            sources.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            sources.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            var scroller = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
            scroller.Controls.Add(sources);
            scroller.Resize += (s, e) => LayoutSummaries();

            var recheck = new Button { Text = "Check Again", AutoSize = true, Padding = new Padding(S(6), S(2), S(6), S(2)) };
            recheck.Click += (s, e) => service.Recheck(report);
            var copy = new Button { Text = report.IsHost ? "Copy Address" : "Copy SHA-256", AutoSize = true, Padding = new Padding(S(6), S(2), S(6), S(2)) };
            copy.Click += (s, e) =>
            {
                string text = report.IsHost ? report.Address : report.Sha256;
                if (text != null) Clipboard.SetText(text);
            };
            var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel, Padding = new Padding(S(6), S(2), S(6), S(2)) };
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(S(10), S(6), S(10), S(10)) };
            buttons.Controls.AddRange(new Control[] { close, copy, recheck });
            CancelButton = close;

            Controls.Add(scroller);
            Controls.Add(details);
            Controls.Add(top);
            Controls.Add(buttons);

            report.Changed += Refill;
            Refill();
            SafetyDrawing.Style(this, theme);
        }

        private int S(int pixels) => (int)(pixels * scale);

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            NativeMethods.SetDarkTitleBar(Handle, theme.IsDark);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            report.Changed -= Refill;
            base.OnFormClosed(e);
        }

        private void Refill()
        {
            if (IsDisposed) return;
            overall.Set(report.Overall, SafetyDrawing.BadgeText(report));
            status.Text = report.Pending > 0 ? "Still asking some sources…" : "Rating is the most serious finding below.";
            if (report.IsHost)
                details.Text = (report.Domain != null ? "Domain: " + report.Domain + "\n" : "") + "Address: " + report.Address;
            else
                details.Text = (report.Path ?? "Program file unknown") +
                               (report.Publisher != null ? "\nPublisher: " + report.Publisher : "") +
                               (report.Sha256 != null ? "\nSHA-256: " + report.Sha256 : "");

            sources.SuspendLayout();
            foreach (Control control in sources.Controls) control.Dispose();
            sources.Controls.Clear();
            sources.RowStyles.Clear();
            int row = 0;
            foreach (SourceResult result in report.Results)
            {
                var name = new Label { Text = result.Source, AutoSize = true, Font = new Font(Font, FontStyle.Bold), Margin = new Padding(0, S(8), S(12), 0) };
                var badge = new SafetyBadge(theme.IsDark) { Font = Font, Size = new Size(S(96), Font.Height + S(4)), Margin = new Padding(0, S(7), S(12), 0) };
                badge.Set(result.Verdict, result.Verdict == Safety.Unrated ? (result.Failed ? "No answer" : "No rating") : SafetyStyle.Title(result.Verdict));

                var body = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = new Padding(0, S(8), 0, S(4)) };
                body.Controls.Add(new Label { Text = result.Summary ?? "", AutoSize = true, Tag = "summary", Margin = Padding.Empty });
                string when = result.Checked > DateTime.MinValue.AddDays(1) ? "Checked " + result.Checked.ToLocalTime().ToString("g") : null;
                if (result.Link != null)
                {
                    var link = new LinkLabel { Text = LinkText(result), AutoSize = true, Margin = new Padding(0, S(3), 0, 0) };
                    string url = result.Link;
                    link.LinkClicked += (s, e) => SafetyDrawing.OpenLink(this, url);
                    body.Controls.Add(link);
                }
                if (when != null)
                    body.Controls.Add(new Label { Text = when, AutoSize = true, ForeColor = theme.MutedInk, Margin = new Padding(0, S(2), 0, 0) });

                sources.Controls.Add(name, 0, row);
                sources.Controls.Add(badge, 1, row);
                sources.Controls.Add(body, 2, row);
                row++;
            }
            if (row == 0)
                sources.Controls.Add(new Label { Text = "Nothing has been checked yet.", AutoSize = true, Margin = new Padding(0, S(8), 0, 0) }, 0, 0);
            SafetyDrawing.Style(sources, theme);
            // Muted labels lose their colour to the styling above; put it back.
            foreach (Control body in sources.Controls)
                foreach (Control part in body.Controls)
                    if (part is Label label && !(part is LinkLabel) && label.Text.StartsWith("Checked ", StringComparison.Ordinal)) label.ForeColor = theme.MutedInk;
            sources.ResumeLayout();
            LayoutSummaries();
        }

        private static string LinkText(SourceResult result)
        {
            switch (result.Source)
            {
                case SafetySources.VirusTotal: return "Open the VirusTotal report";
                case SafetySources.MetaDefender: return "Open the MetaDefender report";
                case SafetySources.MalwareBazaar: return "Open the MalwareBazaar entry";
                case SafetySources.Kev: return result.Link.Contains("nvd.nist.gov") ? "Read the vulnerability details (NVD)" : "Open CISA's catalog";
                case SafetySources.EndOfLife: return "See the support timeline";
                case HostSources.UrlHaus: return "Open the URLhaus entry";
                case HostSources.IpLists: return result.Link.Contains("spamhaus") ? "Check it at Spamhaus" : "Open the Feodo Tracker entry";
                case HostSources.Quad9: return "Look it up at Quad9";
                case HostSources.Cloudflare: return "Look it up on Cloudflare Radar";
                default: return "Read more";
            }
        }

        // Summaries wrap to whatever width the window leaves for them.
        private void LayoutSummaries()
        {
            Control scroller = sources.Parent;
            if (scroller == null) return;
            int used = sources.Padding.Horizontal + SystemInformation.VerticalScrollBarWidth;
            for (int column = 0; column < 2; column++)
            {
                int widest = 0;
                foreach (Control control in sources.Controls)
                    if (sources.GetColumn(control) == column) widest = Math.Max(widest, control.PreferredSize.Width + control.Margin.Horizontal);
                used += widest;
            }
            int width = Math.Max(S(160), scroller.ClientSize.Width - used);
            foreach (Control body in sources.Controls)
                foreach (Control part in body.Controls)
                    if (part is Label label) label.MaximumSize = new Size(width, 0);
            details.MaximumSize = new Size(Math.Max(S(160), ClientSize.Width - details.Padding.Horizontal), 0);
        }
    }

    /// <summary>API keys for the malware scanners, and whether to use the public lists.</summary>
    internal sealed class SafetySourcesForm : Form
    {
        private readonly TextBox virusTotal, metaDefender, abuseCh;
        private readonly CheckBox useLists, askDnsFilters, lookUpAddresses;
        private readonly Theme theme;
        private readonly float scale;

        public SafetySourcesForm(SafetySettings settings, Theme theme, int dpi, Font font)
        {
            this.theme = theme;
            scale = dpi / 96f;
            Text = "Safety Sources";
            Font = font;
            AutoScaleMode = AutoScaleMode.None;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MinimizeBox = MaximizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            int textWidth = S(560);
            var layout = new TableLayoutPanel { ColumnCount = 3, AutoSize = true, Padding = new Padding(S(14)), Dock = DockStyle.Fill };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            void Note(string text, bool heading = false)
            {
                var label = new Label
                {
                    Text = text, AutoSize = true, MaximumSize = new Size(textWidth, 0),
                    Margin = new Padding(0, heading ? S(14) : S(2), 0, S(4))
                };
                if (heading) label.Font = new Font(Font, FontStyle.Bold);
                layout.Controls.Add(label, 0, layout.RowCount);
                layout.SetColumnSpan(label, 3);
                layout.RowCount++;
            }

            TextBox Key(string name, string value, string signUp)
            {
                var label = new Label { Text = name, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, S(4), S(10), S(4)) };
                var box = new TextBox { Text = value, Width = S(330), UseSystemPasswordChar = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, S(4), S(10), S(4)) };
                var link = new LinkLabel { Text = "Get a free key", AutoSize = true, Anchor = AnchorStyles.Left };
                link.LinkClicked += (s, e) => SafetyDrawing.OpenLink(this, signUp);
                layout.Controls.Add(label, 0, layout.RowCount);
                layout.Controls.Add(box, 1, layout.RowCount);
                layout.Controls.Add(link, 2, layout.RowCount);
                layout.RowCount++;
                return box;
            }

            Note("Each program is rated by every source available, and the Safety column shows the most serious finding. " +
                 "Right-click a process and choose Safety Report to see what each source said, with links to its own page.");

            Note("Always on", true);
            Note("Digital signature: Windows checks whether the program file is signed and unaltered. This needs no internet connection.");

            Note("Public lists (no account needed)", true);
            // A check box does not wrap its text, so the explanation goes in a note below it.
            useLists = new CheckBox
            {
                Text = "Check against the public lists of exploited vulnerabilities, unsupported releases and malware hosts",
                Checked = settings.UseLists, AutoSize = true, Margin = new Padding(0, S(2), 0, S(2))
            };
            layout.Controls.Add(useLists, 0, layout.RowCount);
            layout.SetColumnSpan(useLists, 3);
            layout.RowCount++;
            Note("Flags programs with vulnerabilities attackers are actively using, and releases past their end of support. " +
                 "For connections, also flags hosts serving malware (URLhaus), botnet control servers (Feodo Tracker) and " +
                 "criminal networks (Spamhaus DROP). The lists are downloaded once a day; nothing about your computer is sent.");

            Note("Malware-blocking DNS (no account needed)", true);
            askDnsFilters = new CheckBox
            {
                Text = "Ask Cloudflare and Quad9 about the domains in the Connections window",
                Checked = settings.AskDnsFilters, AutoSize = true, Margin = new Padding(0, S(2), 0, S(2))
            };
            layout.Controls.Add(askDnsFilters, 0, layout.RowCount);
            layout.SetColumnSpan(askDnsFilters, 3);
            layout.RowCount++;
            Note("Both run free DNS services that refuse to look up domains known for malware and phishing. Each domain shown " +
                 "in a Connections window is looked up there to see whether it is refused, which tells them the domain name only.");

            Note("Address details (no account needed)", true);
            lookUpAddresses = new CheckBox
            {
                Text = "Ask ipwho.is where the public addresses in the Connections window are, and who owns them",
                Checked = settings.LookUpAddresses, AutoSize = true, Margin = new Padding(0, S(2), 0, S(2))
            };
            layout.Controls.Add(lookUpAddresses, 0, layout.RowCount);
            layout.SetColumnSpan(lookUpAddresses, 3);
            layout.RowCount++;
            Note("Fills the Location and Owner columns. One address from each block of 256 is sent, and the " +
                 "answer is kept for a month. Free for non-commercial use, up to a monthly limit.");

            Note("Malware scanners (free API key each)", true);
            Note("Each program's SHA-256 fingerprint is sent to look it up; the files themselves are never uploaded. " +
                 "Keys are stored encrypted for your Windows account. VirusTotal's free API is for non-commercial use.");
            virusTotal = Key("VirusTotal", settings.VirusTotalKey, "https://www.virustotal.com/gui/join-us");
            metaDefender = Key("MetaDefender", settings.MetaDefenderKey, "https://metadefender.com/");
            abuseCh = Key("MalwareBazaar (abuse.ch)", settings.AbuseChKey, "https://auth.abuse.ch/");

            var show = new CheckBox { Text = "Show keys", AutoSize = true, Margin = new Padding(0, S(2), 0, S(4)) };
            show.CheckedChanged += (s, e) =>
            {
                foreach (TextBox box in new[] { virusTotal, metaDefender, abuseCh }) box.UseSystemPasswordChar = !show.Checked;
            };
            layout.Controls.Add(show, 1, layout.RowCount);
            layout.RowCount++;

            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, AutoSize = true, MinimumSize = new Size(S(80), 0) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true, MinimumSize = new Size(S(80), 0) };
            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, S(14), 0, 0) };
            buttons.Controls.AddRange(new Control[] { cancel, ok });
            layout.Controls.Add(buttons, 0, layout.RowCount);
            layout.SetColumnSpan(buttons, 3);
            layout.RowCount++;
            AcceptButton = ok;
            CancelButton = cancel;

            Controls.Add(layout);
            SafetyDrawing.Style(this, theme);
        }

        private int S(int pixels) => (int)(pixels * scale);

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            NativeMethods.SetDarkTitleBar(Handle, theme.IsDark);
        }

        public SafetySettings Result => new SafetySettings
        {
            VirusTotalKey = virusTotal.Text.Trim(),
            MetaDefenderKey = metaDefender.Text.Trim(),
            AbuseChKey = abuseCh.Text.Trim(),
            UseLists = useLists.Checked,
            AskDnsFilters = askDnsFilters.Checked,
            LookUpAddresses = lookUpAddresses.Checked
        };
    }
}
