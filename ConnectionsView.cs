using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    /// <summary>
    /// The Connections tab: the remote hosts every process, or the one whose PID is in the filter, has
    /// exchanged data with, and how much went each way, since this program started watching, with a
    /// graph of the data rates beside them; updated every second while shown. Without the rights to
    /// trace traffic it lists open TCP connections instead. Each host is rated for safety.
    /// </summary>
    internal sealed class ConnectionsView : UserControl
    {
        private enum Column { ProcessName, FileName, Pid, Domain, Address, Scope, Safety, Location, Owner, Protocol, Port, Use, Sent, Received, Total, LastActive }

        private static readonly int ColumnCount = Enum.GetValues(typeof(Column)).Length;

        // Columns unticked in the header's menu, kept until the program closes.
        private static readonly HashSet<Column> hidden = new HashSet<Column>();
        private static readonly Dictionary<Column, int> hiddenWidths = new Dictionary<Column, int>();     // their widths before, in pixels

        /// <summary>One remote endpoint as shown: traffic summed over the processes that talked to it.</summary>
        private sealed class Row
        {
            public Endpoint Endpoint;
            public readonly HashSet<int> Pids = new HashSet<int>();
            public string Domain = "", Address = "", Protocol = "", Port = "", When = "";
            public string ProcessName = "", FileName = "", PidText = "";    // of the processes that talked to it
            public List<ProcInfo> Processes = new List<ProcInfo>();         // those, by PID; for Show Process
            public string Scope = "", Location = "", Owner = "";
            public string Use = "", UseOf;   // the likely use, and the host name it was guessed from     // the last two for public addresses, from IpDetails
            public bool DomainGuessed;      // from a reverse lookup rather than the process's own lookup
            public bool Local;              // this computer, the local network or multicast: nothing to rate
            public long Sent, Received;
            public DateTime LastActive;
            public SafetyReport Report;     // null for local addresses
            public ListViewItem Item;
        }

        private int? pidFilter;             // null for every process
        private ProcInfo target;            // the process the filter names, as of the last refill; null for none or all
        private readonly TextBox pidBox;
        private readonly Timer filterDelay;  // applies the PID once typing pauses
        private readonly ProcessMonitor monitor;
        private readonly SafetyService safety;
        private Theme theme;
        private readonly float scale;
        private readonly bool traced;
        private readonly ListView list;
        private readonly Label subtitle, note, summary;
        private readonly CheckBox includeHelpers;
        private readonly Timer timer;
        private readonly ContextMenuStrip menu;
        private readonly ToolStripMenuItem copyValue, copyRows, copyAll, showProcess, openLocation, safetyReport;
        private HeaderFiller headerFiller;
        private ListViewItem hotItem;   // row under the mouse
        private readonly ToolTip safetyTip = new ToolTip { AutoPopDelay = 30000, InitialDelay = 400, ReshowDelay = 100 };
        private string safetyTipText;
        private readonly Dictionary<Endpoint, Row> rows = new Dictionary<Endpoint, Row>();
        private Column sortColumn = Column.Total;
        private bool sortDescending = true;
        private Row menuRow;
        private List<ProcInfo> menuProcesses = new List<ProcInfo>();     // what Show Process offers
        private int badgeWidth;
        private ContextMenuStrip columnMenu;
        private readonly ConnectionGraph graph;
        private readonly SplitContainer split;
        private readonly Control timeBar;
        private readonly TrackBar timeSpan;
        private ComboBox layerSort;             // the graph's stacking order, beside the time span
        private ComboBox graphed;               // which way the graph counts traffic
        private readonly Timer animation;       // pans the graph between samples
        private long graphSample = -1;          // the newest sample the graph has been given

        /// <param name="font">The main window's font, so that text here is the same size.</param>
        public ConnectionsView(ProcessMonitor monitor, SafetyService safety, Theme theme, int dpi, Font font, Action restartElevated)
        {
            this.monitor = monitor;
            this.safety = safety;
            this.theme = theme;
            scale = dpi / 96f;
            traced = monitor.NetworkAvailable;
            Font = font;
            AutoScaleMode = AutoScaleMode.None;

            // The PID filter: empty for every process's connections, or one process's (and its helpers').
            pidBox = new TextBox { Width = S(80), Anchor = AnchorStyles.Left, Margin = new Padding(S(3), S(3), S(10), S(3)) };
            filterDelay = new Timer { Interval = 400 };
            filterDelay.Tick += (s, e) => ApplyFilter();
            pidBox.TextChanged += (s, e) =>
            {
                filterDelay.Stop();
                filterDelay.Start();
            };
            pidBox.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter) ApplyFilter();
                else if (e.KeyCode == Keys.Escape) pidBox.Clear();
                else return;
                e.Handled = e.SuppressKeyPress = true;
            };
            // Placeholder text, shown while the box is empty.
            pidBox.HandleCreated += (s, e) => SendMessage(pidBox.Handle, EM_SETCUEBANNER, (IntPtr)1, "All processes");
            subtitle = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, S(4), S(16), 0) };
            includeHelpers = new CheckBox { AutoSize = true, Checked = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, S(3), 0, 0), Visible = false };
            includeHelpers.CheckedChanged += (s, e) => Restart();
            var top = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Top, Padding = new Padding(S(14), S(8), S(14), 0) };
            top.Controls.AddRange(new Control[] { new Label { Text = "PID:", AutoSize = true, Anchor = AnchorStyles.Left }, pidBox, subtitle, includeHelpers });

            note = new Label { AutoSize = true, Dock = DockStyle.Top, Padding = new Padding(S(14), S(6), S(14), S(8)) };
            note.Text = (traced
                ? "Data sent and received since Process Streamgraph started, by remote host. Domains are the names the program " +
                  "looked up; grey ones come from a reverse lookup of the address instead, and may name a hosting or CDN company " +
                  "rather than the site. Browsers using Secure DNS do not show their lookups to Windows."
                : "Showing open TCP connections only. Amounts sent and received, and UDP traffic (which includes most browser " +
                  "traffic over QUIC), need Process Streamgraph to run as administrator." +
                  (monitor.Network.NamesAvailable ? "" : " Domains come from reverse lookups, and may name a hosting company rather than the site.")) +
                " Safety is the most serious finding of the sources under Safety Sources; hover over it for details." +
                " Location and owners of public addresses come from ipwho.is; the location is approximate, and for a CDN " +
                "may be the company's headquarters rather than the server.";

            list = new WheelListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                HideSelection = false,
                BorderStyle = BorderStyle.None,
                OwnerDraw = true,
                AllowColumnReorder = true,
                ListViewItemSorter = new RowComparer(this)
            };
            // Updated every second; without double buffering each update flickers.
            typeof(Control).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                ?.SetValue(list, true);
            AddColumn("Process Name", 160, HorizontalAlignment.Left);
            AddColumn("File Name", 130, HorizontalAlignment.Left);
            AddColumn("PID", 70, HorizontalAlignment.Left);
            AddColumn("Domain", 250, HorizontalAlignment.Left);
            AddColumn("Address", 200, HorizontalAlignment.Left);
            AddColumn("Scope", 70, HorizontalAlignment.Left);
            AddColumn("Safety", 100, HorizontalAlignment.Left);
            AddColumn("Location", 180, HorizontalAlignment.Left);
            AddColumn("Owner", 240, HorizontalAlignment.Left);
            AddColumn("Protocol", 70, HorizontalAlignment.Left);
            AddColumn("Port", 130, HorizontalAlignment.Left);
            AddColumn("Likely Use", 190, HorizontalAlignment.Left);
            AddColumn("Sent", 80, HorizontalAlignment.Right);
            AddColumn("Received", 80, HorizontalAlignment.Right);
            AddColumn("Total", 80, HorizontalAlignment.Right);
            AddColumn(traced ? "Last Active" : "State", 100, HorizontalAlignment.Left);
            list.DrawColumnHeader += DrawHeader;
            list.DrawItem += DrawRow;
            list.DrawSubItem += DrawCell;
            list.ColumnClick += (s, e) =>
            {
                var column = (Column)e.Column;
                // Amounts read best biggest-first, and safety worst-first; names and addresses alphabetically.
                bool firstDescending = column >= Column.Sent || column == Column.Safety;
                sortDescending = column == sortColumn ? !sortDescending : firstDescending;
                sortColumn = column;
                list.Sort();
            };
            foreach (Column column in hidden)
                list.Columns[(int)column].Width = 0;
            // A hidden column stays hidden: its edge in the header can still be dragged.
            list.ColumnWidthChanging += (s, e) =>
            {
                if (!hidden.Contains((Column)e.ColumnIndex)) return;
                e.Cancel = true;
                e.NewWidth = 0;
            };
            list.HandleCreated += (s, e) =>
            {
                NativeMethods.SetWindowTheme(list.Handle, this.theme.IsDark ? "DarkMode_Explorer" : null, null);
                headerFiller = new HeaderFiller(list, this.theme);
                headerFiller.RightClicked += ShowColumnMenu;
            };
            list.HandleDestroyed += (s, e) => headerFiller?.ReleaseHandle();
            list.MouseMove += (s, e) =>
            {
                SetHotItem(list.HitTest(e.Location).Item);
                ShowSafetyTip(e.Location);
            };
            list.MouseLeave += (s, e) =>
            {
                SetHotItem(null);
                ShowSafetyTip(null);
            };
            // Selected rows change colour with the focus, as in the process table.
            list.GotFocus += (s, e) => list.Invalidate();
            list.LostFocus += (s, e) => list.Invalidate();
            list.SelectedIndexChanged += (s, e) =>
            {
                ListViewItem item = list.FocusedItem != null && list.FocusedItem.Selected ? list.FocusedItem
                    : list.SelectedItems.Count > 0 ? list.SelectedItems[0] : null;
                graph.Selected = item?.Tag is Row row ? GraphKey(row) : null;
            };
            list.MouseUp += (s, e) => { if (e.Button == MouseButtons.Right) ShowMenu(e.Location); };
            list.MouseDoubleClick += (s, e) =>
            {
                if (e.Button == MouseButtons.Left && list.HitTest(e.Location).Item?.Tag is Row row) ShowSafetyReport(row);
            };
            list.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.C && e.Control)
                {
                    CopyRows(list.SelectedItems.Count > 0);
                    e.Handled = true;
                }
                else if ((e.KeyCode == Keys.Apps || (e.KeyCode == Keys.F10 && e.Shift)) && list.FocusedItem != null)
                {
                    Rectangle bounds = list.FocusedItem.Bounds;
                    ShowMenu(new Point(bounds.Left + S(20), bounds.Bottom));
                    e.Handled = true;
                }
            };

            menu = new ContextMenuStrip { ShowImageMargin = false, Font = Font };
            copyValue = new ToolStripMenuItem("Copy Value");
            copyValue.Click += (s, e) => CopyText(copyValue.Tag as string);
            copyRows = new ToolStripMenuItem("Copy Selected Rows", null, (s, e) => CopyRows(true));
            copyAll = new ToolStripMenuItem("Copy All Rows", null, (s, e) => CopyRows(false));
            showProcess = new ToolStripMenuItem("Show Process");
            showProcess.Click += (s, e) =>
            {
                if (showProcess.DropDownItems.Count == 0 && menuProcesses.Count == 1)
                    ProcessRequested?.Invoke(menuProcesses[0]);
            };
            openLocation = new ToolStripMenuItem("Open File Location");
            openLocation.Click += (s, e) =>
            {
                if (openLocation.DropDownItems.Count == 0) OpenLocation(openLocation.Tag as string);
            };
            safetyReport = new ToolStripMenuItem("Safety Report…", null, (s, e) => ShowSafetyReport(menuRow));
            menu.Items.AddRange(new ToolStripItem[] { showProcess, openLocation, safetyReport, new ToolStripSeparator(), copyValue, copyRows, copyAll });

            summary = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(S(4), S(8), S(12), 0) };
            var copy = new Button { Text = "Copy", AutoSize = true, Padding = new Padding(S(6), S(2), S(6), S(2)) };
            copy.Click += (s, e) => CopyRows(list.SelectedItems.Count > 0);
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(S(10), S(6), S(10), S(10)) };
            buttons.Controls.Add(copy);
            if (!traced && monitor.NetworkAccessDenied && restartElevated != null)
            {
                var elevate = new Button { Text = "Restart as Administrator", AutoSize = true, Padding = new Padding(S(6), S(2), S(6), S(2)) };
                elevate.Click += (s, e) => restartElevated();
                buttons.Controls.Add(elevate);
            }
            buttons.Controls.Add(summary);

            graph = new ConnectionGraph(monitor) { Dock = DockStyle.Fill, Font = font, Theme = theme };
            graph.SeriesClicked += SelectRowsOf;
            graph.SeriesMenuRequested += ShowLayerMenu;
            graph.ElevationRequested += () => restartElevated?.Invoke();
            timeBar = BuildTimeBar(out timeSpan);

            var listFrame = new Panel { Dock = DockStyle.Fill, Padding = new Padding(S(14), 0, 0, 0) };
            listFrame.Controls.Add(list);
            // The list on the left, and on the right the graph with its time span bar.
            split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, SplitterWidth = S(6) };
            split.Panel1.Controls.Add(listFrame);
            split.Panel2.Controls.Add(graph);
            split.Panel2.Controls.Add(timeBar);
            Controls.Add(split);
            Controls.Add(note);
            Controls.Add(top);
            Controls.Add(buttons);
            ApplyTheme(theme);
            // The list's share and the least widths are set once the split has its real width: they
            // cannot be met by the small size it is created at, and setting them then throws.
            bool splitPlaced = false;
            split.SizeChanged += (s, e) =>
            {
                if (splitPlaced || split.Width < S(240) + S(260) + split.SplitterWidth) return;
                splitPlaced = true;
                split.SplitterDistance = Math.Max(S(240), split.Width * 58 / 100);
                split.Panel1MinSize = S(240);
                split.Panel2MinSize = S(260);
            };
            Resize += (s, e) => note.MaximumSize = new Size(Math.Max(S(200), ClientSize.Width - note.Padding.Horizontal), 0);
            // Nothing is gathered while another tab is shown, and the list catches up as soon as it is back.
            VisibleChanged += (s, e) =>
            {
                if (!Visible) return;
                Refill();
                UpdateGraph();
            };

            Favicons.Loaded += OnFaviconLoaded;

            timer = new Timer { Interval = 1000 };
            timer.Tick += (s, e) => { if (Visible) Refill(); };
            Refill();
            timer.Start();

            animation = new Timer { Interval = 15 };
            animation.Tick += (s, e) =>
            {
                if (!Visible || FindForm()?.WindowState == FormWindowState.Minimized) return;
                if (monitor.SampleIndex != graphSample) UpdateGraph();
                graph.Animate();
            };
            animation.Start();
        }

        private const int EM_SETCUEBANNER = 0x1501;

        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);

        /// <summary>Raised by Show Process in a row's menu, with the process to show in the Processes tab.</summary>
        public event Action<ProcInfo> ProcessRequested;

        /// <summary>Shows one process's connections, by putting its PID in the filter.</summary>
        public void ShowProcess(ProcInfo process)
        {
            pidBox.Text = process.Pid.ToString(CultureInfo.InvariantCulture);
            ApplyFilter();
        }

        // Takes up the PID in the box; anything that is not a number counts as empty.
        private void ApplyFilter()
        {
            filterDelay.Stop();
            int? pid = int.TryParse(pidBox.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int value) ? value : (int?)null;
            if (pid == pidFilter) return;
            pidFilter = pid;
            Restart();
        }

        /// <summary>Starts the list and graph afresh, with nothing selected, as when the filter changes.</summary>
        private void Restart()
        {
            list.BeginUpdate();
            list.Items.Clear();
            list.EndUpdate();
            rows.Clear();
            hotItem = null;
            menuRow = null;
            graph.Clear();
            graphSample = -1;
            if (Visible)
            {
                Refill();
                UpdateGraph();
            }
        }

        public void ApplyTheme(Theme theme)
        {
            this.theme = theme;
            SafetyDrawing.Style(this, theme);
            subtitle.ForeColor = theme.MutedInk;
            list.BackColor = theme.Window;
            list.ForeColor = theme.WindowText;
            if (list.IsHandleCreated) NativeMethods.SetWindowTheme(list.Handle, theme.IsDark ? "DarkMode_Explorer" : null, null);
            if (headerFiller != null) headerFiller.Theme = theme;
            menu.Renderer = theme.IsDark ? new ThemedMenuRenderer(theme) : (ToolStripRenderer)new ToolStripProfessionalRenderer();
            menu.ForeColor = theme.ControlText;
            timeBar.BackColor = timeSpan.BackColor = theme.Control;
            timeBar.ForeColor = theme.ControlText;
            // The standard combo box ignores colours, so the dark theme uses the flat one, as in the toolbar.
            foreach (ComboBox box in new[] { layerSort, graphed })
            {
                box.FlatStyle = theme.IsDark ? FlatStyle.Flat : FlatStyle.Standard;
                box.BackColor = theme.IsDark ? theme.InactiveSelection : theme.Window;
                box.ForeColor = theme.WindowText;
            }
            split.BackColor = theme.Control;
            split.Panel1.BackColor = theme.Control;
            split.Panel2.BackColor = theme.Surface;
            graph.Theme = theme;
            // The cells keep the colours they were given until refilled.
            foreach (Row row in rows.Values) Show(row);
            list.Invalidate(true);
        }

        /// <summary>The bar above the graph with the slider that sets how much history it shows.</summary>
        private Control BuildTimeBar(out TrackBar slider)
        {
            var bar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = true,     // onto a second line when the graph is narrow
                Padding = new Padding(S(8), S(2), S(6), S(2))
            };
            int[] spans = MainForm.TimeSpans;
            var trackBar = new TrackBar
            {
                Minimum = 0,
                Maximum = spans.Length - 1,
                Value = Array.IndexOf(spans, 60),
                LargeChange = 1,
                TickStyle = TickStyle.None,
                AutoSize = false,
                Width = S(120),
                Height = S(26),
                Anchor = AnchorStyles.Left
            };
            var shown = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Text = MainForm.SpanText(spans[trackBar.Value]) };
            graph.VisibleSeconds = spans[trackBar.Value];
            trackBar.ValueChanged += (s, e) =>
            {
                shown.Text = MainForm.SpanText(spans[trackBar.Value]);
                graph.VisibleSeconds = spans[trackBar.Value];
            };
            bar.Controls.Add(new Label { Text = "Time span:", AutoSize = true, Anchor = AnchorStyles.Left });
            bar.Controls.Add(trackBar);
            bar.Controls.Add(shown);

            layerSort = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = S(110), Anchor = AnchorStyles.Left };
            layerSort.Items.AddRange(new object[] { "Domain", "Owner", "Data rate", "Data (total)" });
            layerSort.SelectedIndex = (int)ConnectionSort.Rate;
            layerSort.SelectedIndexChanged += (s, e) => graph.SortMode = (ConnectionSort)layerSort.SelectedIndex;
            var reverse = new CheckBox { Text = "Reverse", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(S(6), S(3), 0, S(3)) };
            reverse.CheckedChanged += (s, e) => graph.Reverse = reverse.Checked;
            bar.Controls.Add(new Label { Text = "Sort layers by:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(S(18), 0, S(3), 0) });
            bar.Controls.Add(layerSort);
            bar.Controls.Add(reverse);

            graphed = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = S(90), Anchor = AnchorStyles.Left };
            graphed.Items.AddRange(new object[] { "Total", "Sent", "Received" });
            graphed.SelectedIndex = (int)TrafficDirection.Both;
            graphed.SelectedIndexChanged += (s, e) =>
            {
                graph.Direction = (TrafficDirection)graphed.SelectedIndex;
                UpdateGraph();
            };
            bar.Controls.Add(new Label { Text = "Graph:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(S(18), 0, S(3), 0) });
            bar.Controls.Add(graphed);
            slider = trackBar;
            return bar;
        }

        /// <summary>
        /// What a row's traffic is graphed under: its domain, so that a site's addresses make one layer,
        /// or its address when it has no domain or only a local label.
        /// </summary>
        private static string GraphKey(Row row) => row.Local || row.Domain == "" ? row.Address : row.Domain;

        /// <summary>Hands the graph each host's data rate over the whole history, from the members' traffic by sample.</summary>
        private void UpdateGraph()
        {
            graphSample = monitor.SampleIndex;
            TrafficDirection direction = graph.Direction;
            int count = monitor.SampleCount;
            if (count < 2) return;
            long first = graphSample - count + 1;
            graph.RefreshSeconds = Math.Max(0.1, monitor.SampleSeconds(graphSample) - monitor.SampleSeconds(graphSample - 1));
            var byKey = new Dictionary<string, GraphSeries>();
            var addresses = new Dictionary<string, HashSet<string>>();
            var uses = new Dictionary<string, string>();
            foreach (ProcInfo p in Members(out _))
            {
                if (p.Connections == null) continue;
                foreach (Connection c in p.Connections.Values)
                {
                    if (c.History.Count == 0 || c.History[c.History.Count - 1].Sample < first || !rows.TryGetValue(c.Endpoint, out Row row)) continue;
                    string key = GraphKey(row);
                    if (!byKey.TryGetValue(key, out GraphSeries series))
                    {
                        byKey[key] = series = new GraphSeries
                        {
                            Key = key,
                            Name = row.Local ? row.Domain + "  ·  " + row.Address : key,
                            About = row.Owner == "…" ? "" : row.Owner,
                            Color = LayerColor(key),
                            Icon = IconFor(row),
                            Values = new float[count]
                        };
                        addresses[key] = new HashSet<string>();
                    }
                    addresses[key].Add(row.Address);
                    if (row.Use != "" && !uses.ContainsKey(key)) uses[key] = row.Use;
                    series.Total += direction == TrafficDirection.Sent ? c.Sent : direction == TrafficDirection.Received ? c.Received : c.Sent + c.Received;
                    if (series.Detail == null && row.Location != "" && row.Location != "…") series.Detail = row.Location;
                    foreach (Moved moved in c.History)
                    {
                        if (moved.Sample < first || moved.Sample > graphSample) continue;
                        long bytes = direction == TrafficDirection.Sent ? moved.Sent : direction == TrafficDirection.Received ? moved.Received : moved.Sent + moved.Received;
                        if (bytes == 0) continue;
                        double seconds = moved.Sample > 0 ? monitor.SampleSeconds(moved.Sample) - monitor.SampleSeconds(moved.Sample - 1) : 1;
                        series.Values[moved.Sample - first] += (float)(bytes / 1024.0 / Math.Max(seconds, 0.05));
                    }
                }
            }
            foreach (GraphSeries series in byKey.Values)
            {
                // The address, or how many, unless the name already says.
                HashSet<string> seen = addresses[series.Key];
                string where = seen.Count > 1 ? seen.Count + " addresses" : series.Name.Contains(seen.First()) ? "" : seen.First();
                uses.TryGetValue(series.Key, out string use);
                series.Detail = string.Join("  ·  ", new[] { use, where, series.Detail }.Where(part => !string.IsNullOrEmpty(part)));
            }
            graph.SetData(first, byKey.Values.ToList());
        }

        /// <summary>
        /// A layer's colour, in the hue of the site it belongs to, so that a site's subdomains look related,
        /// and a shade of it from the full name, so that they can still be told apart.
        /// </summary>
        private static Color LayerColor(string key)
        {
            string site = key;
            if (!System.Net.IPAddress.TryParse(key, out _))
            {
                string[] parts = key.Split('.');
                if (parts.Length > 2) site = parts[parts.Length - 2] + "." + parts[parts.Length - 1];
            }
            uint hash = 2166136261;
            foreach (char c in key)
                hash = unchecked((hash ^ c) * 16777619u);
            return ProcessMonitor.ColorFor(site, (int)(hash % 5) * 4);
        }

        /// <summary>Selects the rows a graph layer stands for.</summary>
        private void SelectRowsOf(string key)
        {
            list.BeginUpdate();
            list.SelectedItems.Clear();
            ListViewItem firstItem = null;
            foreach (ListViewItem item in list.Items)
            {
                if (!(item.Tag is Row row) || GraphKey(row) != key) continue;
                item.Selected = true;
                if (firstItem == null || item.Index < firstItem.Index) firstItem = item;
            }
            list.EndUpdate();
            if (firstItem == null) return;
            firstItem.Focused = true;
            firstItem.EnsureVisible();
            list.Focus();
        }

        // A tick for each column that can be hidden; the domain always stays.
        private void ShowColumnMenu(Point screen)
        {
            columnMenu?.Dispose();
            columnMenu = new ContextMenuStrip { ShowImageMargin = false, ShowCheckMargin = true, Font = Font };
            if (theme.IsDark) columnMenu.Renderer = new ThemedMenuRenderer(theme);
            columnMenu.ForeColor = theme.ControlText;
            foreach (ColumnHeader header in list.Columns.Cast<ColumnHeader>().OrderBy(c => c.DisplayIndex))
            {
                var column = (Column)header.Index;
                if (column == Column.Domain) continue;
                var item = new ToolStripMenuItem(header.Text) { Checked = !hidden.Contains(column), CheckOnClick = true };
                item.CheckedChanged += (s, e) => SetShown(column, item.Checked);
                columnMenu.Items.Add(item);
            }
            columnMenu.Show(screen);
        }

        private void SetShown(Column column, bool show)
        {
            ColumnHeader header = list.Columns[(int)column];
            if (show)
            {
                if (!hidden.Remove(column)) return;
                header.Width = hiddenWidths.TryGetValue(column, out int width) && width > 0 ? width : S(100);
            }
            else
            {
                if (hidden.Contains(column)) return;
                hiddenWidths[column] = header.Width;
                header.Width = 0;
                hidden.Add(column);
                if (sortColumn == column)
                {
                    // Sorting by a column that is no longer there would be a puzzle.
                    sortColumn = Column.Total;
                    sortDescending = true;
                    list.Sort();
                }
            }
            list.Invalidate();
        }

        private int S(int pixels) => (int)(pixels * scale);

        private void AddColumn(string title, int width, HorizontalAlignment align) =>
            list.Columns.Add(new ColumnHeader { Text = title, Width = S(width), TextAlign = align });

        // On a background thread.
        private void OnFaviconLoaded()
        {
            try
            {
                if (IsHandleCreated && !IsDisposed) BeginInvoke((Action)(() => list.Invalidate()));
            }
            catch (InvalidOperationException)
            {
                // Closed in the meantime.
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Favicons.Loaded -= OnFaviconLoaded;
                timer.Dispose();
                animation.Dispose();
                filterDelay.Dispose();
                menu.Dispose();
                columnMenu?.Dispose();
                safetyTip.Dispose();
            }
            base.Dispose(disposing);
        }

        private void DrawHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            using (var back = new SolidBrush(theme.Control))
                e.Graphics.FillRectangle(back, e.Bounds);
            using (var pen = new Pen(theme.Border))
            {
                e.Graphics.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                e.Graphics.DrawLine(pen, e.Bounds.Right - 1, e.Bounds.Top + S(4), e.Bounds.Right - 1, e.Bounds.Bottom - S(5));
            }
            string title = e.Header.Text;
            if ((Column)e.ColumnIndex == sortColumn) title = sortDescending ? title + "  ▼" : title + "  ▲";
            var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix |
                        (e.Header.TextAlign == HorizontalAlignment.Right ? TextFormatFlags.Right : TextFormatFlags.Left);
            Rectangle text = Rectangle.Inflate(e.Bounds, -S(6), 0);
            TextRenderer.DrawText(e.Graphics, title, Font, text, theme.ControlText, flags);
        }

        // Rows are drawn here rather than by the list, in the process table's colours: the list's own
        // highlights do not follow the theme, and could not take in the rating's badges.
        private Color RowBack(ListViewItem item) =>
            item.Selected ? (list.Focused ? theme.Selection : theme.InactiveSelection) : item == hotItem ? theme.Hover : theme.Window;

        private Color RowInk(ListViewItem item) =>
            item.Selected ? (list.Focused ? theme.SelectionText : theme.InactiveSelectionText) : theme.WindowText;

        private void DrawRow(object sender, DrawListViewItemEventArgs e)
        {
            // The whole row, including any width past the last column; the cells then go on top.
            using (var back = new SolidBrush(RowBack(e.Item)))
                e.Graphics.FillRectangle(back, new Rectangle(0, e.Bounds.Top, list.ClientSize.Width, e.Bounds.Height));
        }

        /// <summary>
        /// The site icon for a row's domain, or null. Fetching one contacts the site, so it waits until
        /// the host has been rated, and is never done for one rated Caution or worse.
        /// </summary>
        private static Bitmap IconFor(Row row)
        {
            if (row.Local || row.Domain == "" || row.Report == null || row.Report.Pending > 0 || row.Report.Overall >= Safety.Caution) return null;
            return Favicons.Get(row.Domain);
        }

        /// <summary>
        /// A cell's bounds, from the columns' widths in their shown order. The list's own bounds for the
        /// first column span the whole row once that column has been dragged away from the left.
        /// </summary>
        private Rectangle CellBounds(ListViewItem item, int column)
        {
            Rectangle row = item.GetBounds(ItemBoundsPortion.Entire);
            int left = row.Left, order = list.Columns[column].DisplayIndex;
            foreach (ColumnHeader header in list.Columns)
                if (header.DisplayIndex < order) left += header.Width;
            return new Rectangle(left, row.Top, list.Columns[column].Width, row.Height);
        }

        // The column under x, by its index; the list's own hit test has the same trouble as its bounds.
        private int ColumnAt(ListViewItem item, int x)
        {
            for (int i = 0; i < list.Columns.Count; i++)
            {
                Rectangle cell = CellBounds(item, i);
                if (x >= cell.Left && x < cell.Right) return i;
            }
            return -1;
        }

        private void DrawCell(object sender, DrawListViewSubItemEventArgs e)
        {
            Rectangle bounds = CellBounds(e.Item, e.ColumnIndex);
            using (var back = new SolidBrush(RowBack(e.Item)))
                e.Graphics.FillRectangle(back, bounds);
            if (!(e.Item.Tag is Row row)) return;
            var column = (Column)e.ColumnIndex;
            if (column != Column.Safety)
            {
                Color ink = RowInk(e.Item);
                if (column == Column.Domain && row.DomainGuessed && !e.Item.Selected) ink = theme.MutedInk;
                bool right = list.Columns[e.ColumnIndex].TextAlign == HorizontalAlignment.Right;
                var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine |
                            (right ? TextFormatFlags.Right : TextFormatFlags.Left);
                Rectangle text = Rectangle.Inflate(bounds, -S(6), 0);
                if (column == Column.Domain)
                {
                    // Every domain gets the room for an icon, so that the names line up.
                    int size = S(16);
                    Bitmap icon = IconFor(row);
                    if (icon != null)
                    {
                        var place = new Rectangle(text.Left, bounds.Top + (bounds.Height - size) / 2, size, size);
                        // An icon about as dark or light as the row goes on a tile of the other shade.
                        float lightness = Favicons.Lightness(icon);
                        bool darkRow = RowBack(e.Item).GetBrightness() < 0.5f;
                        if (darkRow ? lightness < 0.3f : lightness > 0.85f)
                            using (var tile = new SolidBrush(darkRow ? Color.FromArgb(0xe8, 0xe6, 0xdf) : Color.FromArgb(0x3a, 0x3a, 0x37)))
                                e.Graphics.FillRectangle(tile, Rectangle.Inflate(place, S(1), S(1)));
                        e.Graphics.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                        e.Graphics.DrawImage(icon, place);
                    }
                    text = Rectangle.FromLTRB(text.Left + size + S(6), text.Top, text.Right, text.Bottom);
                }
                TextRenderer.DrawText(e.Graphics, e.SubItem.Text, Font, text, ink, flags);
                return;
            }
            if (row.Report == null) return;
            if (badgeWidth == 0) badgeWidth = SafetyDrawing.BadgeWidth(e.Graphics, Font, scale);
            Rectangle cell = Rectangle.FromLTRB(bounds.Left + S(6), bounds.Top, bounds.Right - S(4), bounds.Bottom);
            int width = Math.Min(cell.Width, badgeWidth);
            int height = Math.Min(cell.Height - 2, Font.Height + S(2));
            var badge = new Rectangle(cell.Left, cell.Top + (cell.Height - height) / 2, width, height);
            SafetyDrawing.DrawBadge(e.Graphics, badge, row.Report.Overall, SafetyDrawing.BadgeText(row.Report), Font, theme.IsDark, scale);
        }

        /// <summary>
        /// The processes whose connections are shown. With no filter, every process; with one, the
        /// process of that PID and, when included, its helpers: processes below it running the same program.
        /// </summary>
        private List<ProcInfo> Members(out int helpers)
        {
            helpers = 0;
            target = null;
            if (pidFilter == null) return new List<ProcInfo>(monitor.Processes);
            // A PID can belong to an exited process and a newer one; the running one comes first.
            foreach (ProcInfo p in monitor.Processes)
                if (p.Pid == pidFilter && (target == null || (p.Alive && !target.Alive) || (p.Alive == target.Alive && p.CreateTime > target.CreateTime)))
                    target = p;
            if (target == null) return new List<ProcInfo>();
            ProcInfo process = target;
            var members = new List<ProcInfo> { process };
            var byParent = new Dictionary<int, List<ProcInfo>>();
            foreach (ProcInfo p in monitor.Processes)
            {
                if (!byParent.TryGetValue(p.ParentPid, out List<ProcInfo> children)) byParent[p.ParentPid] = children = new List<ProcInfo>();
                children.Add(p);
            }
            var found = new List<ProcInfo>();
            var stack = new Stack<ProcInfo>();
            stack.Push(process);
            while (stack.Count > 0)
            {
                ProcInfo parent = stack.Pop();
                if (!byParent.TryGetValue(parent.Pid, out List<ProcInfo> children)) continue;
                foreach (ProcInfo child in children)
                {
                    // A PID can be reused, so a child must have started after its parent.
                    if (child == parent || child.CreateTime < parent.CreateTime || found.Contains(child)) continue;
                    if (!string.Equals(child.Name, process.Name, StringComparison.OrdinalIgnoreCase)) continue;
                    found.Add(child);
                    stack.Push(child);
                }
            }
            helpers = found.Count;
            if (includeHelpers.Checked) members.AddRange(found);
            return members;
        }

        private void Refill()
        {
            if (IsDisposed) return;
            List<ProcInfo> members = Members(out int helpers);
            subtitle.Text = pidFilter == null ? "Connections of every process"
                : target == null ? "No process has PID " + pidFilter
                : target.DisplayName + (target.DisplayName != target.Name ? "  ·  " + target.Name : "") + (target.Alive ? "" : "  ·  exited");
            includeHelpers.Visible = helpers > 0;
            includeHelpers.Text = $"Include its {helpers} helper process{(helpers == 1 ? "" : "es")} (in Chromium-based programs, the network service does the talking)";

            // Gather this second's figures by endpoint.
            var current = new Dictionary<Endpoint, Row>();
            if (traced)
            {
                foreach (ProcInfo p in members)
                {
                    if (p.Connections == null) continue;
                    foreach (Connection c in p.Connections.Values)
                    {
                        Row row = Gather(current, c.Endpoint, p.Pid);
                        row.Sent += c.Sent;
                        row.Received += c.Received;
                        if (c.LastActive > row.LastActive) row.LastActive = c.LastActive;
                    }
                }
            }
            else
            {
                var pids = new HashSet<int>();
                foreach (ProcInfo p in members)
                    if (p.Alive) pids.Add(p.Pid);
                foreach (KeyValuePair<int, Connection> entry in ConnectionInfo.TcpConnections(pids))
                {
                    Row row = Gather(current, entry.Value.Endpoint, entry.Key);
                    // The most advanced state among duplicates: one open connection makes the endpoint open.
                    if (row.When == "" || entry.Value.State == "Open") row.When = entry.Value.State;
                }
            }

            var byPid = new Dictionary<int, ProcInfo>();
            foreach (ProcInfo p in members)
                if (!byPid.TryGetValue(p.Pid, out ProcInfo known) || (p.Alive && !known.Alive)) byPid[p.Pid] = p;
            bool lookUp = safety.Settings.LookUpAddresses;
            list.BeginUpdate();
            // Endpoints gone from the table (closed connections) leave; traced ones stay with their totals.
            var gone = new List<Endpoint>();
            foreach (Endpoint endpoint in rows.Keys)
                if (!current.ContainsKey(endpoint)) gone.Add(endpoint);
            foreach (Endpoint endpoint in gone)
            {
                list.Items.Remove(rows[endpoint].Item);
                rows.Remove(endpoint);
            }
            DateTime now = DateTime.Now;
            foreach (Row fresh in current.Values)
            {
                if (traced) fresh.When = (now - fresh.LastActive).TotalSeconds < 2.5 ? "Now" : fresh.LastActive.ToString("T");
                if (!rows.TryGetValue(fresh.Endpoint, out Row row))
                {
                    row = fresh;
                    row.Item = new ListViewItem(Array.ConvertAll(new string[ColumnCount], _ => "")) { Tag = row, UseItemStyleForSubItems = false };
                    rows[row.Endpoint] = row;
                    list.Items.Add(row.Item);
                }
                else
                {
                    if (row.Domain != fresh.Domain || row.DomainGuessed != fresh.DomainGuessed) row.Report = null;    // rated afresh, by its new name
                    row.Domain = fresh.Domain;
                    row.DomainGuessed = fresh.DomainGuessed;
                    row.Sent = fresh.Sent;
                    row.Received = fresh.Received;
                    row.LastActive = fresh.LastActive;
                    row.When = fresh.When;
                    row.Pids.Clear();
                    row.Pids.UnionWith(fresh.Pids);
                }
                FillProcesses(row, byPid);
                if (row.Report == null && !row.Local)
                {
                    // Only a name the program looked up itself is worth checking; a reverse lookup's names the host's owner.
                    string domain = row.DomainGuessed || row.Domain == "" ? null : row.Domain;
                    row.Report = safety.ReportForHost(domain, row.Endpoint.Address.ToIPAddress());
                }
                if (row.UseOf != row.Domain)
                {
                    row.UseOf = row.Domain;
                    row.Use = row.Local ? ConnectionInfo.PortName(row.Endpoint.Port, row.Endpoint.Udp) ?? "" : ServiceGuess.Describe(row.Domain, row.Endpoint.Port, row.Endpoint.Udp);
                }
                FillDetails(row, lookUp);
                Show(row);
            }
            list.Sort();
            list.EndUpdate();

            long sent = 0, received = 0;
            foreach (Row row in rows.Values)
            {
                sent += row.Sent;
                received += row.Received;
            }
            int risky = rows.Values.Count(r => r.Report != null && r.Report.Overall >= Safety.Caution);
            summary.Text = (traced
                ? $"{rows.Count} remote host{(rows.Count == 1 ? "" : "s")}  ·  sent {Bytes(sent)}  ·  received {Bytes(received)}"
                : $"{rows.Count} open connection{(rows.Count == 1 ? "" : "s")}") +
                (risky > 0 ? $"  ·  {risky} flagged" : "");
        }

        /// <summary>
        /// Who talked to an endpoint: the program's name, file path and PID for one process; for several,
        /// the first few names and PIDs, and the path when they all run the same program.
        /// </summary>
        private static void FillProcesses(Row row, Dictionary<int, ProcInfo> byPid)
        {
            row.Processes.Clear();
            var names = new List<string>();
            var files = new List<string>();
            foreach (int pid in row.Pids.OrderBy(pid => pid))
            {
                if (!byPid.TryGetValue(pid, out ProcInfo p)) continue;
                row.Processes.Add(p);
                if (!names.Contains(p.DisplayName)) names.Add(p.DisplayName);
                if (!string.IsNullOrEmpty(p.Name) && !files.Contains(p.Name, StringComparer.OrdinalIgnoreCase)) files.Add(p.Name);
            }
            row.ProcessName = names.Count <= 2 ? string.Join(", ", names) : names[0] + ", " + names[1] + " +" + (names.Count - 2) + " more";
            row.FileName = files.Count <= 2 ? string.Join(", ", files) : files[0] + ", " + files[1] + " +" + (files.Count - 2) + " more";
            List<int> pids = row.Pids.OrderBy(pid => pid).ToList();
            row.PidText = string.Join(", ", pids.Take(3)) + (pids.Count > 3 ? " +" + (pids.Count - 3) : "");
        }

        private Row Gather(Dictionary<Endpoint, Row> current, Endpoint endpoint, int pid)
        {
            if (current.TryGetValue(endpoint, out Row row))
            {
                row.Pids.Add(pid);
                if (row.Domain == "" || row.DomainGuessed) ApplyLookedUpName(row, pid);
                return row;
            }
            System.Net.IPAddress address = endpoint.Address.ToIPAddress();
            row = new Row
            {
                Endpoint = endpoint,
                Address = address.ToString(),
                Protocol = endpoint.Udp ? "UDP" : "TCP",
                Scope = ConnectionInfo.Scope(address)
            };
            string service = ConnectionInfo.PortName(endpoint.Port, endpoint.Udp);
            row.Port = endpoint.Port.ToString(CultureInfo.InvariantCulture) + (service != null ? "  ·  " + service : "");
            row.Pids.Add(pid);
            ApplyLookedUpName(row, pid);
            if (row.Domain == "")
            {
                string local = ConnectionInfo.LocalLabel(address);
                row.Local = local != null;
                row.Domain = local ?? "";
                if (row.Domain == "")
                {
                    row.Domain = ConnectionInfo.ReverseName(endpoint.Address) ?? "";
                    row.DomainGuessed = row.Domain != "";
                }
            }
            current[endpoint] = row;
            return row;
        }

        /// <summary>
        /// A public address's location and owner, "…" while they are looked up. The company running the
        /// network follows the owner only when it is someone else, as for Amazon's addresses, which are
        /// registered to Amazon Technologies but run by Amazon.com.
        /// </summary>
        private static void FillDetails(Row row, bool lookUp)
        {
            IpDetail detail = null;
            bool pending = false;
            if (lookUp && row.Scope == "Public") detail = IpDetails.Get(row.Endpoint.Address, out pending);
            string waiting = pending ? "…" : "";
            row.Location = detail?.Location ?? waiting;
            if (detail == null)
            {
                row.Owner = waiting;
                return;
            }
            string owner = detail.Owner ?? "", company = detail.Company ?? "";
            bool redundant = company == "" || owner.IndexOf(company, StringComparison.OrdinalIgnoreCase) >= 0;
            row.Owner = owner == "" ? company : redundant ? owner : owner + "  ·  " + company;
        }

        private void ApplyLookedUpName(Row row, int pid)
        {
            string name = monitor.Network.NameFor(pid, row.Endpoint.Address);
            if (name == null) return;
            row.Domain = name;
            row.DomainGuessed = false;
            row.Local = false;
        }

        private void Show(Row row)
        {
            ListViewItem item = row.Item;
            Set(item, Column.Domain, row.Domain);
            item.SubItems[(int)Column.Domain].ForeColor = row.DomainGuessed ? theme.MutedInk : theme.WindowText;
            Set(item, Column.ProcessName, row.ProcessName);
            Set(item, Column.FileName, row.FileName);
            Set(item, Column.Pid, row.PidText);
            Set(item, Column.Address, row.Address);
            // The badge is drawn, not written; the text here only makes the cell repaint when the rating changes.
            Set(item, Column.Safety, row.Report == null ? "" : SafetyDrawing.BadgeText(row.Report));
            Set(item, Column.Scope, row.Scope);
            Set(item, Column.Location, row.Location);
            Set(item, Column.Owner, row.Owner);
            Set(item, Column.Protocol, row.Protocol);
            Set(item, Column.Port, row.Port);
            Set(item, Column.Use, row.Use + Direction(row));
            Set(item, Column.Sent, traced ? Bytes(row.Sent) : "—");
            Set(item, Column.Received, traced ? Bytes(row.Received) : "—");
            Set(item, Column.Total, traced ? Bytes(row.Sent + row.Received) : "—");
            Set(item, Column.LastActive, row.When);
        }

        /// <summary>
        /// "  ·  mostly sending" for a host this computer sent far more to than it got back, a megabyte or more:
        /// an upload, a backup or a call, and worth knowing about. Downloads are what most hosts do.
        /// </summary>
        private string Direction(Row row)
        {
            if (!traced || row.Sent < 1024 * 1024 || row.Sent < row.Received * 3) return "";
            return row.Use == "" ? "Mostly sending" : "  ·  mostly sending";
        }

        private void Set(ListViewItem item, Column column, string text)
        {
            ListViewItem.ListViewSubItem cell = item.SubItems[(int)column];
            if (cell.Text != text) cell.Text = text;
            if (column != Column.Domain && cell.ForeColor != theme.WindowText) cell.ForeColor = theme.WindowText;
            if (cell.BackColor != theme.Window) cell.BackColor = theme.Window;
        }

        public static string Bytes(long bytes)
        {
            if (bytes < 1024) return bytes.ToString(CultureInfo.CurrentCulture) + " B";
            return Format.Memory(bytes / 1048576.0);
        }

        /// <summary>A row's column titles and values, for the copy items.</summary>
        private List<KeyValuePair<string, string>> CellsOf(Row row)
        {
            var cells = new List<KeyValuePair<string, string>>();
            foreach (ColumnHeader header in ShownOrder())
                cells.Add(new KeyValuePair<string, string>(header.Text, row.Item.SubItems[header.Index].Text));
            return cells;
        }

        private List<ColumnHeader> ShownOrder() =>
            list.Columns.Cast<ColumnHeader>().Where(c => !hidden.Contains((Column)c.Index)).OrderBy(c => c.DisplayIndex).ToList();

        // Where a column, by its index, now sits among the shown ones; -1 for none.
        private int DisplayPosition(int index) =>
            index < 0 || index >= list.Columns.Count || hidden.Contains((Column)index) ? -1 : ShownOrder().IndexOf(list.Columns[index]);

        private void ShowMenu(Point location)
        {
            ListViewHitTestInfo hit = list.HitTest(location);
            if (!(hit.Item?.Tag is Row row)) return;
            if (!hit.Item.Selected)
            {
                list.SelectedItems.Clear();
                hit.Item.Selected = true;
            }
            hit.Item.Focused = true;
            menuRow = row;
            int clicked = ColumnAt(hit.Item, location.X);
            if (!Equals(menu.Font, Font)) menu.Font = Font;
            CellMenu.Fill(copyValue, CellsOf(row), DisplayPosition(clicked));
            copyRows.Text = list.SelectedItems.Count == 1 ? "Copy Row" : $"Copy {list.SelectedItems.Count} Selected Rows";
            safetyReport.Enabled = row.Report != null;
            FillShowProcess(row.Processes);
            FillOpenLocation(row.Processes);
            menu.Show(list, location);
        }

        /// <summary>
        /// The row menu for a layer of the graph: its rows are selected, Show Process offers every process
        /// behind them, and the safety report is that of the busiest, since a site's addresses share one rating.
        /// </summary>
        private void ShowLayerMenu(string key, Point screen)
        {
            SelectRowsOf(key);
            List<Row> layerRows = rows.Values.Where(r => GraphKey(r) == key).OrderByDescending(r => r.Sent + r.Received).ToList();
            if (layerRows.Count == 0) return;
            menuRow = layerRows[0];
            if (!Equals(menu.Font, Font)) menu.Font = Font;
            CellMenu.Fill(copyValue, null, -1);
            copyRows.Text = layerRows.Count == 1 ? "Copy Row" : $"Copy {layerRows.Count} Selected Rows";
            safetyReport.Enabled = menuRow.Report != null;
            List<ProcInfo> processes = layerRows.SelectMany(r => r.Processes).Distinct().OrderBy(p => p.Pid).ToList();
            FillShowProcess(processes);
            FillOpenLocation(processes);
            menu.Show(screen);
        }

        // One process is shown with a click; several are offered as a submenu.
        private void FillShowProcess(List<ProcInfo> processes)
        {
            menuProcesses = processes;
            foreach (ToolStripItem old in showProcess.DropDownItems.Cast<ToolStripItem>().ToList()) old.Dispose();
            showProcess.DropDownItems.Clear();
            showProcess.Enabled = processes.Count > 0;
            if (processes.Count < 2) return;
            foreach (ProcInfo p in processes)
            {
                ProcInfo process = p;
                showProcess.DropDownItems.Add(new ToolStripMenuItem($"{p.DisplayName} ({p.Pid}){(p.Alive ? "" : "  ·  exited")}", null,
                    (s, e) => ProcessRequested?.Invoke(process)));
            }
            if (theme.IsDark) showProcess.DropDown.Renderer = menu.Renderer;
            showProcess.DropDown.ForeColor = menu.ForeColor;
        }

        // Likewise Open File Location: one program's folder with a click, several programs' as a submenu of their paths.
        private void FillOpenLocation(List<ProcInfo> processes)
        {
            List<string> paths = processes.Select(p => p.Path).Where(path => !string.IsNullOrEmpty(path))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            foreach (ToolStripItem old in openLocation.DropDownItems.Cast<ToolStripItem>().ToList()) old.Dispose();
            openLocation.DropDownItems.Clear();
            openLocation.Enabled = paths.Count > 0;
            openLocation.Tag = paths.Count == 1 ? paths[0] : null;
            if (paths.Count < 2) return;
            foreach (string path in paths)
                openLocation.DropDownItems.Add(new ToolStripMenuItem(path, null, (s, e) => OpenLocation(path)));
            if (theme.IsDark) openLocation.DropDown.Renderer = menu.Renderer;
            openLocation.DropDown.ForeColor = menu.ForeColor;
        }

        private void OpenLocation(string path)
        {
            if (path == null) return;
            string error = ProcessActions.OpenFileLocation(path);
            if (error != null) MessageBox.Show(FindForm(), error, "Process Streamgraph", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private void SetHotItem(ListViewItem item)
        {
            if (item == hotItem) return;
            foreach (ListViewItem row in new[] { hotItem, item })
                if (row != null && row.ListView == list)
                    list.Invalidate(new Rectangle(0, row.Bounds.Top, list.ClientSize.Width, row.Bounds.Height));
            hotItem = item;
        }

        /// <summary>
        /// Paints the header past its last column, which the list leaves in the system's colour, in the
        /// colour of the columns' own headers.
        /// </summary>
        internal sealed class HeaderFiller : NativeWindow
        {
            private const int LVM_GETHEADER = 0x101F, HDM_GETITEMCOUNT = 0x1200, HDM_GETITEMRECT = 0x1207, WM_PAINT = 0x000F, WM_RBUTTONUP = 0x0205;
            private Theme theme;

            /// <summary>Raised by a right-click on the header, with the pointer's screen position.</summary>
            public event Action<Point> RightClicked;

            public HeaderFiller(ListView list, Theme theme)
            {
                this.theme = theme;
                IntPtr header = NativeMethods.SendMessage(list.Handle, LVM_GETHEADER, IntPtr.Zero, IntPtr.Zero);
                if (header != IntPtr.Zero) AssignHandle(header);
            }

            public Theme Theme
            {
                set
                {
                    theme = value;
                    if (Handle != IntPtr.Zero) NativeMethods.InvalidateRect(Handle, IntPtr.Zero, true);
                }
            }

            protected override void WndProc(ref Message m)
            {
                base.WndProc(ref m);
                if (m.Msg == WM_RBUTTONUP && RightClicked != null)
                {
                    RightClicked(Control.MousePosition);
                    return;
                }
                if (m.Msg != WM_PAINT || Handle == IntPtr.Zero) return;
                int right = 0, count = (int)NativeMethods.SendMessage(Handle, HDM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
                for (int i = 0; i < count; i++)
                {
                    var item = new NativeMethods.RECT();
                    NativeMethods.SendMessage(Handle, HDM_GETITEMRECT, (IntPtr)i, ref item);
                    right = Math.Max(right, item.Right);
                }
                NativeMethods.GetClientRect(Handle, out NativeMethods.RECT client);
                if (right >= client.Right) return;
                using (Graphics g = Graphics.FromHwnd(Handle))
                using (var back = new SolidBrush(theme.Control))
                using (var pen = new Pen(theme.Border))
                {
                    g.FillRectangle(back, Rectangle.FromLTRB(right, 0, client.Right, client.Bottom));
                    g.DrawLine(pen, right, client.Bottom - 1, client.Right, client.Bottom - 1);
                }
            }
        }

        private void ShowSafetyReport(Row row)
        {
            if (row?.Report == null) return;
            var form = new SafetyReportForm(row.Report, safety, theme, (int)(scale * 96), Font);
            form.FormClosed += (s, e) => form.Dispose();
            form.Show(FindForm());
        }

        // Hovering a rating shows what each source said, as in the process table.
        private void ShowSafetyTip(Point? location)
        {
            string text = null;
            if (location.HasValue)
            {
                ListViewHitTestInfo hit = list.HitTest(location.Value);
                if (hit.Item?.Tag is Row row && ColumnAt(hit.Item, location.Value.X) == (int)Column.Safety)
                    text = SafetyTip(row.Report);
            }
            if (text == safetyTipText) return;
            safetyTipText = text;
            safetyTip.SetToolTip(list, text);
        }

        private static string SafetyTip(SafetyReport report)
        {
            if (report == null) return null;
            var text = new StringBuilder();
            text.Append(SafetyDrawing.BadgeText(report)).Append(": the most serious of these findings.");
            foreach (SourceResult r in report.Results)
            {
                text.AppendLine().Append("• ").Append(r.Source).Append(": ");
                if (r.Verdict != Safety.Unrated) text.Append(SafetyStyle.Title(r.Verdict)).Append(". ");
                text.Append(r.Summary);
            }
            if (report.Pending > 0) text.AppendLine().Append("Still asking some sources…");
            text.AppendLine().Append("Double-click for the full Safety Report with links.");
            return text.ToString();
        }

        private static void CopyText(string text)
        {
            if (!string.IsNullOrEmpty(text)) Clipboard.SetText(text);
        }

        private void CopyRows(bool selectedOnly)
        {
            var text = new StringBuilder();
            text.AppendLine(string.Join("\t", ShownOrder().Select(c => c.Text)));
            IEnumerable<ListViewItem> items = selectedOnly ? list.SelectedItems.Cast<ListViewItem>() : list.Items.Cast<ListViewItem>();
            foreach (ListViewItem item in items)
                text.AppendLine(CellMenu.RowText(CellsOf((Row)item.Tag)));
            CopyText(text.ToString());
        }

        private sealed class RowComparer : System.Collections.IComparer
        {
            private readonly ConnectionsView form;

            public RowComparer(ConnectionsView form)
            {
                this.form = form;
            }

            public int Compare(object x, object y)
            {
                var a = (Row)((ListViewItem)x).Tag;
                var b = (Row)((ListViewItem)y).Tag;
                int result;
                switch (form.sortColumn)
                {
                    case Column.Domain:
                        // Unnamed addresses after the named ones.
                        result = (a.Domain == "").CompareTo(b.Domain == "");
                        if (result == 0) result = string.Compare(a.Domain, b.Domain, StringComparison.CurrentCultureIgnoreCase);
                        break;
                    case Column.Address: result = CompareAddresses(a.Endpoint.Address, b.Endpoint.Address); break;
                    case Column.Safety: result = SafetyRank(a).CompareTo(SafetyRank(b)); break;
                    case Column.ProcessName: result = CompareText(a.ProcessName, b.ProcessName); break;
                    case Column.FileName: result = CompareText(a.FileName, b.FileName); break;
                    case Column.Pid: result = a.Pids.Min().CompareTo(b.Pids.Min()); break;
                    case Column.Scope: result = string.CompareOrdinal(a.Scope, b.Scope); break;
                    case Column.Location: result = CompareText(a.Location, b.Location); break;
                    case Column.Owner: result = CompareText(a.Owner, b.Owner); break;
                    case Column.Protocol: result = string.CompareOrdinal(a.Protocol, b.Protocol); break;
                    case Column.Port: result = a.Endpoint.Port.CompareTo(b.Endpoint.Port); break;
                    case Column.Use: result = CompareText(a.Use, b.Use); break;
                    case Column.Sent: result = a.Sent.CompareTo(b.Sent); break;
                    case Column.Received: result = a.Received.CompareTo(b.Received); break;
                    case Column.LastActive: result = form.traced ? a.LastActive.CompareTo(b.LastActive) : string.CompareOrdinal(a.When, b.When); break;
                    default: result = (a.Sent + a.Received).CompareTo(b.Sent + b.Received); break;
                }
                if (form.sortDescending) result = -result;
                // Ties keep a steady order between updates.
                return result != 0 ? result : CompareAddresses(a.Endpoint.Address, b.Endpoint.Address) * 2 + a.Endpoint.Port.CompareTo(b.Endpoint.Port);
            }

            // Blank and still-unknown values after the known ones.
            private static int CompareText(string a, string b)
            {
                bool aBlank = a == "" || a == "…", bBlank = b == "" || b == "…";
                return aBlank != bBlank ? aBlank.CompareTo(bBlank) : string.Compare(a, b, StringComparison.CurrentCultureIgnoreCase);
            }

            // Local addresses, which are not rated, below even the unrated hosts.
            private static int SafetyRank(Row row) => row.Report == null ? -2 : (int)row.Report.Overall;

            private static int CompareAddresses(IpAddr a, IpAddr b)
            {
                if (a.V6 != b.V6) return a.V6 ? 1 : -1;
                // The stored bytes are in network order; compare them as written, most significant first.
                byte[] x = a.ToIPAddress().GetAddressBytes(), y = b.ToIPAddress().GetAddressBytes();
                for (int i = 0; i < x.Length; i++)
                    if (x[i] != y[i]) return x[i].CompareTo(y[i]);
                return 0;
            }
        }
    }
}
