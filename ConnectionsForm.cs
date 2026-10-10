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
    /// The remote hosts a process has exchanged data with, and how much went each way, since this
    /// program started watching; updated every second while open. Without the rights to trace
    /// traffic it lists the process's open TCP connections instead. Each host is rated for safety.
    /// </summary>
    internal sealed class ConnectionsForm : Form
    {
        private enum Column { Domain, Address, Safety, Protocol, Port, Sent, Received, Total, LastActive }

        private static readonly int ColumnCount = Enum.GetValues(typeof(Column)).Length;

        /// <summary>One remote endpoint as shown: traffic summed over the process and, if chosen, its helpers.</summary>
        private sealed class Row
        {
            public Endpoint Endpoint;
            public string Domain = "", Address = "", Protocol = "", Port = "", When = "";
            public bool DomainGuessed;      // from a reverse lookup rather than the process's own lookup
            public bool Local;              // this computer, the local network or multicast: nothing to rate
            public long Sent, Received;
            public DateTime LastActive;
            public SafetyReport Report;     // null for local addresses
            public ListViewItem Item;
        }

        private readonly ProcInfo process;
        private readonly ProcessMonitor monitor;
        private readonly SafetyService safety;
        private readonly Theme theme;
        private readonly float scale;
        private readonly bool traced;
        private readonly ListView list;
        private readonly Label subtitle, note, summary;
        private readonly CheckBox includeHelpers;
        private readonly Timer timer;
        private readonly ContextMenuStrip menu;
        private readonly ToolStripMenuItem copyValue, copyRows, copyAll, safetyReport;
        private HeaderFiller headerFiller;
        private ListViewItem hotItem;   // row under the mouse
        private readonly ToolTip safetyTip = new ToolTip { AutoPopDelay = 30000, InitialDelay = 400, ReshowDelay = 100 };
        private string safetyTipText;
        private readonly Dictionary<Endpoint, Row> rows = new Dictionary<Endpoint, Row>();
        private Column sortColumn = Column.Total;
        private bool sortDescending = true;
        private Row menuRow;
        private int badgeWidth;

        /// <param name="font">The main window's font, so that text here is the same size.</param>
        public ConnectionsForm(ProcInfo process, ProcessMonitor monitor, SafetyService safety, Theme theme, int dpi, Font font, Action restartElevated)
        {
            this.process = process;
            this.monitor = monitor;
            this.safety = safety;
            this.theme = theme;
            scale = dpi / 96f;
            traced = monitor.NetworkAvailable;

            Text = process.DisplayName + ": Connections";
            Icon = ProgramIcon(process.Path);
            Font = font;
            AutoScaleMode = AutoScaleMode.None;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(S(1100), S(560));
            MinimumSize = new Size(S(560), S(300));

            subtitle = new Label { AutoSize = true, Anchor = AnchorStyles.Left, ForeColor = theme.MutedInk, Margin = new Padding(0, S(4), S(16), 0) };
            includeHelpers = new CheckBox { AutoSize = true, Checked = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, S(3), 0, 0), Visible = false };
            includeHelpers.CheckedChanged += (s, e) => Refill();
            var top = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Top, Padding = new Padding(S(14), S(12), S(14), 0) };
            top.Controls.AddRange(new Control[] { subtitle, includeHelpers });

            note = new Label { AutoSize = true, Dock = DockStyle.Top, Padding = new Padding(S(14), S(6), S(14), S(8)) };
            note.Text = (traced
                ? "Data sent and received since Process Streamgraph started, by remote host. Domains are the names the program " +
                  "looked up; grey ones come from a reverse lookup of the address instead, and may name a hosting or CDN company " +
                  "rather than the site. Browsers using Secure DNS do not show their lookups to Windows."
                : "Showing open TCP connections only. Amounts sent and received, and UDP traffic (which includes most browser " +
                  "traffic over QUIC), need Process Streamgraph to run as administrator." +
                  (monitor.Network.NamesAvailable ? "" : " Domains come from reverse lookups, and may name a hosting company rather than the site.")) +
                " Safety is the most serious finding of the sources under Safety Sources; hover over it for details.";

            list = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                HideSelection = false,
                BorderStyle = BorderStyle.None,
                OwnerDraw = true,
                AllowColumnReorder = true,
                BackColor = theme.Window,
                ForeColor = theme.WindowText,
                ListViewItemSorter = new RowComparer(this)
            };
            // Updated every second; without double buffering each update flickers.
            typeof(Control).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                ?.SetValue(list, true);
            AddColumn("Domain", 250, HorizontalAlignment.Left);
            AddColumn("Address", 200, HorizontalAlignment.Left);
            AddColumn("Safety", 100, HorizontalAlignment.Left);
            AddColumn("Protocol", 70, HorizontalAlignment.Left);
            AddColumn("Port", 130, HorizontalAlignment.Left);
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
            list.HandleCreated += (s, e) =>
            {
                NativeMethods.SetWindowTheme(list.Handle, theme.IsDark ? "DarkMode_Explorer" : null, null);
                headerFiller = new HeaderFiller(list, theme);
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
            if (theme.IsDark) menu.Renderer = new ThemedMenuRenderer(theme);
            menu.ForeColor = theme.ControlText;
            copyValue = new ToolStripMenuItem("Copy Value");
            copyValue.Click += (s, e) => CopyText(copyValue.Tag as string);
            copyRows = new ToolStripMenuItem("Copy Selected Rows", null, (s, e) => CopyRows(true));
            copyAll = new ToolStripMenuItem("Copy All Rows", null, (s, e) => CopyRows(false));
            safetyReport = new ToolStripMenuItem("Safety Report…", null, (s, e) => ShowSafetyReport(menuRow));
            menu.Items.AddRange(new ToolStripItem[] { copyValue, copyRows, copyAll, new ToolStripSeparator(), safetyReport });

            summary = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(S(4), S(8), S(12), 0) };
            var copy = new Button { Text = "Copy", AutoSize = true, Padding = new Padding(S(6), S(2), S(6), S(2)) };
            copy.Click += (s, e) => CopyRows(list.SelectedItems.Count > 0);
            var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel, Padding = new Padding(S(6), S(2), S(6), S(2)) };
            close.Click += (s, e) => Close();
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(S(10), S(6), S(10), S(10)) };
            buttons.Controls.Add(close);
            buttons.Controls.Add(copy);
            if (!traced && monitor.NetworkAccessDenied && restartElevated != null)
            {
                var elevate = new Button { Text = "Restart as Administrator", AutoSize = true, Padding = new Padding(S(6), S(2), S(6), S(2)) };
                elevate.Click += (s, e) => restartElevated();
                buttons.Controls.Add(elevate);
            }
            buttons.Controls.Add(summary);
            CancelButton = close;

            var listFrame = new Panel { Dock = DockStyle.Fill, Padding = new Padding(S(14), 0, S(14), 0) };
            listFrame.Controls.Add(list);
            Controls.Add(listFrame);
            Controls.Add(note);
            Controls.Add(top);
            Controls.Add(buttons);
            SafetyDrawing.Style(this, theme);
            subtitle.ForeColor = theme.MutedInk;
            list.BackColor = theme.Window;
            list.ForeColor = theme.WindowText;
            Resize += (s, e) => note.MaximumSize = new Size(Math.Max(S(200), ClientSize.Width - note.Padding.Horizontal), 0);

            Favicons.Loaded += OnFaviconLoaded;

            timer = new Timer { Interval = 1000 };
            timer.Tick += (s, e) => Refill();
            Refill();
            timer.Start();
        }

        private int S(int pixels) => (int)(pixels * scale);

        /// <summary>The program's own icon, or Process Streamgraph's when it has none to give.</summary>
        private static Icon ProgramIcon(string path)
        {
            try
            {
                if (!string.IsNullOrEmpty(path) && System.IO.File.Exists(path)) return Icon.ExtractAssociatedIcon(path);
            }
            catch (Exception e) when (e is ArgumentException || e is System.IO.IOException || e is UnauthorizedAccessException)
            {
            }
            using (var stream = typeof(ConnectionsForm).Assembly.GetManifestResourceStream("ProcessStreamgraph.app.ico"))
                return stream != null ? new Icon(stream) : null;
        }

        private void AddColumn(string title, int width, HorizontalAlignment align) =>
            list.Columns.Add(new ColumnHeader { Text = title, Width = S(width), TextAlign = align });

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            NativeMethods.SetDarkTitleBar(Handle, theme.IsDark);
        }

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

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            Favicons.Loaded -= OnFaviconLoaded;
            Icon?.Dispose();
            timer.Dispose();
            menu.Dispose();
            safetyTip.Dispose();
            base.OnFormClosed(e);
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

        /// <summary>The process, and its helpers when included: processes below it running the same program.</summary>
        private List<ProcInfo> Members(out int helpers)
        {
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
            subtitle.Text = process.Name + "  ·  PID " + process.Pid + (process.Alive ? "" : "  ·  exited");
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
                }
                if (row.Report == null && !row.Local)
                {
                    // Only a name the program looked up itself is worth checking; a reverse lookup's names the host's owner.
                    string domain = row.DomainGuessed || row.Domain == "" ? null : row.Domain;
                    row.Report = safety.ReportForHost(domain, row.Endpoint.Address.ToIPAddress());
                }
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

        private Row Gather(Dictionary<Endpoint, Row> current, Endpoint endpoint, int pid)
        {
            if (current.TryGetValue(endpoint, out Row row))
            {
                if (row.Domain == "" || row.DomainGuessed) ApplyLookedUpName(row, pid);
                return row;
            }
            System.Net.IPAddress address = endpoint.Address.ToIPAddress();
            row = new Row
            {
                Endpoint = endpoint,
                Address = address.ToString(),
                Protocol = endpoint.Udp ? "UDP" : "TCP",
            };
            string service = ConnectionInfo.PortName(endpoint.Port, endpoint.Udp);
            row.Port = endpoint.Port.ToString(CultureInfo.InvariantCulture) + (service != null ? "  ·  " + service : "");
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
            Set(item, Column.Address, row.Address);
            // The badge is drawn, not written; the text here only makes the cell repaint when the rating changes.
            Set(item, Column.Safety, row.Report == null ? "" : SafetyDrawing.BadgeText(row.Report));
            Set(item, Column.Protocol, row.Protocol);
            Set(item, Column.Port, row.Port);
            Set(item, Column.Sent, traced ? Bytes(row.Sent) : "—");
            Set(item, Column.Received, traced ? Bytes(row.Received) : "—");
            Set(item, Column.Total, traced ? Bytes(row.Sent + row.Received) : "—");
            Set(item, Column.LastActive, row.When);
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

        private List<ColumnHeader> ShownOrder() => list.Columns.Cast<ColumnHeader>().OrderBy(c => c.DisplayIndex).ToList();

        // Where a column, by its index, now sits among the shown ones; -1 for none.
        private int DisplayPosition(int index) => index < 0 || index >= list.Columns.Count ? -1 : list.Columns[index].DisplayIndex;

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
            menu.Show(list, location);
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
        private sealed class HeaderFiller : NativeWindow
        {
            private const int LVM_GETHEADER = 0x101F, HDM_GETITEMCOUNT = 0x1200, HDM_GETITEMRECT = 0x1207, WM_PAINT = 0x000F;
            private readonly Theme theme;

            public HeaderFiller(ListView list, Theme theme)
            {
                this.theme = theme;
                IntPtr header = NativeMethods.SendMessage(list.Handle, LVM_GETHEADER, IntPtr.Zero, IntPtr.Zero);
                if (header != IntPtr.Zero) AssignHandle(header);
            }

            protected override void WndProc(ref Message m)
            {
                base.WndProc(ref m);
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
            form.Show(this);
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
            private readonly ConnectionsForm form;

            public RowComparer(ConnectionsForm form)
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
                    case Column.Protocol: result = string.CompareOrdinal(a.Protocol, b.Protocol); break;
                    case Column.Port: result = a.Endpoint.Port.CompareTo(b.Endpoint.Port); break;
                    case Column.Sent: result = a.Sent.CompareTo(b.Sent); break;
                    case Column.Received: result = a.Received.CompareTo(b.Received); break;
                    case Column.LastActive: result = form.traced ? a.LastActive.CompareTo(b.LastActive) : string.CompareOrdinal(a.When, b.When); break;
                    default: result = (a.Sent + a.Received).CompareTo(b.Sent + b.Received); break;
                }
                if (form.sortDescending) result = -result;
                // Ties keep a steady order between updates.
                return result != 0 ? result : CompareAddresses(a.Endpoint.Address, b.Endpoint.Address) * 2 + a.Endpoint.Port.CompareTo(b.Endpoint.Port);
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
