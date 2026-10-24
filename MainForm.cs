using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ProcessStreamgraph
{
    internal sealed class MainForm : Form, IMessageFilter
    {
        private readonly ProcessMonitor monitor = new ProcessMonitor();
        private readonly IconCache icons = new IconCache();
        private readonly ProcessTreePanel treePanel;
        private readonly ProcessTree tree;
        private readonly StreamGraphControl[] streamGraphs;
        private readonly TableLayoutPanel graphs;
        private readonly Panel graphScroll;    // scrolls the graphs when they do not all fit at their minimum height
        private readonly Panel graphFiller;
        private readonly SplitContainer split;
        private readonly TabStrip tabs;
        private readonly Panel processesPage, connectionsPage;
        private ConnectionsView connectionsView;    // made when its tab is first shown
        private readonly Timer timer;
        private readonly Timer animation;      // pans the graphs between samples
        private Control toolbar;
        private ComboBox[] dropdowns;
        private ComboBox layerSort, systemBand;     // in the Processes tab's bar above the graphs
        private NumericUpDown refreshSeconds;
        private Button safetySources, fileInUse;
        private FileInUseForm fileInUseForm;
        // Lengths of the time axis, in seconds, that the time span slider steps through.
        internal static readonly int[] TimeSpans = { 10, 15, 20, 30, 45, 60, 90, 120, 180, 240, ProcessMonitor.HistorySeconds };
        private Control timeBar;
        private TrackBar timeSpan;
        private const int MinGraphHeight = 200;     // an open graph's least automatic height, in 96-DPI units
        private const int MinDraggedHeight = 100;   // the least height an open graph can be dragged to, likewise
        private int[] graphHeights;                 // heights the graphs were dragged to, in 96-DPI units; null for automatic
        private readonly ProcessMenu processMenu;
        private readonly SafetyService safety;
        private Theme theme;
        private bool followSystemTheme = true;     // the System default choice: light or dark as Windows is set
        private bool graphsStale;  // samples were taken while minimized and not yet drawn
        private bool arranging;     // true while nodes are being reordered, when selection events are noise

        public MainForm()
        {
            Text = "Process Streamgraph";
            using (var stream = typeof(MainForm).Assembly.GetManifestResourceStream("ProcessStreamgraph.app.ico"))
                if (stream != null) Icon = new Icon(stream);
            Font = SystemFonts.MessageBoxFont;
            // Created here rather than with the fields: by now the form exists, so the UI thread's
            // synchronization context is installed for the service to post its results back through.
            safety = new SafetyService();
            // Sizes below are in 96-DPI units; OnLoad scales them for the monitor the window opens on.
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(1880, 900);
            StartPosition = FormStartPosition.CenterScreen;

            treePanel = new ProcessTreePanel { Dock = DockStyle.Fill };
            tree = treePanel.Tree;
            tree.ImageList = icons.SmallImages;
            tree.AfterSelect += (s, e) => { if (!arranging) SetSelected(e.Node?.Tag as ProcInfo); };
            tree.SortChanged += ArrangeTree;
            tree.NetworkAvailable = monitor.NetworkAvailable;
            tree.ColumnsChanged += delta =>
            {
                // The tree pane grows or shrinks with its columns, so the name column keeps its room.
                int target = split.SplitterDistance + delta * DeviceDpi / 96;
                split.SplitterDistance = Math.Max(split.Panel1MinSize, Math.Min(target, MaxTreePane));
            };
            processMenu = new ProcessMenu(monitor, this, tree);
            processMenu.SafetyReportRequested += ShowSafetyReport;
            processMenu.ConnectionsRequested += ShowConnections;
            processMenu.ServicePropertiesRequested += ShowServiceProperties;
            // Safety results arrive in bursts; one pass over the visible rows covers each burst.
            safety.Updated += tree.QueueRefreshChangedCells;
            tree.MouseUp += (s, e) =>
            {
                if (e.Button != MouseButtons.Right || !(tree.GetNodeAt(e.Location) is TreeNode node)) return;
                tree.SelectedNode = node;
                var process = (ProcInfo)node.Tag;
                processMenu.Show(process, tree.PointToScreen(e.Location), tree.CellsOf(process), tree.ShownIndexAt(e.X));
            };
            tree.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Delete && e.Modifiers == Keys.None && tree.SelectedNode?.Tag is ProcInfo selected)
                {
                    processMenu.ConfirmEndTask(selected);
                    e.Handled = true;
                    return;
                }
                // The keyboard's menu key, and its Shift+F10 equivalent, open the menu for the selected row.
                bool menuKey = e.KeyCode == Keys.Apps || (e.KeyCode == Keys.F10 && e.Shift);
                if (!menuKey || tree.SelectedNode == null) return;
                Rectangle row = tree.SelectedNode.Bounds;
                var process = (ProcInfo)tree.SelectedNode.Tag;
                processMenu.Show(process, tree.PointToScreen(new Point(row.Left, row.Bottom)), tree.CellsOf(process), -1);
                e.Handled = true;
            };

            // The panel's own colour shows as the one-pixel rules between the graphs.
            graphs = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1 };
            graphs.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            var metrics = new[] { Metric.Cpu, Metric.Memory, Metric.Gpu, Metric.GpuMemory, Metric.Network };
            streamGraphs = new StreamGraphControl[metrics.Length];
            for (int i = 0; i < metrics.Length; i++)
            {
                var graph = new StreamGraphControl(monitor, icons, metrics[i])
                {
                    Dock = DockStyle.Fill,
                    Margin = new Padding(0, i == 0 ? 0 : 1, 0, 0)
                };
                graph.ProcessClicked += SelectInTree;
                graph.ProcessMenuRequested += (process, location) => processMenu.Show(process, location, tree.CellsOf(process), -1);
                graph.ElevationRequested += RestartElevated;
                graph.CollapsedChanged += LayoutGraphs;
                int index = i;
                graph.HeightDragged += height => ResizeGraph(index, height);
                graph.HeightResetRequested += () =>
                {
                    graphHeights = null;
                    LayoutGraphs();
                };
                streamGraphs[i] = graph;
                graphs.RowStyles.Add(new RowStyle());
                graphs.Controls.Add(graph, 0, i);
            }
            // Takes up the space below the headings when every graph is collapsed.
            graphFiller = new Panel { Dock = DockStyle.Fill, Margin = new Padding(0, 1, 0, 0) };
            graphs.RowStyles.Add(new RowStyle());
            graphs.Controls.Add(graphFiller, 0, metrics.Length);
            // The graphs fill the scrolling panel's display area, which grows past the visible part
            // when the open graphs need more room than there is.
            graphScroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
            graphScroll.Controls.Add(graphs);
            graphScroll.HandleCreated += (s, e) => ThemeScrollBar();
            LayoutGraphs();
            FontChanged += (s, e) => LayoutGraphs();
            DpiChanged += (s, e) => LayoutGraphs();

            split = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
            split.Panel1.Controls.Add(treePanel);
            split.Panel2.Controls.Add(graphScroll);
            split.Panel2.Controls.Add(timeBar = BuildTimeBar());

            // Below the toolbar, a tab for the processes and their graphs, and one for a process's connections.
            processesPage = new Panel { Dock = DockStyle.Fill };
            processesPage.Controls.Add(split);
            connectionsPage = new Panel { Dock = DockStyle.Fill, Visible = false };
            tabs = new TabStrip("Processes", "Connections");
            tabs.SelectedChanged += ShowTab;
            Controls.Add(processesPage);
            Controls.Add(connectionsPage);
            Controls.Add(tabs);
            Controls.Add(toolbar = BuildToolbar());
            split.SplitterDistance = TreeWidth;
            ApplyTheme(Theme.SystemDefault);

            timer = new Timer { Interval = 1000 };
            timer.Tick += (s, e) => TakeSample();
            // About the display's refresh rate; the graphs only repaint when they have moved a pixel.
            animation = new Timer { Interval = 15 };
            animation.Tick += (s, e) =>
            {
                if (WindowState == FormWindowState.Minimized) return;
                foreach (StreamGraphControl graph in streamGraphs) graph.Animate();
            };
            Application.AddMessageFilter(this);
        }

        /// <summary>
        /// Mouse wheel anywhere over the graphs scrolls them. Done as a message filter because wheel
        /// messages otherwise go to whichever control has the focus, normally the tree.
        /// </summary>
        public bool PreFilterMessage(ref Message m)
        {
            if (m.Msg != NativeMethods.WM_MOUSEWHEEL) return false;
            long position = m.LParam.ToInt64();
            var point = new Point((short)(position & 0xFFFF), (short)((position >> 16) & 0xFFFF));
            Control under = FromHandle(NativeMethods.WindowFromPoint(point));
            if (!(under is StreamGraphControl) && under != graphFiller && under != graphScroll && under != graphs) return false;
            if (!graphScroll.VerticalScroll.Visible) return true;
            int delta = (short)((m.WParam.ToInt64() >> 16) & 0xFFFF);
            // The system setting is lines per notch, or -1 for a page at a time.
            int lines = SystemInformation.MouseWheelScrollLines;
            int pixels = lines > 0 ? delta * lines * Font.Height / 120 : delta * graphScroll.ClientSize.Height / 120;
            graphScroll.AutoScrollPosition = new Point(0, -graphScroll.AutoScrollPosition.Y - pixels);
            return true;
        }

        // Default width of the tree pane, in 96-DPI units: the shown columns plus the scroll bar.
        private int TreeWidth => tree.ShownColumnsWidth + 24;

        // The tree pane never takes more than this, so the graphs keep a usable width.
        private int MaxTreePane => split.Width * 3 / 5;

        /// <summary>
        /// Collapsed graphs get just their heading line. Open ones share the rest equally, but never
        /// shrink below a minimum height, until one is dragged to a height of its own: from then on each
        /// keeps the height it has, and any room left over stays empty below them. When the graphs need
        /// more room than there is, the panel scrolls.
        /// </summary>
        private void LayoutGraphs()
        {
            int open = 0, needed = 0;
            for (int i = 0; i < streamGraphs.Length; i++)
            {
                StreamGraphControl graph = streamGraphs[i];
                if (!graph.Collapsed) open++;
                int height = graph.Collapsed ? graph.HeadingHeight : (graphHeights?[i] ?? MinGraphHeight) * DeviceDpi / 96;
                needed += height + graph.Margin.Vertical;
            }
            graphScroll.AutoScrollMinSize = new Size(0, needed);

            graphs.SuspendLayout();
            for (int i = 0; i < streamGraphs.Length; i++)
            {
                StreamGraphControl graph = streamGraphs[i];
                graphs.RowStyles[i] = graph.Collapsed ? new RowStyle(SizeType.Absolute, graph.HeadingHeight + graph.Margin.Vertical)
                    : graphHeights != null ? new RowStyle(SizeType.Absolute, graphHeights[i] * DeviceDpi / 96 + graph.Margin.Vertical)
                    : new RowStyle(SizeType.Percent, 100f / open);
            }
            bool fill = open == 0 || graphHeights != null;
            graphs.RowStyles[streamGraphs.Length] = fill ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.Absolute, 0);
            graphFiller.Visible = fill;
            graphs.ResumeLayout();
        }

        /// <summary>
        /// Gives a graph the height its bottom edge is dragged to. The first drag fixes every graph at the
        /// height it has, so only the one dragged changes.
        /// </summary>
        private void ResizeGraph(int index, int pixels)
        {
            if (graphHeights == null)
            {
                graphHeights = new int[streamGraphs.Length];
                for (int i = 0; i < streamGraphs.Length; i++)
                    graphHeights[i] = streamGraphs[i].Collapsed ? MinGraphHeight : streamGraphs[i].Height * 96 / DeviceDpi;
            }
            int height = Math.Max(MinDraggedHeight, pixels * 96 / DeviceDpi);
            if (height == graphHeights[index]) return;
            graphHeights[index] = height;
            LayoutGraphs();
        }

        private void RestartElevated()
        {
            try
            {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath) { UseShellExecute = true, Verb = "runas" });
            }
            catch (Win32Exception)
            {
                return;     // the elevation prompt was declined
            }
            Close();
        }

        protected override void OnLoad(EventArgs e)
        {
            // The layout above is in 96-DPI units, while WinForms starts out assuming the system DPI.
            if (DeviceDpi != 96)
            {
                float factor = DeviceDpi / 96f;
                Scale(new SizeF(factor, factor));
            }

            // When the window opens on a monitor whose scale differs from the system DPI, WinForms
            // keeps the system value and nothing tells it otherwise. Replaying the DPI-changed
            // message Windows would send on a monitor move lets it rescale fonts and layout itself.
            int actualDpi = NativeMethods.GetDpiForWindow(Handle);
            float toActual = actualDpi / (float)DeviceDpi;
            Rectangle area = Screen.FromHandle(Handle).WorkingArea;
            int width = Math.Min((int)(Width * toActual), area.Width), height = Math.Min((int)(Height * toActual), area.Height);
            var bounds = new Rectangle(area.X + (area.Width - width) / 2, area.Y + (area.Height - height) / 2, width, height);
            if (actualDpi != DeviceDpi)
            {
                var rect = new NativeMethods.RECT { Left = bounds.Left, Top = bounds.Top, Right = bounds.Right, Bottom = bounds.Bottom };
                NativeMethods.SendMessage(Handle, NativeMethods.WM_DPICHANGED, (IntPtr)((actualDpi << 16) | actualDpi), ref rect);
            }
            else
            {
                Bounds = bounds;
            }
            // The rescaling above does not reliably carry the splitter along, so place it explicitly.
            split.SplitterDistance = Math.Min(TreeWidth * actualDpi / 96, MaxTreePane);
            icons.SetSmallSize(16 * actualDpi / 96);
            LayoutGraphs();
            NativeMethods.SetDarkTitleBar(Handle, streamGraphs[0].Theme.IsDark);
            base.OnLoad(e);

            TakeSample();
            timer.Start();
            animation.Start();
        }

        /// <summary>The bar above the graphs with the slider that sets how much history they show.</summary>
        private Control BuildTimeBar()
        {
            var bar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = false,
                Padding = new Padding(8, 2, 6, 2)
            };
            timeSpan = new TrackBar
            {
                Minimum = 0,
                Maximum = TimeSpans.Length - 1,
                Value = Array.IndexOf(TimeSpans, 30),
                LargeChange = 1,
                TickStyle = TickStyle.None,
                AutoSize = false,
                Width = 120,
                Height = 26,
                Anchor = AnchorStyles.Left
            };
            var shown = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Text = SpanText(TimeSpans[timeSpan.Value]) };
            foreach (StreamGraphControl graph in streamGraphs) graph.VisibleSeconds = TimeSpans[timeSpan.Value];
            timeSpan.ValueChanged += (s, e) =>
            {
                int seconds = TimeSpans[timeSpan.Value];
                shown.Text = SpanText(seconds);
                foreach (StreamGraphControl graph in streamGraphs) graph.VisibleSeconds = seconds;
            };
            bar.Controls.Add(new Label { Text = "Time span:", AutoSize = true, Anchor = AnchorStyles.Left });
            bar.Controls.Add(timeSpan);
            bar.Controls.Add(shown);

            // How the layers are stacked, which only this tab's graphs need.
            layerSort = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 130, Anchor = AnchorStyles.Left };
            layerSort.Items.AddRange(new object[] { "Usage", "Start time", "Name", "Process ID" });
            layerSort.SelectedIndex = 0;
            layerSort.SelectedIndexChanged += (s, e) =>
            {
                foreach (StreamGraphControl graph in streamGraphs) graph.SortMode = (SortMode)layerSort.SelectedIndex;
            };

            var reverse = new CheckBox { Text = "Reverse", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(6, 3, 18, 3) };
            reverse.CheckedChanged += (s, e) =>
            {
                foreach (StreamGraphControl graph in streamGraphs) graph.Reverse = reverse.Checked;
            };

            systemBand = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 90, Anchor = AnchorStyles.Left };
            systemBand.Items.AddRange(new object[] { "On top", "At bottom" });
            systemBand.SelectedIndex = 0;
            systemBand.SelectedIndexChanged += (s, e) =>
            {
                foreach (StreamGraphControl graph in streamGraphs) graph.SystemBandAtBottom = systemBand.SelectedIndex == 1;
            };

            bar.Controls.Add(new Label { Text = "Sort layers by:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(21, 0, 3, 0) });
            bar.Controls.Add(layerSort);
            bar.Controls.Add(reverse);
            bar.Controls.Add(new Label { Text = "System band:", AutoSize = true, Anchor = AnchorStyles.Left });
            bar.Controls.Add(systemBand);
            return bar;
        }

        internal static string SpanText(int seconds) =>
            seconds < 60 ? seconds + " s" : seconds % 60 == 0 ? seconds / 60 + " min" : (seconds / 60.0).ToString("0.#") + " min";

        private Control BuildToolbar()
        {
            var bar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = false,
                Padding = new Padding(6, 4, 6, 4)
            };

            var themes = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
            themes.Items.Add("System default");
            foreach (Theme theme in Theme.All) themes.Items.Add(theme.Name);
            themes.SelectedIndex = 0;
            themes.SelectedIndexChanged += (s, e) =>
            {
                followSystemTheme = themes.SelectedIndex == 0;
                ApplyTheme(followSystemTheme ? Theme.SystemDefault : Theme.All[themes.SelectedIndex - 1]);
            };
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;

            bar.Controls.Add(new Label { Text = "Theme:", AutoSize = true, Anchor = AnchorStyles.Left });
            bar.Controls.Add(themes);

            refreshSeconds = new NumericUpDown
            {
                Minimum = (decimal)ProcessMonitor.MinIntervalSeconds,
                Maximum = 60,
                Increment = 0.5m,
                DecimalPlaces = 1,
                Value = 1,
                Width = 56,
                TextAlign = HorizontalAlignment.Right,
                Margin = new Padding(3, 3, 0, 3)
            };
            refreshSeconds.ValueChanged += (s, e) =>
            {
                timer.Interval = (int)(refreshSeconds.Value * 1000);
                foreach (StreamGraphControl graph in streamGraphs) graph.RefreshSeconds = (double)refreshSeconds.Value;
            };
            bar.Controls.Add(new Label { Text = "Refresh every:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(21, 0, 3, 0) });
            bar.Controls.Add(refreshSeconds);
            bar.Controls.Add(new Label { Text = "seconds", AutoSize = true, Anchor = AnchorStyles.Left });

            safetySources = new Button
            {
                Text = "Safety Sources…",
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Anchor = AnchorStyles.Left,
                Padding = new Padding(6, 0, 6, 0),
                Margin = new Padding(21, 0, 3, 0)
            };
            safetySources.Click += (s, e) => ShowSafetySources();
            bar.Controls.Add(safetySources);

            fileInUse = new Button
            {
                Text = "File in Use…",
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Anchor = AnchorStyles.Left,
                Padding = new Padding(6, 0, 6, 0),
                Margin = new Padding(6, 0, 3, 0)
            };
            fileInUse.Click += (s, e) => ShowFileInUse();
            bar.Controls.Add(fileInUse);
            dropdowns = new[] { layerSort, systemBand, themes };
            return bar;
        }

        private void ApplyTheme(Theme theme)
        {
            this.theme = theme;
            BackColor = theme.Control;
            ForeColor = theme.ControlText;
            toolbar.BackColor = theme.Control;
            toolbar.ForeColor = theme.ControlText;
            foreach (ComboBox dropdown in dropdowns)
            {
                // The standard combo box ignores colours, so the dark theme uses the flat one.
                dropdown.FlatStyle = theme.IsDark ? FlatStyle.Flat : FlatStyle.Standard;
                dropdown.BackColor = theme.IsDark ? theme.InactiveSelection : theme.Window;
                dropdown.ForeColor = theme.WindowText;
            }
            refreshSeconds.BackColor = theme.IsDark ? theme.InactiveSelection : theme.Window;
            refreshSeconds.ForeColor = theme.WindowText;
            foreach (Button button in new[] { safetySources, fileInUse })
            {
                button.FlatStyle = theme.IsDark ? FlatStyle.Flat : FlatStyle.Standard;
                button.BackColor = theme.IsDark ? theme.InactiveSelection : SystemColors.Control;
                button.ForeColor = theme.ControlText;
                if (theme.IsDark) button.FlatAppearance.BorderColor = theme.Border;
            }
            split.BackColor = theme.Control;
            tabs.Theme = theme;
            processesPage.BackColor = connectionsPage.BackColor = theme.Control;
            connectionsView?.ApplyTheme(theme);
            graphs.BackColor = theme.Border;
            graphFiller.BackColor = theme.Surface;
            graphScroll.BackColor = theme.Surface;
            timeBar.BackColor = timeSpan.BackColor = theme.Control;
            timeBar.ForeColor = theme.ControlText;
            if (graphScroll.IsHandleCreated) ThemeScrollBar();
            treePanel.ApplyTheme(theme);
            foreach (StreamGraphControl graph in streamGraphs) graph.Theme = theme;
            processMenu.Theme = theme;
            if (IsHandleCreated) NativeMethods.SetDarkTitleBar(Handle, theme.IsDark);
        }

        // The stock scroll bar has a dark variant only through the Explorer theme.
        private void ThemeScrollBar() =>
            NativeMethods.SetWindowTheme(graphScroll.Handle, theme.IsDark ? "DarkMode_Explorer" : null, null);

        private void TakeSample()
        {
            monitor.Sample();
            // While minimized nothing is drawn: the history keeps filling, and the tree keeps track of
            // which processes exist, but the graphs wait to be rebuilt until the window is back.
            if (WindowState == FormWindowState.Minimized)
            {
                SyncTree();
                graphsStale = true;
                return;
            }
            ProcessActions.UpdateWindowStates(monitor.Processes);
            ServiceDirectory.Update(monitor);
            WorkingFolders.Update(monitor);
            RendererPages.Update(monitor);
            SyncTree();
            foreach (StreamGraphControl graph in streamGraphs) graph.Rebuild();
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            if (graphsStale && WindowState != FormWindowState.Minimized)
            {
                graphsStale = false;
                ProcessActions.UpdateWindowStates(monitor.Processes);
                foreach (StreamGraphControl graph in streamGraphs) graph.Rebuild();
                tree.Invalidate();
            }
        }

        private void SyncTree()
        {
            // Adding, expanding and reselecting rows all make the control scroll by itself, so note
            // which row is at the top and put it back there afterwards.
            TreeNode top = tree.TopNode;

            List<ProcInfo> added = monitor.Added, removed = monitor.Removed;
            if (added.Count > 0 || removed.Count > 0)
            {
                // Suspending redraw only pays for itself on big batches, such as the first sample:
                // re-enabling it makes the control re-measure every row, which takes most of a second
                // with a few hundred processes, while adding or removing a row as it is costs about 1 ms.
                bool bulk = added.Count + removed.Count > 20;
                if (bulk) tree.BeginUpdate();
                foreach (ProcInfo p in removed)
                {
                    TreeNode node = p.Node;
                    if (node == null) continue;
                    // Keep the graphs' outline on the exited process rather than letting the tree
                    // move the selection to a neighbour.
                    if (tree.SelectedNode == node) tree.SelectedNode = null;
                    // Orphans move to the top level, as in Process Explorer.
                    while (node.Nodes.Count > 0)
                    {
                        TreeNode child = node.Nodes[0];
                        child.Remove();
                        tree.Nodes.Add(child);
                    }
                    node.Remove();
                    p.Node = null;
                }

                // Oldest first, so a parent created in the same interval gets its node before its children.
                added.Sort((a, b) => a.CreateTime.CompareTo(b.CreateTime));
                foreach (ProcInfo p in added)
                {
                    int image = icons.GetSmallIndex(p.Path);
                    p.Report = safety.ReportFor(p);
                    // The row's text is what typing a name in the tree jumps to; the cells are drawn separately.
                    p.Node = new TreeNode(p.DisplayName, image, image) { Tag = p };
                    PlaceNode(p);
                }
                if (bulk) tree.EndUpdate();
            }

            if (tree.SortColumn.HasValue) SortList();
            if (top != null && top.TreeView == tree && tree.TopNode != top) tree.TopNode = top;
            // Only the cells whose text changed; repainting every row each sample was most of the cost.
            tree.RefreshChangedCells();
        }

        /// <summary>Adds a process's node under its parent in tree view, or at the top level in a sorted list.</summary>
        private void PlaceNode(ProcInfo p)
        {
            // A parent PID can belong to a newer, unrelated process once the real parent has exited.
            ProcInfo parent = !tree.SortColumn.HasValue && p.ParentPid != 0 && p.ParentPid != p.Pid
                ? monitor.FindLive(p.ParentPid)
                : null;
            if (parent?.Node != null && parent.Node != p.Node && parent.CreateTime <= p.CreateTime)
            {
                parent.Node.Nodes.Add(p.Node);
                if (parent.Node.Nodes.Count == 1) parent.Node.Expand();
            }
            else
            {
                tree.Nodes.Add(p.Node);
            }
        }

        /// <summary>Rebuilds the node layout after a header click switches between tree and sorted list.</summary>
        private void ArrangeTree()
        {
            var live = new List<ProcInfo>();
            foreach (ProcInfo p in monitor.Processes)
                if (p.Node != null) live.Add(p);
            // Tree view is built oldest first, so parents are in place before their children.
            if (tree.SortColumn.HasValue) live.Sort(tree.Compare);
            else live.Sort((a, b) => a.CreateTime.CompareTo(b.CreateTime));

            TreeNode selected = tree.SelectedNode;
            arranging = true;
            tree.BeginUpdate();
            tree.Nodes.Clear();
            foreach (ProcInfo p in live) p.Node.Nodes.Clear();
            // A flat list has no expanders, so it does not need the column reserved for them.
            tree.ShowRootLines = !tree.SortColumn.HasValue;
            foreach (ProcInfo p in live) PlaceNode(p);
            tree.SelectedNode = selected;
            selected?.EnsureVisible();
            tree.EndUpdate();
            arranging = false;
        }

        /// <summary>
        /// Puts the list back in sort order after a sample has changed the values. The rows themselves
        /// stay where they are and the processes are dealt out to them afresh; removing and re-adding
        /// rows would send the list back to the top each time.
        /// </summary>
        private void SortList()
        {
            TreeNodeCollection rows = tree.Nodes;
            var sorted = new ProcInfo[rows.Count];
            for (int i = 0; i < sorted.Length; i++) sorted[i] = (ProcInfo)rows[i].Tag;
            Array.Sort(sorted, tree.Compare);

            var selected = tree.SelectedNode?.Tag as ProcInfo;
            for (int i = 0; i < sorted.Length; i++)
            {
                TreeNode row = rows[i];
                ProcInfo process = sorted[i];
                if (row.Tag == process) continue;
                row.Tag = process;
                process.Node = row;
                if (row.Text != process.DisplayName) row.Text = process.DisplayName;
                int image = icons.GetSmallIndex(process.Path);
                if (row.ImageIndex != image) row.ImageIndex = row.SelectedImageIndex = image;
            }

            // The selection stays with the process, not the row.
            if (selected != null && tree.SelectedNode != selected.Node)
            {
                arranging = true;
                tree.SelectedNode = selected.Node;
                arranging = false;
            }
        }

        private void ShowSafetyReport(ProcInfo process)
        {
            if (process.Report == null) return;
            var form = new SafetyReportForm(process.Report, safety, theme, DeviceDpi, tree.Font);
            form.FormClosed += (s, e) => form.Dispose();
            form.Show(this);
        }

        /// <summary>Switches to the Connections tab, showing the process's connections.</summary>
        private void ShowConnections(ProcInfo process)
        {
            tabs.SelectedIndex = 1;
            connectionsView.ShowProcess(process);
        }

        private void ShowTab()
        {
            bool connections = tabs.SelectedIndex == 1;
            if (connections && connectionsView == null)
            {
                // Made only now, when the window has been scaled for its monitor, since its sizes are worked out from that.
                connectionsView = new ConnectionsView(monitor, safety, theme, DeviceDpi, tree.Font, RestartElevated) { Dock = DockStyle.Fill };
                connectionsView.ProcessRequested += process =>
                {
                    tabs.SelectedIndex = 0;
                    SelectInTree(process);
                };
                connectionsPage.Controls.Add(connectionsView);
            }
            // The page shown first, so the switch never shows an empty window.
            (connections ? connectionsPage : processesPage).Visible = true;
            (connections ? processesPage : connectionsPage).Visible = false;
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            // Ctrl+Tab and Ctrl+Shift+Tab, and Ctrl+Page Down and Up, step through the tabs, as in a browser.
            int step = keyData == (Keys.Control | Keys.Tab) || keyData == (Keys.Control | Keys.PageDown) ? 1
                : keyData == (Keys.Control | Keys.Shift | Keys.Tab) || keyData == (Keys.Control | Keys.PageUp) ? -1 : 0;
            if (step == 0) return base.ProcessCmdKey(ref msg, keyData);
            tabs.SelectedIndex = (tabs.SelectedIndex + step + tabs.Count) % tabs.Count;
            return true;
        }

        private void ShowServiceProperties(ServiceInfo service)
        {
            var form = new ServicePropertiesForm(service, theme, DeviceDpi, tree.Font);
            form.FormClosed += (s, e) => form.Dispose();
            form.Show(this);
        }

        private void ShowSafetySources()
        {
            using (var form = new SafetySourcesForm(safety.Settings, theme, DeviceDpi, tree.Font))
            {
                if (form.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    safety.ApplySettings(form.Result);
                }
                catch (Exception e) when (e is System.IO.IOException || e is UnauthorizedAccessException || e is System.Security.Cryptography.CryptographicException)
                {
                    MessageBox.Show(this, "Could not save the safety settings: " + e.Message, "Process Streamgraph", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        /// <summary>Opens the window that finds what has a file open, or brings it forward if it is already open.</summary>
        private void ShowFileInUse()
        {
            if (fileInUseForm != null)
            {
                fileInUseForm.Activate();
                return;
            }
            fileInUseForm = new FileInUseForm(monitor, icons, theme, DeviceDpi, tree.Font, SelectInTree,
                (process, location) => processMenu.Show(process, location),
                (process, owner) => processMenu.ConfirmEndTask(process, owner), RestartElevated);
            fileInUseForm.FormClosed += (s, e) =>
            {
                fileInUseForm.Dispose();
                fileInUseForm = null;
            };
            fileInUseForm.Show(this);
        }

        private void SetSelected(ProcInfo process)
        {
            foreach (StreamGraphControl graph in streamGraphs) graph.Selected = process;
        }

        private void SelectInTree(ProcInfo process)
        {
            if (process.Node == null)
            {
                // Already exited: nothing to select in the tree, but still mark it in both graphs.
                SetSelected(process);
                return;
            }
            tree.SelectedNode = process.Node;
            process.Node.EnsureVisible();
            tree.Focus();
        }

        // Raised on a system thread when Windows settings change, the light or dark app mode among them.
        private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            if (e.Category != UserPreferenceCategory.General || !IsHandleCreated) return;
            BeginInvoke((Action)(() =>
            {
                if (followSystemTheme && Theme.SystemDefault != theme) ApplyTheme(Theme.SystemDefault);
            }));
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
                Application.RemoveMessageFilter(this);
                processMenu.Dispose();
                safety.Dispose();
                timer.Dispose();
                animation.Dispose();
                monitor.Dispose();
                icons.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
