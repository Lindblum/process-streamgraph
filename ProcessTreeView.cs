using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    internal enum TreeColumn { Name, FileName, Details, Cpu, Memory, Network, WindowStatus, Safety, Pid, Started, Arguments }

    /// <summary>
    /// Process tree with a row of data columns, which can be shown or hidden from the header's
    /// right-click menu and resized by dragging the divider to their right in the header, and a
    /// clickable header row for sorting.
    /// </summary>
    internal sealed class ProcessTreePanel : UserControl
    {
        private readonly HeaderRow header;
        // The tree draws its own columns, so it scrolls them sideways itself, by this bar.
        private readonly HScrollBar scrollBar;
        private Theme theme = Theme.Light;

        public ProcessTree Tree { get; }

        public ProcessTreePanel()
        {
            Tree = new ProcessTree { Dock = DockStyle.Fill };
            header = new HeaderRow(Tree) { Dock = DockStyle.Top };
            scrollBar = new HScrollBar { Dock = DockStyle.Bottom, Visible = false };
            Controls.Add(Tree);
            Controls.Add(header);
            Controls.Add(scrollBar);
            Tree.Resize += (s, e) => { header.Invalidate(); UpdateScrollBar(); };
            Tree.SortChanged += header.Invalidate;
            Tree.ColumnsChanged += delta => { header.Invalidate(); UpdateScrollBar(); };
            Tree.ColumnsResized += () => { header.Invalidate(); UpdateScrollBar(); };
            Tree.HorizontalScrolled += () =>
            {
                header.Invalidate();
                if (scrollBar.Visible && scrollBar.Value != Tree.ScrollX) scrollBar.Value = Tree.ScrollX;
            };
            scrollBar.ValueChanged += (s, e) => Tree.ScrollX = scrollBar.Value;
            scrollBar.HandleCreated += (s, e) => ApplyScrollBarTheme();
        }

        public void ApplyTheme(Theme theme)
        {
            this.theme = theme;
            header.Theme = theme;
            Tree.Theme = theme;
            ApplyScrollBarTheme();
        }

        private void ApplyScrollBarTheme()
        {
            if (scrollBar.IsHandleCreated)
                NativeMethods.SetWindowTheme(scrollBar.Handle, theme.IsDark ? "DarkMode_Explorer" : null, null);
        }

        /// <summary>Shows the scroll bar while the columns are wider than the tree, sized to match.</summary>
        private void UpdateScrollBar()
        {
            int max = Tree.MaxScrollX;
            Tree.ScrollX = Tree.ScrollX;     // within the new range
            if (max > 0)
            {
                // A scroll bar's value reaches Maximum - LargeChange + 1, which is then max.
                scrollBar.LargeChange = Math.Max(1, Tree.ClientSize.Width);
                scrollBar.SmallChange = Math.Max(1, (int)(20 * DeviceDpi / 96f));
                scrollBar.Maximum = max + scrollBar.LargeChange - 1;
                scrollBar.Value = Tree.ScrollX;
            }
            scrollBar.Visible = max > 0;
        }

        private sealed class HeaderRow : Control
        {
            private readonly ProcessTree tree;
            private Theme theme = Theme.Light;
            private TreeColumn? hot;
            private ContextMenuStrip columnMenu;
            private TreeColumn? resizing;           // column whose right edge is being dragged
            private int dragStartX, dragStartWidth;
            private TreeColumn? pressed;            // column the left button went down on: a click sorts, a drag moves it
            private bool moving;
            private int dropIndex;                  // where in the display order a moving column would land

            public HeaderRow(ProcessTree tree)
            {
                this.tree = tree;
                SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                         ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            }

            public Theme Theme
            {
                set { theme = value; BackColor = theme.Control; Invalidate(); }
            }

            protected override void OnFontChanged(EventArgs e)
            {
                base.OnFontChanged(e);
                Height = Font.Height + 10;
            }

            protected override void OnParentChanged(EventArgs e)
            {
                base.OnParentChanged(e);
                Height = Font.Height + 10;
            }

            private Rectangle CellRect(TreeColumn column)
            {
                if (column == TreeColumn.Name)
                {
                    int pad = tree.CellPadding;
                    int left = pad - tree.ScrollX;
                    return new Rectangle(left, 0, Math.Max(0, tree.ColumnRect(TreeColumn.Name, 0, Height).Right - left), Height);
                }
                return ProcessTree.IsText(column) ? tree.TextCellRect(column, 0, Height) : tree.FigureCellRect(column, 0, Height);
            }

            /// <summary>
            /// The column whose right edge, the divider after it, is under the point. As in Explorer,
            /// dragging a divider resizes the column to its left and moves the columns after it along.
            /// </summary>
            private TreeColumn? EdgeAt(Point point)
            {
                int grip = (int)(4 * DeviceDpi / 96f);
                foreach (TreeColumn column in ProcessTree.Columns)
                {
                    if (!tree.HasDivider(column)) continue;
                    if (Math.Abs(point.X - tree.ColumnRect(column, 0, Height).Right) <= grip) return column;
                }
                return null;
            }

            private TreeColumn? ColumnAt(Point point)
            {
                int pad = tree.CellPadding;
                foreach (TreeColumn column in ProcessTree.Columns)
                {
                    if (!tree.IsShown(column)) continue;
                    Rectangle cell = CellRect(column);
                    if (point.X >= cell.Left - pad && point.X < cell.Right + pad) return column;
                }
                return null;
            }

            protected override void OnMouseMove(MouseEventArgs e)
            {
                base.OnMouseMove(e);
                if (resizing.HasValue)
                {
                    float s = DeviceDpi / 96f;
                    tree.SetColumnWidth(resizing.Value, dragStartWidth + (int)Math.Round((e.X - dragStartX) / s));
                    return;
                }
                if (pressed.HasValue)
                {
                    // The process name stays first: the tree's indents and expanders live in it.
                    if (!moving && pressed != TreeColumn.Name && Math.Abs(e.X - dragStartX) > SystemInformation.DragSize.Width)
                        moving = true;
                    if (moving)
                    {
                        dropIndex = DropIndexAt(e.X);
                        Invalidate();
                    }
                    return;
                }
                Cursor = EdgeAt(e.Location).HasValue ? Cursors.SizeWE : Cursors.Default;
                TreeColumn? column = ColumnAt(e.Location);
                if (column != hot)
                {
                    hot = column;
                    Invalidate();
                }
            }

            protected override void WndProc(ref Message m)
            {
                // Shift and the wheel over the titles scroll the columns, as over the rows.
                if (tree.ScrollByWheel(ref m)) return;
                base.WndProc(ref m);
            }

            protected override void OnMouseLeave(EventArgs e)
            {
                base.OnMouseLeave(e);
                hot = null;
                Invalidate();
            }

            protected override void OnMouseDown(MouseEventArgs e)
            {
                base.OnMouseDown(e);
                if (e.Button == MouseButtons.Left && EdgeAt(e.Location) is TreeColumn edge)
                {
                    // A double-click on an edge puts the column back to its usual width.
                    if (e.Clicks == 2)
                    {
                        tree.SetColumnWidth(edge, ProcessTree.DefaultWidth(edge));
                        return;
                    }
                    resizing = edge;
                    dragStartX = e.X;
                    dragStartWidth = tree.ColumnWidth96(edge);
                    Capture = true;
                    return;
                }
                TreeColumn? column = ColumnAt(e.Location);
                if (e.Button == MouseButtons.Left && column.HasValue)
                {
                    pressed = column;
                    moving = false;
                    dragStartX = e.X;
                    Capture = true;
                }
            }

            protected override void OnMouseCaptureChanged(EventArgs e)
            {
                base.OnMouseCaptureChanged(e);
                if (Capture) return;
                resizing = null;
                if (moving) Invalidate();
                pressed = null;
                moving = false;
            }

            protected override void OnMouseUp(MouseEventArgs e)
            {
                base.OnMouseUp(e);
                if (resizing.HasValue)
                {
                    resizing = null;
                    Capture = false;
                    return;
                }
                if (pressed.HasValue && e.Button == MouseButtons.Left)
                {
                    TreeColumn column = pressed.Value;
                    bool moved = moving;
                    pressed = null;
                    moving = false;
                    Capture = false;
                    if (moved) tree.MoveColumn(column, dropIndex);
                    else tree.CycleSort(column);
                    Invalidate();
                    return;
                }
                if (e.Button != MouseButtons.Right) return;

                // A tick for each column that can be hidden; the process name always stays.
                columnMenu?.Dispose();
                columnMenu = new ContextMenuStrip { ShowImageMargin = false, ShowCheckMargin = true, Font = tree.Font };
                if (theme.IsDark) columnMenu.Renderer = new ThemedMenuRenderer(theme);
                columnMenu.ForeColor = theme.ControlText;
                foreach (TreeColumn column in tree.DisplayOrder)
                {
                    if (column == TreeColumn.Name) continue;
                    var item = new ToolStripMenuItem(ProcessTree.Title(column)) { Checked = tree.IsShown(column), CheckOnClick = true };
                    item.CheckedChanged += (s, a) => tree.SetShown(column, item.Checked);
                    columnMenu.Items.Add(item);
                }
                columnMenu.Show(this, e.Location);
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing) columnMenu?.Dispose();
                base.Dispose(disposing);
            }

            /// <summary>The place in the display order before the column whose middle is right of x.</summary>
            private int DropIndexAt(int x)
            {
                IReadOnlyList<TreeColumn> order = tree.DisplayOrder;
                for (int i = 1; i < order.Count; i++)
                {
                    if (!tree.IsShown(order[i])) continue;
                    Rectangle cell = tree.ColumnRect(order[i], 0, Height);
                    if (x < cell.Left + cell.Width / 2) return i;
                }
                return order.Count;
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                Graphics g = e.Graphics;
                float s = DeviceDpi / 96f;
                int pad = tree.CellPadding;
                foreach (TreeColumn column in ProcessTree.Columns)
                {
                    if (!tree.IsShown(column)) continue;
                    Rectangle cell = CellRect(column);
                    bool leftAligned = column == TreeColumn.Name || ProcessTree.IsText(column);
                    if (column == hot || (moving && column == pressed))
                    {
                        using (var brush = new SolidBrush(Color.FromArgb(28, theme.ControlText)))
                            g.FillRectangle(brush, cell.Left - pad, 0, cell.Width + pad * 2, Height - 1);
                    }

                    string title = ProcessTree.Title(column);
                    TextFormatFlags flags = TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix |
                                            (leftAligned ? TextFormatFlags.Left : TextFormatFlags.Right);
                    TextRenderer.DrawText(g, title, Font, cell, theme.ControlText, flags);

                    if (tree.SortColumn == column)
                    {
                        // Arrow on the inner side of the title: up for ascending, down for descending.
                        int textWidth = TextRenderer.MeasureText(g, title, Font, cell.Size, flags).Width;
                        float r = 3.5f * s;
                        float x = leftAligned ? cell.Left + textWidth + r + 3 * s : cell.Right - textWidth - r - 3 * s;
                        float y = Height / 2f, tip = tree.SortAscending ? -r * 0.6f : r * 0.6f;
                        g.SmoothingMode = SmoothingMode.AntiAlias;
                        using (var brush = new SolidBrush(theme.ControlText))
                            g.FillPolygon(brush, new[] { new PointF(x - r, y - tip), new PointF(x + r, y - tip), new PointF(x, y + tip) });
                        g.SmoothingMode = SmoothingMode.None;
                    }
                }
                using (var pen = new Pen(theme.Border))
                {
                    // Faint dividers after each column, where it can be grabbed and resized.
                    foreach (TreeColumn column in ProcessTree.Columns)
                    {
                        if (!tree.HasDivider(column)) continue;
                        int x = tree.ColumnRect(column, 0, Height).Right;
                        g.DrawLine(pen, x, 4, x, Height - 5);
                    }
                    g.DrawLine(pen, 0, Height - 1, Width, Height - 1);
                }
                if (moving)
                {
                    // Where the column would go: the left edge of the column it would go before.
                    IReadOnlyList<TreeColumn> order = tree.DisplayOrder;
                    int x = 0;
                    for (int i = 0; i < dropIndex && i < order.Count; i++)
                        if (tree.IsShown(order[i])) x = tree.ColumnRect(order[i], 0, Height).Right;
                    using (var brush = new SolidBrush(theme.ControlText))
                        g.FillRectangle(brush, x - (int)s, 0, Math.Max(2, (int)(2 * s)), Height);
                }
            }
        }
    }

    internal sealed class ProcessTree : TreeView
    {
        public static readonly TreeColumn[] Columns = (TreeColumn[])Enum.GetValues(typeof(TreeColumn));

        // Usual widths of the columns, in 96-DPI pixels; the name's includes the indent of nested rows.
        private static readonly int[] DefaultWidths = { 270, 130, 220, 58, 80, 84, 112, 100, 56, 124, 240 };

        private const int MinNameWidth = 100, MinColumnWidth = 28, MaxColumnWidth = 1200;

        private readonly int[] widths = (int[])DefaultWidths.Clone();
        private readonly bool[] shown = { true, true, true, true, true, true, true, true, true, true, true };
        private static readonly TreeColumn[] DefaultOrder =
        {
            TreeColumn.Name, TreeColumn.FileName, TreeColumn.Pid, TreeColumn.Details, TreeColumn.Cpu, TreeColumn.Memory,
            TreeColumn.Network, TreeColumn.WindowStatus, TreeColumn.Safety, TreeColumn.Started, TreeColumn.Arguments
        };
        private readonly List<TreeColumn> order = new List<TreeColumn>(DefaultOrder);    // left to right; the name always first
        private TreeNode hotNode;       // row under the mouse
        private readonly ToolTip safetyTip = new ToolTip { AutoPopDelay = 30000, InitialDelay = 400, ReshowDelay = 100 };
        private string safetyTipText;
        private Theme theme = Theme.Light;

        public ProcessTree()
        {
            DrawMode = TreeViewDrawMode.OwnerDrawText;
            ShowLines = false;
            ShowRootLines = true;
            FullRowSelect = true;
            HideSelection = false;
            BorderStyle = BorderStyle.None;
        }

        /// <summary>Column the processes are listed by, or null while they are shown as a tree.</summary>
        public TreeColumn? SortColumn { get; private set; }

        public bool SortAscending { get; private set; }

        /// <summary>False when network traffic cannot be measured; the column then shows a dash.</summary>
        public bool NetworkAvailable { get; set; }

        public bool IsShown(TreeColumn column) => column == TreeColumn.Name || shown[(int)column];

        /// <summary>Columns of text, drawn left-aligned rather than as right-aligned figures.</summary>
        public static bool IsText(TreeColumn column) =>
            column == TreeColumn.FileName || column == TreeColumn.Details || column == TreeColumn.WindowStatus || column == TreeColumn.Safety ||
            column == TreeColumn.Arguments;

        public event Action SortChanged;

        /// <summary>Raised when a column is shown or hidden, with the change in width in 96-DPI pixels.</summary>
        public event Action<int> ColumnsChanged;

        /// <summary>Raised while a column is being resized.</summary>
        public event Action ColumnsResized;

        public static int DefaultWidth(TreeColumn column) => DefaultWidths[(int)column];

        /// <summary>The columns from left to right, shown or not.</summary>
        public IReadOnlyList<TreeColumn> DisplayOrder => order;

        /// <summary>Moves a column to a place in the display order, as its index before the move counts it.</summary>
        public void MoveColumn(TreeColumn column, int index)
        {
            int from = order.IndexOf(column);
            if (column == TreeColumn.Name || from < 0) return;
            if (index > from) index--;
            index = Math.Max(1, Math.Min(order.Count - 1, index));
            if (index == from) return;
            order.RemoveAt(from);
            order.Insert(index, column);
            ColumnsResized?.Invoke();
            Invalidate();
        }

        /// <summary>A column's width in 96-DPI pixels, whether or not it is shown.</summary>
        public int ColumnWidth96(TreeColumn column) => widths[(int)column];

        public void SetColumnWidth(TreeColumn column, int width96)
        {
            width96 = Math.Max(column == TreeColumn.Name ? MinNameWidth : MinColumnWidth, Math.Min(MaxColumnWidth, width96));
            if (widths[(int)column] == width96) return;
            widths[(int)column] = width96;
            ColumnsResized?.Invoke();
            Invalidate();
        }

        /// <summary>Total width of the shown columns, the process name's included, in 96-DPI pixels.</summary>
        public int ShownColumnsWidth
        {
            get
            {
                int width = 0;
                foreach (TreeColumn column in Columns)
                    if (IsShown(column)) width += widths[(int)column];
                return width;
            }
        }

        /// <summary>
        /// The last shown column when it holds text: it stretches to the right edge, so long arguments
        /// get whatever room there is. Columns of figures keep their width, and leave the rest empty.
        /// </summary>
        private TreeColumn? FillColumn
        {
            get
            {
                for (int i = order.Count - 1; i > 0; i--)
                    if (IsShown(order[i])) return IsText(order[i]) ? (TreeColumn?)order[i] : null;
                return null;
            }
        }

        /// <summary>Whether a column has a divider after it, to resize it by; the stretching column has none.</summary>
        public bool HasDivider(TreeColumn column) => IsShown(column) && column != FillColumn;

        public void SetShown(TreeColumn column, bool show)
        {
            if (column == TreeColumn.Name || shown[(int)column] == show) return;
            shown[(int)column] = show;
            if (!show && SortColumn == column)
            {
                // Sorting by a column that is no longer there would be a puzzle, so go back to the tree.
                SortColumn = null;
                SortChanged?.Invoke();
            }
            ColumnsChanged?.Invoke(show ? widths[(int)column] : -widths[(int)column]);
            Invalidate();
        }

        public static string Title(TreeColumn column)
        {
            switch (column)
            {
                case TreeColumn.Name: return "Process Name";
                case TreeColumn.FileName: return "File Name";
                case TreeColumn.Details: return "Details";
                case TreeColumn.Cpu: return "CPU (%)";
                case TreeColumn.Memory: return "Memory";
                case TreeColumn.Network: return "Network";
                case TreeColumn.WindowStatus: return "Window Status";
                case TreeColumn.Safety: return "Safety";
                case TreeColumn.Pid: return "PID";
                case TreeColumn.Started: return "Started";
                default: return "Arguments";
            }
        }

        /// <summary>
        /// Header click: the first sorts by the column, the second reverses it, the third returns to the tree.
        /// The Process column always shows the tree.
        /// </summary>
        public void CycleSort(TreeColumn column)
        {
            if (column == TreeColumn.Name)
            {
                if (!SortColumn.HasValue) return;
                SortColumn = null;
                SortChanged?.Invoke();
                return;
            }

            // Usage columns are most useful biggest-first, and window status and safety worst-first; the
            // rest read naturally in ascending order (details alphabetically, which groups like roles).
            bool firstAscending = column != TreeColumn.Cpu && column != TreeColumn.Memory &&
                                  column != TreeColumn.Network && column != TreeColumn.WindowStatus &&
                                  column != TreeColumn.Safety;
            if (SortColumn != column)
            {
                SortColumn = column;
                SortAscending = firstAscending;
            }
            else if (SortAscending == firstAscending)
            {
                SortAscending = !firstAscending;
            }
            else
            {
                SortColumn = null;
            }
            SortChanged?.Invoke();
        }

        /// <summary>Orders two processes by the current sort column and direction.</summary>
        public int Compare(ProcInfo a, ProcInfo b)
        {
            int result = 0;
            switch (SortColumn)
            {
                case TreeColumn.Cpu: result = a.Cpu.CompareTo(b.Cpu); break;
                case TreeColumn.Memory: result = a.Memory.CompareTo(b.Memory); break;
                case TreeColumn.Network: result = a.Network.CompareTo(b.Network); break;
                case TreeColumn.WindowStatus: result = a.WindowState.CompareTo(b.WindowState); break;
                case TreeColumn.Safety: result = a.Safety.CompareTo(b.Safety); break;
                case TreeColumn.Started: result = a.CreateTime.CompareTo(b.CreateTime); break;
                case TreeColumn.FileName: result = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); break;
                case TreeColumn.Details: result = string.Compare(a.Details, b.Details, StringComparison.CurrentCultureIgnoreCase); break;
                case TreeColumn.Arguments: result = string.Compare(a.Arguments, b.Arguments, StringComparison.OrdinalIgnoreCase); break;
            }
            if (!SortAscending) result = -result;
            if (result != 0) return result;
            // Ties fall back to ascending PID, so equal rows keep a steady order between updates.
            int byPid = a.Pid.CompareTo(b.Pid);
            return SortColumn == TreeColumn.Pid && !SortAscending ? -byPid : byPid;
        }

        public Theme Theme
        {
            set
            {
                theme = value;
                BackColor = theme.Window;
                ForeColor = theme.WindowText;
                ApplyWindowTheme();
                Invalidate();
            }
        }

        private float DpiScale => DeviceDpi / 96f;

        public int CellPadding => (int)(6 * DpiScale);

        /// <summary>
        /// Bounds of a column. Columns run left to right from the process name; when the pane is too
        /// narrow for them all, they run off the right edge, last column first.
        /// </summary>
        public Rectangle ColumnRect(TreeColumn column, int top, int height)
        {
            int left = 0;
            foreach (TreeColumn before in order)
            {
                if (before == column) break;
                left += ColumnWidth(before);
            }
            int width = ColumnWidth(column);
            if (column == FillColumn) width = Math.Max(width, ClientSize.Width - CellPadding - left);
            return new Rectangle(left - scrollX, top, width, height);
        }

        private int scrollX;

        /// <summary>How far the columns are scrolled to the left, in pixels.</summary>
        public int ScrollX
        {
            get => scrollX;
            set
            {
                value = Math.Max(0, Math.Min(MaxScrollX, value));
                if (value == scrollX) return;
                scrollX = value;
                Invalidate();
                HorizontalScrolled?.Invoke();
            }
        }

        /// <summary>How far the columns can scroll: how much wider they are than the tree, in pixels.</summary>
        public int MaxScrollX
        {
            get
            {
                int width = CellPadding;
                foreach (TreeColumn column in order) width += ColumnWidth(column);
                return Math.Max(0, width - ClientSize.Width);
            }
        }

        /// <summary>Raised when the columns are scrolled sideways.</summary>
        public event Action HorizontalScrolled;

        /// <summary>Scrolls the columns for Shift and the wheel, or a tilting wheel; false for any other message.</summary>
        public bool ScrollByWheel(ref Message m)
        {
            int pixels = HorizontalWheel.Pixels(ref m, DpiScale);
            if (pixels == 0) return false;
            ScrollX += pixels;
            m.Result = m.Msg == NativeMethods.WM_MOUSEHWHEEL ? (IntPtr)1 : IntPtr.Zero;
            return true;
        }

        protected override void WndProc(ref Message m)
        {
            if (ScrollByWheel(ref m)) return;
            // The control lays out rows unscrolled, and they are drawn scrollX to the left of that, so
            // clicks are moved back by as much: then a click on an expander lands on the control's own.
            if (scrollX != 0 && (m.Msg == NativeMethods.WM_LBUTTONDOWN || m.Msg == NativeMethods.WM_LBUTTONUP ||
                                 m.Msg == NativeMethods.WM_LBUTTONDBLCLK))
            {
                long position = m.LParam.ToInt64();
                int x = (short)(position & 0xFFFF) + scrollX, y = (short)((position >> 16) & 0xFFFF);
                m.LParam = (IntPtr)((y << 16) | (x & 0xFFFF));
            }
            base.WndProc(ref m);
        }

        /// <summary>A text column's cell: left-aligned, so set in from the figures of the column before it.</summary>
        public Rectangle TextCellRect(TreeColumn column, int top, int height)
        {
            Rectangle cell = ColumnRect(column, top, height);
            int gap = CellPadding * 3;
            return Rectangle.FromLTRB(cell.Left + gap, cell.Top, cell.Right, cell.Bottom);
        }

        /// <summary>A column of figures' cell: right-aligned, so set in from the divider after it.</summary>
        public Rectangle FigureCellRect(TreeColumn column, int top, int height)
        {
            Rectangle cell = ColumnRect(column, top, height);
            return new Rectangle(cell.Left, cell.Top, Math.Max(0, cell.Width - CellPadding), cell.Height);
        }

        private int ColumnWidth(TreeColumn column)
        {
            return IsShown(column) ? (int)(widths[(int)column] * DpiScale) : 0;
        }

        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams cp = base.CreateParams;
                cp.Style |= NativeMethods.TVS_NOHSCROLL;
                return cp;
            }
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            NativeMethods.SendMessage(Handle, NativeMethods.TVM_SETEXTENDEDSTYLE,
                (IntPtr)NativeMethods.TVS_EX_DOUBLEBUFFER, (IntPtr)NativeMethods.TVS_EX_DOUBLEBUFFER);
            ApplyWindowTheme();
        }

        // The rows are painted here, but the scroll bar is the system's and needs its dark variant.
        private void ApplyWindowTheme()
        {
            if (IsHandleCreated)
                NativeMethods.SetWindowTheme(Handle, theme.IsDark ? "DarkMode_Explorer" : null, null);
        }

        /// <summary>What a row last showed, so an update can repaint just the cells that changed.</summary>
        private sealed class RowState
        {
            public ProcInfo Process;
            public readonly string[] Texts = new string[Columns.Length];    // by TreeColumn; Name included
            public Safety Safety;
        }

        // Keyed weakly by node, so rows that leave the tree take their state with them.
        private readonly ConditionalWeakTable<TreeNode, RowState> drawn = new ConditionalWeakTable<TreeNode, RowState>();
        private bool refreshQueued;

        /// <summary>
        /// Repaints the cells of the rows on screen whose text has changed since they were drawn. Most
        /// cells are the same from one sample to the next, and drawing text is the expensive part of
        /// painting the tree, so this costs a fraction of repainting it all.
        /// </summary>
        public void RefreshChangedCells()
        {
            refreshQueued = false;
            if (!IsHandleCreated || !Visible) return;
            int height = ClientSize.Height;
            for (TreeNode node = TopNode; node != null; node = node.NextVisibleNode)
            {
                Rectangle bounds = node.Bounds;
                if (bounds.Top >= height) break;
                if (!(node.Tag is ProcInfo p)) continue;
                if (!drawn.TryGetValue(node, out RowState state) || state.Process != p || state.Texts[0] != p.DisplayName)
                {
                    Invalidate(new Rectangle(0, bounds.Top, ClientSize.Width, bounds.Height));
                    continue;
                }
                foreach (TreeColumn column in Columns)
                {
                    if (column == TreeColumn.Name || !IsShown(column)) continue;
                    bool changed = column == TreeColumn.Safety
                        ? state.Safety != p.Safety || state.Texts[(int)column] != CellText(p, column)
                        : state.Texts[(int)column] != CellText(p, column);
                    if (changed) Invalidate(ColumnRect(column, bounds.Top, bounds.Height));
                }
            }
        }

        /// <summary>RefreshChangedCells, once, after the messages already waiting; for bursts of changes.</summary>
        public void QueueRefreshChangedCells()
        {
            if (refreshQueued || !IsHandleCreated) return;
            refreshQueued = true;
            BeginInvoke((Action)RefreshChangedCells);
        }

        [DllImport("gdi32.dll")]
        private static extern int GetClipBox(IntPtr hdc, out NativeMethods.RECT rect);

        // The part of a row being repainted: usually just the cells RefreshChangedCells invalidated.
        private static Rectangle PaintArea(Graphics g, Rectangle row)
        {
            IntPtr hdc = g.GetHdc();
            try
            {
                const int NULLREGION = 1, ERROR = 0;
                int kind = GetClipBox(hdc, out NativeMethods.RECT box);
                if (kind == ERROR || kind == NULLREGION) return row;
                return Rectangle.Intersect(row, Rectangle.FromLTRB(box.Left, box.Top, box.Right, box.Bottom));
            }
            finally
            {
                g.ReleaseHdc(hdc);
            }
        }

        private static string FormatStarted(ProcInfo p)
        {
            DateTime? started = p.StartTime;
            if (!started.HasValue) return "";
            return started.Value.ToString(started.Value.Date == DateTime.Today ? "T" : "g");
        }

        protected override void OnDrawNode(DrawTreeNodeEventArgs e)
        {
            // The control also raises this for rows that are not on screen, with empty bounds.
            if (e.Bounds.Height == 0 || !(e.Node.Tag is ProcInfo p)) return;

            bool selected = (e.State & TreeNodeStates.Selected) != 0;
            Color back = selected ? (Focused ? theme.Selection : theme.InactiveSelection) : e.Node == hotNode ? theme.Hover : theme.Window;
            Color fore = selected ? (Focused ? theme.SelectionText : theme.InactiveSelectionText) : theme.WindowText;

            // The row is repainted in full, including the expander and icon the control has already drawn
            // to the left of the text, so that every part of it follows the theme. Only the parts inside
            // the area being repainted are drawn, though: after a sample that is usually a few cells.
            var row = new Rectangle(0, e.Bounds.Top, ClientSize.Width, e.Bounds.Height);
            Rectangle area = PaintArea(e.Graphics, row);
            using (var brush = new SolidBrush(back))
                e.Graphics.FillRectangle(brush, area);

            Rectangle Cell(TreeColumn column) => ColumnRect(column, row.Top, row.Height);
            int nameRight = Cell(TreeColumn.Name).Right;
            if (!drawn.TryGetValue(e.Node, out RowState state))
            {
                state = new RowState();
                drawn.Add(e.Node, state);
            }
            if (state.Process != p)
            {
                // A different process in this row: whatever was recorded no longer describes it.
                state.Process = p;
                Array.Clear(state.Texts, 0, state.Texts.Length);
            }

            if (area.Left < nameRight)
            {
                int textLeft = e.Bounds.Left - scrollX;
                int iconLeft = textLeft;
                if (ImageList != null)
                {
                    Size icon = ImageList.ImageSize;
                    iconLeft = textLeft - icon.Width - (int)(3 * DpiScale);
                    if (e.Node.ImageIndex >= 0 && e.Node.ImageIndex < ImageList.Images.Count)
                        ImageList.Draw(e.Graphics, iconLeft, row.Top + (row.Height - icon.Height) / 2, e.Node.ImageIndex);
                }
                if (e.Node.Nodes.Count > 0)
                    DrawExpander(e.Graphics, iconLeft - Indent / 2f, row.Top + row.Height / 2f, e.Node.IsExpanded, fore);

                // Swatch in the colour this process has in the graphs.
                int swatch = (int)(9 * DpiScale);
                var swatchRect = new Rectangle(textLeft + 2,row.Top + (row.Height - swatch) / 2, swatch, swatch);
                using (var brush = new SolidBrush(p.Color))
                    e.Graphics.FillRectangle(brush, swatchRect);

                int nameLeft = swatchRect.Right + 3;
                var name = new Rectangle(nameLeft, row.Top, Math.Max(0, nameRight - nameLeft), row.Height);
                TextRenderer.DrawText(e.Graphics, p.DisplayName, Font, name, fore, LeftText);
                state.Texts[0] = p.DisplayName;
            }

            foreach (TreeColumn column in Columns)
            {
                if (column == TreeColumn.Name || !IsShown(column)) continue;
                Rectangle cell = Cell(column);
                if (cell.Right <= area.Left || cell.Left >= area.Right) continue;
                string text = CellText(p, column);
                if (column == TreeColumn.Safety)
                {
                    DrawSafety(e.Graphics, p, TextCellRect(column, row.Top, row.Height));
                    state.Safety = p.Safety;
                }
                else if (IsText(column))
                {
                    TextRenderer.DrawText(e.Graphics, text, Font, TextCellRect(column, row.Top, row.Height), fore, LeftText);
                }
                else
                {
                    TextRenderer.DrawText(e.Graphics, text, Font, FigureCellRect(column, row.Top, row.Height), fore, RightText);
                }
                state.Texts[(int)column] = text;
            }

            // The header's dividers carry on down through the rows, so each column reads as one.
            using (var pen = new Pen(selected ? Color.FromArgb(60, theme.Border) : theme.Border))
            {
                foreach (TreeColumn column in Columns)
                {
                    if (!HasDivider(column)) continue;
                    int x = Cell(column).Right;
                    if (x >= area.Left && x < area.Right) e.Graphics.DrawLine(pen, x, row.Top, x, row.Bottom - 1);
                }
            }
        }

        /// <summary>The shown columns' titles and what they show for a process, in order, for copying.</summary>
        public List<KeyValuePair<string, string>> CellsOf(ProcInfo p)
        {
            var cells = new List<KeyValuePair<string, string>>();
            foreach (TreeColumn column in order)
                if (IsShown(column))
                    cells.Add(new KeyValuePair<string, string>(Title(column), column == TreeColumn.Name ? p.DisplayName : CellText(p, column)));
            return cells;
        }

        /// <summary>Where a column falls among the shown ones, as CellsOf lists them; -1 for none.</summary>
        public int ShownIndexAt(int x)
        {
            int index = 0;
            foreach (TreeColumn column in order)
            {
                if (!IsShown(column)) continue;
                Rectangle cell = ColumnRect(column, 0, 1);
                if (x >= cell.Left && x < cell.Right) return index;
                index++;
            }
            return -1;
        }

        private const TextFormatFlags RightText = TextFormatFlags.Right | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix;
        private const TextFormatFlags LeftText = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis;

        private string CellText(ProcInfo p, TreeColumn column)
        {
            switch (column)
            {
                case TreeColumn.FileName: return p.Name;
                case TreeColumn.Details: return p.Details;
                case TreeColumn.Cpu: return Format.Cpu(p.Cpu);
                case TreeColumn.Memory: return Format.Memory(p.Memory / 1048576.0);
                case TreeColumn.Network: return !NetworkAvailable ? "—" : p.Network > 0 ? Format.Rate(p.Network) : "";
                case TreeColumn.WindowStatus:
                    return p.WindowState == WindowState.NotResponding ? "Not Responding"
                        : p.WindowState == WindowState.Running ? "Running" : "";
                case TreeColumn.Safety: return SafetyDrawing.BadgeText(p.Report);
                case TreeColumn.Pid: return p.Pid.ToString();
                case TreeColumn.Started: return FormatStarted(p);
                case TreeColumn.Arguments: return p.Arguments;
                default: return "";
            }
        }

        // The last column stretches to the right edge, so a change of width redraws it, ellipsis and all;
        // the control itself would only repaint the strip that was uncovered.
        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            Invalidate();
        }

        private int badgeWidth;     // measured once per font and DPI; 0 when not yet known

        protected override void OnFontChanged(EventArgs e)
        {
            base.OnFontChanged(e);
            badgeWidth = 0;
        }

        protected override void OnDpiChangedAfterParent(EventArgs e)
        {
            base.OnDpiChangedAfterParent(e);
            badgeWidth = 0;
        }

        // Badges are all the same width, so the column reads as a strip.
        private void DrawSafety(Graphics g, ProcInfo p, Rectangle cell)
        {
            if (badgeWidth == 0) badgeWidth = SafetyDrawing.BadgeWidth(g, Font, DpiScale);
            int width = Math.Min(cell.Width, badgeWidth);
            int height = Math.Min(cell.Height - 2, Font.Height + (int)(2 * DpiScale));
            var badge = new Rectangle(cell.Left, cell.Top + (cell.Height - height) / 2, width, height);
            SafetyDrawing.DrawBadge(g, badge, p.Safety, SafetyDrawing.BadgeText(p.Report), Font, theme.IsDark, DpiScale);
        }

        // Hovering a safety badge shows what the rating is based on, and hovering the details what they mean.
        private void SetHotNode(TreeNode node)
        {
            if (node == hotNode) return;
            foreach (TreeNode row in new[] { hotNode, node })
                if (row != null && row.TreeView == this)
                    Invalidate(new Rectangle(0, row.Bounds.Top, ClientSize.Width, row.Bounds.Height));
            hotNode = node;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            SetHotNode(GetNodeAt(e.Location));
            string text = null;
            if (GetNodeAt(e.Location)?.Tag is ProcInfo p)
            {
                bool Over(TreeColumn column)
                {
                    Rectangle cell = ColumnRect(column, 0, 1);
                    return IsShown(column) && e.X >= cell.Left && e.X < cell.Right;
                }
                if (Over(TreeColumn.Safety)) text = SafetyTip(p);
                else if (Over(TreeColumn.Details)) text = DetailsTip(p);
            }
            if (text == safetyTipText) return;
            safetyTipText = text;
            safetyTip.SetToolTip(this, text);
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            SetHotNode(null);
            safetyTipText = null;
            safetyTip.SetToolTip(this, null);
        }

        private static string SafetyTip(ProcInfo p)
        {
            SafetyReport report = p.Report;
            if (report == null) return null;
            var text = new System.Text.StringBuilder();
            text.Append(SafetyDrawing.BadgeText(report)).Append(": the most serious of these findings.");
            foreach (SourceResult r in report.Results)
            {
                text.AppendLine().Append("• ").Append(r.Source).Append(": ");
                if (r.Verdict != Safety.Unrated) text.Append(SafetyStyle.Title(r.Verdict)).Append(". ");
                text.Append(r.Summary);
            }
            if (report.Pending > 0) text.AppendLine().Append("Still asking some sources…");
            text.AppendLine().Append("Right-click for the full Safety Report with links.");
            return text.ToString();
        }

        // What the roles read from command lines mean, for those that need saying.
        private static readonly Dictionary<string, string> RoleNotes = new Dictionary<string, string>
        {
            ["Main process"] = "The program's main process: it owns the windows and starts the helper processes below it.",
            ["Page renderer"] = "Draws and runs web content: one or more tabs, frames or app windows. Chromium-based programs do not say which; for browsers, the site and page title are guesses from the renderer's memory and its browser's, shown only when one clearly leads. The browser's own task manager (Shift+Esc) knows for sure.",
            ["Extension renderer"] = "Runs browser extensions' background pages and scripts.",
            ["GPU process"] = "Does the program's graphics work on the graphics card, for every tab and window.",
            ["Crash reporter"] = "Waits to collect a crash report if another of the program's processes fails.",
            ["Network service"] = "Makes all of the program's network connections.",
            ["Storage service"] = "Reads and writes the program's site data: local storage, IndexedDB and caches.",
            ["Audio service"] = "Plays and records sound for the program.",
            ["Camera service"] = "Captures video from cameras for the program.",
            ["Node.js service"] = "Runs Node.js code for the app, such as VS Code's extension host, terminals or file watcher.",
        };

        private static string DetailsTip(ProcInfo p)
        {
            var text = new System.Text.StringBuilder();
            if (p.Services != null && p.Services.Length > 0)
            {
                text.Append(p.Services.Length == 1 ? "Hosts this Windows service:" : $"Hosts these {p.Services.Length} Windows services:");
                foreach (ServiceInfo service in p.Services)
                {
                    text.AppendLine().Append("• ").Append(service.DisplayName).Append(" (").Append(service.Name).Append(')');
                    string description = ServiceDirectory.Describe(service.Name);
                    if (description != null) text.AppendLine().Append(Wrap(description, 100, "   "));
                }
            }
            else if (p.Role != null)
            {
                text.Append(p.Role);
                string role = p.Role.StartsWith("WebView2") ? null : p.Role.Split(new[] { " for " }, StringSplitOptions.None)[0];
                if (role != null && RoleNotes.TryGetValue(role, out string note)) text.AppendLine().Append(Wrap(note, 100, ""));
            }
            if (p.Site != null)
            {
                if (text.Length > 0) text.AppendLine();
                text.Append("Showing ").Append(p.Site).Append(" (a guess from the addresses in its memory)");
            }
            if (p.PageTitle != null)
            {
                if (text.Length > 0) text.AppendLine();
                text.Append("Page: “").Append(p.PageTitle).Append("” (a guess from its memory and its browser's)");
            }
            if (p.WorkingFolder != null)
            {
                if (text.Length > 0) text.AppendLine();
                text.Append("Working in ").Append(p.WorkingFolder);
            }
            if (!string.IsNullOrEmpty(p.WindowTitle))
            {
                if (text.Length > 0) text.AppendLine();
                text.Append("Window: \u201C").Append(p.WindowTitle).Append('\u201D');
            }
            return text.Length == 0 ? null : text.ToString();
        }

        // Tooltips grow as wide as their longest line, so long descriptions are broken up.
        private static string Wrap(string text, int width, string indent)
        {
            var result = new System.Text.StringBuilder();
            int lineStart = 0;
            foreach (string word in text.Split(' '))
            {
                if (word.Length == 0) continue;
                if (result.Length > lineStart && result.Length - lineStart + word.Length + 1 > width)
                {
                    result.AppendLine();
                    lineStart = result.Length;
                }
                result.Append(result.Length == lineStart ? indent : " ").Append(word);
            }
            return result.ToString();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) safetyTip.Dispose();
            base.Dispose(disposing);
        }

        // Chevron centred where the control's own expander sits, so clicks still land on it.
        private void DrawExpander(Graphics g, float x, float y, bool expanded, Color color)
        {
            float r = 3.5f * DpiScale;
            PointF[] points = expanded
                ? new[] { new PointF(x - r, y - r / 2), new PointF(x, y + r / 2), new PointF(x + r, y - r / 2) }
                : new[] { new PointF(x - r / 2, y - r), new PointF(x + r / 2, y), new PointF(x - r / 2, y + r) };
            SmoothingMode smoothing = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var pen = new Pen(Color.FromArgb(170, color), 1.4f * DpiScale) { LineJoin = LineJoin.Round, StartCap = LineCap.Round, EndCap = LineCap.Round })
                g.DrawLines(pen, points);
            g.SmoothingMode = smoothing;
        }
    }
}
