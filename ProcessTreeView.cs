using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    internal enum TreeColumn { Name, Cpu, Memory, Network, WindowStatus, Pid, Started, Arguments }

    /// <summary>
    /// Process tree with a row of data columns, which can be shown or hidden from the header's
    /// right-click menu, and a clickable header row for sorting.
    /// </summary>
    internal sealed class ProcessTreePanel : UserControl
    {
        private readonly HeaderRow header;

        public ProcessTree Tree { get; }

        public ProcessTreePanel()
        {
            Tree = new ProcessTree { Dock = DockStyle.Fill };
            header = new HeaderRow(Tree) { Dock = DockStyle.Top };
            Controls.Add(Tree);
            Controls.Add(header);
            Tree.Resize += (s, e) => header.Invalidate();
            Tree.SortChanged += header.Invalidate;
            Tree.ColumnsChanged += delta => header.Invalidate();
        }

        public void ApplyTheme(Theme theme)
        {
            header.Theme = theme;
            Tree.Theme = theme;
        }

        private sealed class HeaderRow : Control
        {
            private readonly ProcessTree tree;
            private Theme theme = Theme.Light;
            private TreeColumn? hot;
            private ContextMenuStrip columnMenu;

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
                    return new Rectangle(pad, 0, Math.Max(0, tree.ColumnRect(TreeColumn.Cpu, 0, Height).Left - pad), Height);
                }
                return ProcessTree.IsText(column) ? tree.TextCellRect(column, 0, Height) : tree.ColumnRect(column, 0, Height);
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
                TreeColumn? column = ColumnAt(e.Location);
                if (column != hot)
                {
                    hot = column;
                    Invalidate();
                }
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
                TreeColumn? column = ColumnAt(e.Location);
                if (e.Button == MouseButtons.Left && column.HasValue) tree.CycleSort(column.Value);
            }

            protected override void OnMouseUp(MouseEventArgs e)
            {
                base.OnMouseUp(e);
                if (e.Button != MouseButtons.Right) return;

                // A tick for each column that can be hidden; the process name always stays.
                columnMenu?.Dispose();
                columnMenu = new ContextMenuStrip { ShowImageMargin = false, ShowCheckMargin = true };
                if (theme.IsDark) columnMenu.Renderer = new ThemedMenuRenderer(theme);
                columnMenu.ForeColor = theme.ControlText;
                foreach (TreeColumn column in ProcessTree.Columns)
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
                    if (column == hot)
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
                    g.DrawLine(pen, 0, Height - 1, Width, Height - 1);
            }
        }
    }

    internal sealed class ProcessTree : TreeView
    {
        public static readonly TreeColumn[] Columns = (TreeColumn[])Enum.GetValues(typeof(TreeColumn));

        // Widths of the columns right of the name, which takes whatever space is left.
        private static readonly int[] ColumnWidths = { 0, 58, 80, 84, 112, 56, 124, 240 };

        private const int MinNameWidth = 170;      // 96-DPI pixels, including the indent of nested rows

        private readonly bool[] shown = { true, true, true, true, true, true, true, true };
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
        public static bool IsText(TreeColumn column) => column == TreeColumn.WindowStatus || column == TreeColumn.Arguments;

        public event Action SortChanged;

        /// <summary>Raised when a column is shown or hidden, with the change in width in 96-DPI pixels.</summary>
        public event Action<int> ColumnsChanged;

        /// <summary>Total width of the shown data columns, in 96-DPI pixels.</summary>
        public int ShownColumnsWidth
        {
            get
            {
                int width = 0;
                foreach (TreeColumn column in Columns)
                    if (IsShown(column)) width += ColumnWidths[(int)column];
                return width;
            }
        }

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
            ColumnsChanged?.Invoke(show ? ColumnWidths[(int)column] : -ColumnWidths[(int)column]);
            Invalidate();
        }

        public static string Title(TreeColumn column)
        {
            switch (column)
            {
                case TreeColumn.Name: return "Process";
                case TreeColumn.Cpu: return "CPU (%)";
                case TreeColumn.Memory: return "Memory";
                case TreeColumn.Network: return "Network";
                case TreeColumn.WindowStatus: return "Window Status";
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

            // Usage columns are most useful biggest-first, and window status worst-first; the rest read
            // naturally in ascending order.
            bool firstAscending = column != TreeColumn.Cpu && column != TreeColumn.Memory &&
                                  column != TreeColumn.Network && column != TreeColumn.WindowStatus;
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
                case TreeColumn.Started: result = a.CreateTime.CompareTo(b.CreateTime); break;
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
        /// Bounds of a data column. Columns are anchored to the right edge of the tree; when the pane is
        /// too narrow for them all, the process name keeps a minimum width and the columns run off the
        /// right edge instead, last column first.
        /// </summary>
        public Rectangle ColumnRect(TreeColumn column, int top, int height)
        {
            int right = Math.Max(ClientSize.Width - CellPadding, (int)((MinNameWidth + ShownColumnsWidth) * DpiScale));
            for (int i = ColumnWidths.Length - 1; i > (int)column; i--)
                right -= ColumnWidth((TreeColumn)i);
            int width = ColumnWidth(column);
            return new Rectangle(right - width, top, width, height);
        }

        /// <summary>A text column's cell: left-aligned, so set in from the figures of the column before it.</summary>
        public Rectangle TextCellRect(TreeColumn column, int top, int height)
        {
            Rectangle cell = ColumnRect(column, top, height);
            int gap = CellPadding * 3;
            return Rectangle.FromLTRB(cell.Left + gap, cell.Top, cell.Right, cell.Bottom);
        }

        private int ColumnWidth(TreeColumn column)
        {
            return IsShown(column) ? (int)(ColumnWidths[(int)column] * DpiScale) : 0;
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
            Color back = selected ? (Focused ? theme.Selection : theme.InactiveSelection) : theme.Window;
            Color fore = selected ? (Focused ? theme.SelectionText : theme.InactiveSelectionText) : theme.WindowText;

            // The whole row is repainted, including the expander and icon the control has already drawn
            // to the left of the text, so that every part of it follows the theme.
            var row = new Rectangle(0, e.Bounds.Top, ClientSize.Width, e.Bounds.Height);
            using (var brush = new SolidBrush(back))
                e.Graphics.FillRectangle(brush, row);

            int iconLeft = e.Bounds.Left;
            if (ImageList != null)
            {
                Size icon = ImageList.ImageSize;
                iconLeft = e.Bounds.Left - icon.Width - (int)(3 * DpiScale);
                if (e.Node.ImageIndex >= 0 && e.Node.ImageIndex < ImageList.Images.Count)
                    ImageList.Draw(e.Graphics, iconLeft, row.Top + (row.Height - icon.Height) / 2, e.Node.ImageIndex);
            }
            if (e.Node.Nodes.Count > 0)
                DrawExpander(e.Graphics, iconLeft - Indent / 2f, row.Top + row.Height / 2f, e.Node.IsExpanded, fore);

            // Swatch in the colour this process has in the graphs.
            int swatch = (int)(9 * DpiScale);
            var swatchRect = new Rectangle(e.Bounds.Left + 2, row.Top + (row.Height - swatch) / 2, swatch, swatch);
            using (var brush = new SolidBrush(p.Color))
                e.Graphics.FillRectangle(brush, swatchRect);

            const TextFormatFlags right = TextFormatFlags.Right | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix;
            const TextFormatFlags left = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis;

            Rectangle Cell(TreeColumn column) => ColumnRect(column, row.Top, row.Height);
            int nameLeft = swatchRect.Right + 3;
            var name = new Rectangle(nameLeft, row.Top, Math.Max(0, Cell(TreeColumn.Cpu).Left - nameLeft), row.Height);
            TextRenderer.DrawText(e.Graphics, p.Name, Font, name, fore, left);
            foreach (TreeColumn column in Columns)
            {
                if (column == TreeColumn.Name || !IsShown(column)) continue;
                string text = CellText(p, column);
                if (IsText(column))
                    TextRenderer.DrawText(e.Graphics, text, Font, TextCellRect(column, row.Top, row.Height), fore, left);
                else
                    TextRenderer.DrawText(e.Graphics, text, Font, Cell(column), fore, right);
            }
        }

        private string CellText(ProcInfo p, TreeColumn column)
        {
            switch (column)
            {
                case TreeColumn.Cpu: return Format.Cpu(p.Cpu);
                case TreeColumn.Memory: return Format.Memory(p.Memory / 1048576.0);
                case TreeColumn.Network: return !NetworkAvailable ? "—" : p.Network > 0 ? Format.Rate(p.Network) : "";
                case TreeColumn.WindowStatus:
                    return p.WindowState == WindowState.NotResponding ? "Not Responding"
                        : p.WindowState == WindowState.Running ? "Running" : "";
                case TreeColumn.Pid: return p.Pid.ToString();
                case TreeColumn.Started: return FormatStarted(p);
                case TreeColumn.Arguments: return p.Arguments;
                default: return "";
            }
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
