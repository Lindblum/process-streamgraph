using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    /// <summary>
    /// A row of tabs drawn in the theme's colours, which the stock tab control cannot do in the dark
    /// theme. It only switches between pages; showing the selected page is up to the owner.
    /// </summary>
    internal sealed class TabStrip : Control
    {
        private readonly List<string> titles = new List<string>();
        private readonly List<Rectangle> bounds = new List<Rectangle>();
        private Theme theme = Theme.Light;
        private int selected, hot = -1;
        private Font boldFont;

        /// <summary>Raised when another tab is chosen.</summary>
        public event Action SelectedChanged;

        public TabStrip(params string[] tabs)
        {
            titles.AddRange(tabs);
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer |
                     ControlStyles.ResizeRedraw, true);
            Dock = DockStyle.Top;
            FitHeight();
        }

        public Theme Theme
        {
            get => theme;
            set { theme = value; Invalidate(); }
        }

        public int SelectedIndex
        {
            get => selected;
            set
            {
                if (value == selected || value < 0 || value >= titles.Count) return;
                selected = value;
                Invalidate();
                SelectedChanged?.Invoke();
            }
        }

        public int Count => titles.Count;

        private float DpiScale => DeviceDpi / 96f;

        private int S(int pixels) => (int)(pixels * DpiScale);

        private Font BoldFont => boldFont ?? (boldFont = new Font(Font, FontStyle.Bold));

        // The height follows the font, which already follows the DPI, so the window's own scaling is not applied on top.
        protected override void ScaleControl(SizeF factor, BoundsSpecified specified) =>
            base.ScaleControl(factor, specified & ~BoundsSpecified.Height);

        private void FitHeight() => Height = Font.Height + S(14);

        protected override void OnFontChanged(EventArgs e)
        {
            base.OnFontChanged(e);
            boldFont?.Dispose();
            boldFont = null;
            FitHeight();
            Invalidate();
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            FitHeight();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) boldFont?.Dispose();
            base.Dispose(disposing);
        }

        // Each tab is as wide as its title in bold, so it does not change width when chosen.
        private void Measure(Graphics g)
        {
            bounds.Clear();
            int x = S(8);
            foreach (string title in titles)
            {
                int width = TextRenderer.MeasureText(g, title, BoldFont).Width + S(28);
                bounds.Add(new Rectangle(x, 0, width, Height));
                x += width;
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.Clear(theme.Control);
            Measure(g);
            using (var border = new Pen(theme.Border))
                g.DrawLine(border, 0, Height - 1, Width, Height - 1);
            for (int i = 0; i < titles.Count; i++)
            {
                Rectangle tab = bounds[i];
                if (i == hot && i != selected)
                    using (var back = new SolidBrush(theme.Hover))
                        g.FillRectangle(back, Rectangle.FromLTRB(tab.Left, tab.Top + S(3), tab.Right, tab.Bottom - 1));
                bool chosen = i == selected;
                TextRenderer.DrawText(g, titles[i], chosen ? BoldFont : Font, tab, chosen ? theme.ControlText : theme.SecondaryInk,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
                if (chosen)
                    using (var underline = new SolidBrush(theme.Selection))
                        g.FillRectangle(underline, tab.Left + S(6), tab.Bottom - S(3), tab.Width - S(12), S(3));
            }
        }

        private int TabAt(Point point)
        {
            for (int i = 0; i < bounds.Count; i++)
                if (bounds[i].Contains(point)) return i;
            return -1;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            int tab = TabAt(e.Location);
            if (tab == hot) return;
            hot = tab;
            Cursor = tab >= 0 && tab != selected ? Cursors.Hand : Cursors.Default;
            Invalidate();
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (hot < 0) return;
            hot = -1;
            Invalidate();
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button != MouseButtons.Left) return;
            int tab = TabAt(e.Location);
            if (tab >= 0) SelectedIndex = tab;
        }
    }
}
