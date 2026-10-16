using System.Drawing;
using Microsoft.Win32;

namespace ProcessStreamgraph
{
    /// <summary>Colours for the window chrome and the graphs.</summary>
    internal sealed class Theme
    {
        public string Name;
        public bool IsDark;

        // Window chrome
        public Color Window, WindowText;                        // tree
        public Color Control, ControlText;                      // toolbar, column header
        public Color Border;
        public Color Selection, SelectionText;                  // selected tree row, tree focused
        public Color InactiveSelection, InactiveSelectionText;  // selected tree row, focus elsewhere
        public Color Hover;                                     // row under the mouse

        // Graphs
        public Color Surface;
        public Color PrimaryInk, SecondaryInk, MutedInk;
        public Color Grid, Axis;
        public Color Silhouette;        // shows through wherever layers are too thin to draw individually
        public Color SystemHatch;       // stripes over the silhouette colour on the memory no process holds
        public Color TooltipBack;

        public static readonly Theme Light = new Theme
        {
            Name = "Light",
            Window = SystemColors.Window,
            WindowText = SystemColors.WindowText,
            Control = SystemColors.Control,
            ControlText = SystemColors.ControlText,
            Border = SystemColors.ControlLight,
            Selection = SystemColors.Highlight,
            SelectionText = SystemColors.HighlightText,
            InactiveSelection = SystemColors.Control,
            InactiveSelectionText = SystemColors.ControlText,
            Hover = Rgb(0xe8f0fa),

            Surface = Rgb(0xfcfcfb),
            PrimaryInk = Rgb(0x0b0b0b),
            SecondaryInk = Rgb(0x52514e),
            MutedInk = Rgb(0x898781),
            Grid = Rgb(0xe1e0d9),
            Axis = Rgb(0xc3c2b7),
            Silhouette = Rgb(0xc9c8c0),
            SystemHatch = Rgb(0xb0afa6),
            TooltipBack = Color.White
        };

        public static readonly Theme Dark = new Theme
        {
            Name = "Dark",
            IsDark = true,
            Window = Rgb(0x1a1a19),
            WindowText = Rgb(0xe8e6df),
            Control = Rgb(0x262624),
            ControlText = Rgb(0xe8e6df),
            Border = Rgb(0x383835),
            Selection = Rgb(0x2a5fa8),
            SelectionText = Color.White,
            InactiveSelection = Rgb(0x3a3a37),
            InactiveSelectionText = Rgb(0xe8e6df),
            Hover = Rgb(0x2a2a28),

            Surface = Rgb(0x1a1a19),
            PrimaryInk = Color.White,
            SecondaryInk = Rgb(0xc3c2b7),
            MutedInk = Rgb(0x898781),
            Grid = Rgb(0x2c2c2a),
            Axis = Rgb(0x4a4a46),
            Silhouette = Rgb(0x55554f),
            SystemHatch = Rgb(0x6c6c65),
            TooltipBack = Rgb(0x2c2c2a)
        };

        public static readonly Theme[] All = { Light, Dark };

        /// <summary>The theme matching the Windows "app mode" setting.</summary>
        public static Theme SystemDefault
        {
            get
            {
                object value = Registry.GetValue(
                    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1);
                return value is int light && light == 0 ? Dark : Light;
            }
        }

        private static Color Rgb(int rgb) => Color.FromArgb(0xff, Color.FromArgb(rgb));
    }
}
