# Draws the program icon, a small bottom-aligned streamgraph on a transparent background, and writes it as app.ico with
# every size Windows asks for. Run from the project folder:
#   powershell -ExecutionPolicy Bypass -File tools\MakeIcon.ps1 [-Preview preview.png]
param([string]$Out = "app.ico", [string]$Preview = "")

Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

public static class StreamIcon
{
    // Band colours, bottom to top.
    private static readonly Color[] Bands =
    {
        Color.FromArgb(0x2f, 0xb8, 0xa6),   // teal
        Color.FromArgb(0x4a, 0x86, 0xf7),   // blue
        Color.FromArgb(0xf3, 0xae, 0x3d),   // amber
        Color.FromArgb(0xef, 0x5f, 0x72),   // coral
    };

    /// <summary>Renders one size, drawn at four times the size and scaled down for clean edges.</summary>
    public static Bitmap Render(int size)
    {
        int big = size * 4;
        using (var large = new Bitmap(big, big, PixelFormat.Format32bppPArgb))
        {
            using (Graphics g = Graphics.FromImage(large))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);
                Draw(g, big, size);
            }
            var result = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (Graphics g = Graphics.FromImage(result))
            {
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                g.CompositingQuality = CompositingQuality.HighQuality;
                g.DrawImage(large, new Rectangle(0, 0, size, size));
            }
            return result;
        }
    }

    private static void Draw(Graphics g, int s, int target)
    {
        // Bands stacked up from a flat baseline at the bottom, on a transparent background, like the
        // app's own graphs. Tiny sizes get three bands so each stays thick enough to read.
        int bands = target <= 20 ? 3 : 4;
        float margin = s * (target <= 24 ? 0.02f : 0.04f);
        var area = new RectangleF(margin, margin, s - 2 * margin, s - 2 * margin);
        int steps = 96;
        var tops = new float[bands + 1][];
        for (int b = 0; b <= bands; b++) tops[b] = new float[steps + 1];
        var xs = new float[steps + 1];
        var thick = new float[steps + 1, bands];
        var totals = new float[steps + 1];
        float maxTotal = 0;
        for (int i = 0; i <= steps; i++)
        {
            float t = i / (float)steps;
            xs[i] = area.Left + area.Width * t;
            // Each band swells and thins as a smooth bump of its own, out of step with the others.
            for (int b = 0; b < bands; b++)
            {
                double centreOfBump = 0.2 + 0.6 * b / Math.Max(1, bands - 1);
                if (b % 2 == 1) centreOfBump = 1 - centreOfBump;
                double bump = 0.45 + Math.Exp(-Math.Pow((t - centreOfBump) / 0.22, 2)) * 0.85
                                   + 0.12 * Math.Sin(t * Math.PI * 3 + b * 1.3);
                thick[i, b] = (float)Math.Max(0.25, bump);
                totals[i] += thick[i, b];
            }
            maxTotal = Math.Max(maxTotal, totals[i]);
        }
        // One scale for the whole width, so the peak just reaches the top of the icon.
        float scale = area.Height / maxTotal;
        for (int i = 0; i <= steps; i++)
        {
            float y = area.Bottom;
            tops[0][i] = y;
            for (int b = 0; b < bands; b++)
            {
                y -= thick[i, b] * scale;
                tops[b + 1][i] = y;
            }
        }

        // Slightly rounded bottom corners keep the silhouette soft beside other icons.
        using (GraphicsPath clip = Rounded(area, s * 0.08f))
        {
            g.SetClip(clip);
            for (int b = 0; b < bands; b++)
            {
                using (var path = new GraphicsPath())
                {
                    var points = new List<PointF>();
                    for (int i = 0; i <= steps; i++) points.Add(new PointF(xs[i], tops[b + 1][i]));
                    for (int i = steps; i >= 0; i--) points.Add(new PointF(xs[i], tops[b][i]));
                    path.AddPolygon(points.ToArray());
                    using (var brush = new SolidBrush(Bands[b % Bands.Length]))
                        g.FillPath(brush, path);
                }
            }
            // Thin transparent gaps between bands, cut out of the colours, so they read as separate
            // streams on any background; dropped at tiny sizes where they would only blur.
            if (target >= 32)
            {
                CompositingMode mode = g.CompositingMode;
                g.CompositingMode = CompositingMode.SourceCopy;
                using (var pen = new Pen(Color.Transparent, s * 0.018f))
                {
                    for (int b = 1; b < bands; b++)
                    {
                        var line = new PointF[steps + 1];
                        for (int i = 0; i <= steps; i++) line[i] = new PointF(xs[i], tops[b][i]);
                        g.DrawLines(pen, line);
                    }
                }
                g.CompositingMode = mode;
            }
            g.ResetClip();
        }
    }

    private static GraphicsPath Rounded(RectangleF r, float radius)
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

    /// <summary>Writes an .ico holding every size, each drawn for that size.</summary>
    public static void WriteIcon(string file, int[] sizes)
    {
        var images = new List<byte[]>();
        foreach (int size in sizes)
            using (Bitmap bmp = Render(size))
            using (var stream = new MemoryStream())
            {
                // The 256-pixel frame as PNG, the rest as plain bitmaps: .NET Framework's Icon class
                // cannot read PNG frames at the smaller sizes, and this is the usual layout anyway.
                if (size >= 256) bmp.Save(stream, ImageFormat.Png);
                else WriteDib(stream, bmp);
                images.Add(stream.ToArray());
            }
        using (var output = new BinaryWriter(File.Create(file)))
        {
            output.Write((short)0);             // reserved
            output.Write((short)1);             // icon
            output.Write((short)sizes.Length);
            int offset = 6 + 16 * sizes.Length;
            for (int i = 0; i < sizes.Length; i++)
            {
                output.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
                output.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
                output.Write((byte)0);          // no palette
                output.Write((byte)0);
                output.Write((short)1);         // colour planes
                output.Write((short)32);        // bits per pixel
                output.Write(images[i].Length);
                output.Write(offset);
                offset += images[i].Length;
            }
            foreach (byte[] image in images) output.Write(image);
        }
    }

    // An icon frame as a 32-bit bitmap: header (with the height doubled to cover the mask), pixels
    // bottom row first, then a 1-bit mask that alpha makes redundant but readers still expect.
    private static void WriteDib(Stream stream, Bitmap bmp)
    {
        int size = bmp.Width;
        var output = new BinaryWriter(stream);
        output.Write(40);                   // header size
        output.Write(size);
        output.Write(size * 2);
        output.Write((short)1);             // planes
        output.Write((short)32);            // bits per pixel
        output.Write(0);                    // uncompressed
        int maskStride = ((size + 31) / 32) * 4;
        output.Write(size * size * 4 + maskStride * size);
        output.Write(0); output.Write(0); output.Write(0); output.Write(0);
        for (int y = size - 1; y >= 0; y--)
            for (int x = 0; x < size; x++)
            {
                Color c = bmp.GetPixel(x, y);
                output.Write(c.B); output.Write(c.G); output.Write(c.R); output.Write(c.A);
            }
        for (int y = 0; y < size; y++)
            for (int i = 0; i < maskStride; i++) output.Write((byte)0);
        output.Flush();
    }

    /// <summary>Every size on a light and a dark strip, for checking by eye.</summary>
    public static void WritePreview(string file, int[] sizes)
    {
        int width = 20;
        foreach (int size in sizes) width += size + 20;
        using (var sheet = new Bitmap(width, 2 * (256 + 40), PixelFormat.Format32bppArgb))
        using (Graphics g = Graphics.FromImage(sheet))
        {
            g.FillRectangle(new SolidBrush(Color.FromArgb(0xf3, 0xf3, 0xf3)), 0, 0, width, 296);
            g.FillRectangle(new SolidBrush(Color.FromArgb(0x20, 0x20, 0x20)), 0, 296, width, 296);
            int x = 20;
            foreach (int size in sizes)
            {
                using (Bitmap icon = Render(size))
                {
                    g.DrawImageUnscaled(icon, x, 20 + 256 - size);
                    g.DrawImageUnscaled(icon, x, 296 + 20 + 256 - size);
                }
                x += size + 20;
            }
            sheet.Save(file, ImageFormat.Png);
        }
    }
}
'@

$sizes = [int[]](16, 20, 24, 32, 40, 48, 64, 128, 256)
[StreamIcon]::WriteIcon((Join-Path (Get-Location) $Out), $sizes)
if ($Preview) { [StreamIcon]::WritePreview($Preview, $sizes) }
"wrote $Out"
