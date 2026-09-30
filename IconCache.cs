using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    /// <summary>Shell icons per executable path: small ones in an ImageList for the tree, large ones for tooltips.</summary>
    internal sealed class IconCache : IDisposable
    {
        private readonly Dictionary<string, int> smallIndex = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Image> large = new Dictionary<string, Image>(StringComparer.OrdinalIgnoreCase);
        private readonly Image defaultLarge;

        public ImageList SmallImages { get; }

        public IconCache()
        {
            SmallImages = new ImageList { ColorDepth = ColorDepth.Depth32Bit };
            using (Icon icon = LoadGeneric(NativeMethods.SHGFI_LARGEICON))
                defaultLarge = icon.ToBitmap();
        }

        /// <summary>Sets the pixel size of the small icons. Must be called before any are requested.</summary>
        public void SetSmallSize(int pixels)
        {
            SmallImages.ImageSize = new Size(pixels, pixels);
            smallIndex.Clear();
        }

        public int GetSmallIndex(string path)
        {
            string key = path ?? "";
            if (smallIndex.TryGetValue(key, out int index)) return index;
            using (Icon icon = key.Length > 0 ? Load(key, NativeMethods.SHGFI_SMALLICON) : LoadGeneric(NativeMethods.SHGFI_SMALLICON))
            {
                if (icon != null)
                {
                    SmallImages.Images.Add(icon);
                    index = SmallImages.Images.Count - 1;
                }
                else
                {
                    index = GetSmallIndex(null);
                }
            }
            smallIndex[key] = index;
            return index;
        }

        // Generic executable icon, for processes with no resolvable image path.
        private static Icon LoadGeneric(uint sizeFlags) =>
            Load(".exe", sizeFlags | NativeMethods.SHGFI_USEFILEATTRIBUTES) ?? (Icon)SystemIcons.Application.Clone();

        public Image GetLarge(string path)
        {
            if (string.IsNullOrEmpty(path)) return defaultLarge;
            if (large.TryGetValue(path, out Image image)) return image;
            using (Icon icon = Load(path, NativeMethods.SHGFI_LARGEICON))
                image = icon != null ? icon.ToBitmap() : defaultLarge;
            large[path] = image;
            return image;
        }

        private static Icon Load(string path, uint sizeFlags)
        {
            var info = new NativeMethods.SHFILEINFO();
            IntPtr result = NativeMethods.SHGetFileInfo(path, NativeMethods.FILE_ATTRIBUTE_NORMAL, ref info,
                (uint)Marshal.SizeOf<NativeMethods.SHFILEINFO>(), NativeMethods.SHGFI_ICON | sizeFlags);
            if (result == IntPtr.Zero || info.hIcon == IntPtr.Zero) return null;
            try
            {
                // Clone so the managed icon owns its own handle and the shell's can be released.
                using (Icon shared = Icon.FromHandle(info.hIcon))
                    return (Icon)shared.Clone();
            }
            finally
            {
                NativeMethods.DestroyIcon(info.hIcon);
            }
        }

        public void Dispose()
        {
            SmallImages.Dispose();
            foreach (Image image in large.Values)
                if (image != defaultLarge) image.Dispose();
            defaultLarge.Dispose();
        }
    }
}
