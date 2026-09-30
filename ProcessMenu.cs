using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    /// <summary>Right-click menu for a process, shown from the tree and from the graphs.</summary>
    internal sealed class ProcessMenu : ContextMenuStrip
    {
        private readonly ProcessMonitor monitor;
        private readonly IWin32Window owner;
        private readonly ToolStripMenuItem header, bringToFront, endTask, openLocation, properties, copyCommandLine;
        private ProcInfo target;
        private IntPtr targetWindow;

        public ProcessMenu(ProcessMonitor monitor, IWin32Window owner)
        {
            this.monitor = monitor;
            this.owner = owner;
            ShowImageMargin = false;

            header = new ToolStripMenuItem { Enabled = false };
            bringToFront = new ToolStripMenuItem("Bring to Front", null, (s, e) => ProcessActions.BringToFront(targetWindow));
            endTask = new ToolStripMenuItem("End Task", null, (s, e) => EndTask());
            openLocation = new ToolStripMenuItem("Open File Location", null, (s, e) => Report(ProcessActions.OpenFileLocation(target.Path)));
            properties = new ToolStripMenuItem("Properties", null, (s, e) => Report(ProcessActions.ShowProperties(owner.Handle, target.Path)));
            // The Arguments column has room for only the start of a long command line.
            copyCommandLine = new ToolStripMenuItem("Copy Command Line", null, (s, e) => Clipboard.SetText(target.CommandLine));
            Items.AddRange(new ToolStripItem[]
            {
                header, new ToolStripSeparator(), bringToFront, endTask, new ToolStripSeparator(),
                openLocation, properties, copyCommandLine
            });
        }

        public Theme Theme
        {
            set
            {
                // The stock renderer has no dark variant.
                if (value.IsDark) Renderer = new ThemedMenuRenderer(value);
                else RenderMode = ToolStripRenderMode.ManagerRenderMode;
                ForeColor = value.ControlText;
            }
        }

        public void Show(ProcInfo process, Point screenLocation)
        {
            target = process;
            targetWindow = process.Alive ? FindWindow(process) : IntPtr.Zero;
            header.Text = $"{process.Name}  (PID {process.Pid})" + (process.Alive ? "" : "  ·  exited");
            bringToFront.Enabled = targetWindow != IntPtr.Zero;
            bringToFront.Text = process.Alive && targetWindow == IntPtr.Zero ? "Bring to Front  (no window)" : "Bring to Front";
            endTask.Enabled = process.Alive && process.Pid != 0;
            openLocation.Enabled = properties.Enabled = !string.IsNullOrEmpty(process.Path);
            copyCommandLine.Enabled = !string.IsNullOrEmpty(process.CommandLine);
            Show(screenLocation);
        }

        /// <summary>
        /// A window of the process, or failing that of the nearest ancestor running the same program:
        /// browsers and the like keep their windows in a parent process, not in the busy child.
        /// </summary>
        private IntPtr FindWindow(ProcInfo process)
        {
            while (process != null)
            {
                IntPtr window = ProcessActions.FindMainWindow(process.Pid);
                if (window != IntPtr.Zero) return window;
                ProcInfo parent = process.ParentPid != process.Pid ? monitor.FindLive(process.ParentPid) : null;
                bool sameProgram = parent != null && parent.CreateTime <= process.CreateTime &&
                                   string.Equals(parent.Name, process.Name, StringComparison.OrdinalIgnoreCase);
                process = sameProgram ? parent : null;
            }
            return IntPtr.Zero;
        }

        private void EndTask()
        {
            DialogResult answer = MessageBox.Show(owner,
                $"End {target.Name} (PID {target.Pid})?\n\nAny unsaved data in it will be lost.", "End Task",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer == DialogResult.Yes) Report(ProcessActions.EndTask(target));
        }

        private void Report(string error)
        {
            if (error != null)
                MessageBox.Show(owner, error, "Process Streamgraph", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    /// <summary>Menu renderer for the dark theme, which the stock renderers lack.</summary>
    internal sealed class ThemedMenuRenderer : ToolStripProfessionalRenderer
    {
        private readonly Theme theme;

        public ThemedMenuRenderer(Theme theme) : base(new Colors(theme))
        {
            this.theme = theme;
            RoundedEdges = false;
        }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = e.Item.Enabled ? theme.ControlText : theme.MutedInk;
            base.OnRenderItemText(e);
        }

        protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
        {
            // The stock tick is a dark bitmap, invisible on a dark menu.
            Rectangle box = e.ImageRectangle;
            float cx = box.Left + box.Width / 2f, cy = box.Top + box.Height / 2f, r = box.Height / 4f;
            e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            using (var pen = new Pen(theme.ControlText, Math.Max(1.5f, r / 2.5f)))
                e.Graphics.DrawLines(pen, new[] { new PointF(cx - r, cy), new PointF(cx - r / 3, cy + r * 0.7f), new PointF(cx + r, cy - r * 0.7f) });
        }

        private sealed class Colors : ProfessionalColorTable
        {
            private readonly Theme theme;

            public Colors(Theme theme)
            {
                this.theme = theme;
            }

            public override Color ToolStripDropDownBackground => theme.Control;
            public override Color MenuBorder => theme.Border;
            public override Color MenuItemBorder => theme.Selection;
            public override Color MenuItemSelected => theme.Selection;
            public override Color SeparatorDark => theme.Border;
            public override Color SeparatorLight => theme.Border;
            public override Color ImageMarginGradientBegin => theme.Control;
            public override Color ImageMarginGradientMiddle => theme.Control;
            public override Color ImageMarginGradientEnd => theme.Control;
            public override Color CheckBackground => theme.Control;
            public override Color CheckSelectedBackground => theme.Selection;
            public override Color CheckPressedBackground => theme.Selection;
        }
    }

    /// <summary>The operations behind the process menu. Those that can fail return an error message, or null.</summary>
    internal static class ProcessActions
    {
        /// <summary>The topmost ordinary window of a process: visible, titled and not owned by another window.</summary>
        public static IntPtr FindMainWindow(int pid)
        {
            MainWindows().TryGetValue(pid, out IntPtr window);
            return window;
        }

        /// <summary>The topmost ordinary window of every process that has one, by process ID.</summary>
        public static Dictionary<int, IntPtr> MainWindows()
        {
            var windows = new Dictionary<int, IntPtr>();
            NativeMethods.EnumWindows((window, state) =>
            {
                if (!NativeMethods.IsWindowVisible(window)) return true;
                if (NativeMethods.GetWindow(window, NativeMethods.GW_OWNER) != IntPtr.Zero) return true;
                if (NativeMethods.GetWindowTextLength(window) == 0) return true;
                if ((NativeMethods.GetWindowLong(window, NativeMethods.GWL_EXSTYLE) & NativeMethods.WS_EX_TOOLWINDOW) != 0) return true;
                NativeMethods.GetWindowThreadProcessId(window, out uint pid);
                // Windows come top to bottom, so the first one seen is the frontmost.
                if (!windows.ContainsKey((int)pid)) windows[(int)pid] = window;
                return true;
            }, IntPtr.Zero);
            return windows;
        }

        /// <summary>Updates each running process's window status: none, running, or not responding.</summary>
        public static void UpdateWindowStates(IReadOnlyList<ProcInfo> processes)
        {
            Dictionary<int, IntPtr> windows = MainWindows();
            foreach (ProcInfo process in processes)
            {
                if (!process.Alive || !windows.TryGetValue(process.Pid, out IntPtr window))
                    process.WindowState = WindowState.None;
                else
                    process.WindowState = NativeMethods.IsHungAppWindow(window) ? WindowState.NotResponding : WindowState.Running;
            }
        }

        public static void BringToFront(IntPtr window)
        {
            if (window == IntPtr.Zero) return;
            if (NativeMethods.IsIconic(window)) NativeMethods.ShowWindow(window, NativeMethods.SW_RESTORE);
            NativeMethods.SetForegroundWindow(window);
        }

        public static string EndTask(ProcInfo process)
        {
            string gone = $"{process.Name} (PID {process.Pid}) has already exited.";
            try
            {
                using (Process running = Process.GetProcessById(process.Pid))
                {
                    // The PID may have been handed to a different process since the menu opened.
                    if (running.StartTime.ToUniversalTime().ToFileTimeUtc() != process.CreateTime) return gone;
                    running.Kill();
                    return null;
                }
            }
            catch (ArgumentException)
            {
                return gone;
            }
            catch (InvalidOperationException)
            {
                return gone;
            }
            catch (Win32Exception e)
            {
                return $"Could not end {process.Name} (PID {process.Pid}): {e.Message}";
            }
        }

        public static string OpenFileLocation(string path)
        {
            try
            {
                Process.Start("explorer.exe", "/select,\"" + path + "\"")?.Dispose();
                return null;
            }
            catch (Win32Exception e)
            {
                return "Could not open the file location: " + e.Message;
            }
        }

        public static string ShowProperties(IntPtr owner, string path)
        {
            return NativeMethods.SHObjectProperties(owner, NativeMethods.SHOP_FILEPATH, path, null)
                ? null
                : "Could not show the properties of " + path;
        }
    }
}
