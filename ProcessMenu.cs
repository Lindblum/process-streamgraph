using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    /// <summary>Right-click menu for a process, shown from the tree and from the graphs.</summary>
    internal sealed class ProcessMenu : ContextMenuStrip
    {
        private readonly ProcessMonitor monitor;
        private readonly IWin32Window owner;
        private readonly Control fontSource;
        private readonly ToolStripMenuItem header, bringToFront, endTask, openLocation, properties, safetyReport, connections;
        private readonly ToolStripMenuItem copyValue, copyRow;
        private readonly ToolStripSeparator copySeparator, serviceSeparator;
        private readonly List<ToolStripItem> serviceItems = new List<ToolStripItem>();
        private List<KeyValuePair<string, string>> cells;
        private ProcInfo target;
        private IntPtr targetWindow;

        /// <param name="fontSource">The control whose font, and so text size, the menu matches.</param>
        public ProcessMenu(ProcessMonitor monitor, IWin32Window owner, Control fontSource)
        {
            this.monitor = monitor;
            this.owner = owner;
            this.fontSource = fontSource;
            ShowImageMargin = false;

            header = new ToolStripMenuItem { Enabled = false };
            bringToFront = new ToolStripMenuItem("Bring to Front", null, (s, e) => ProcessActions.BringToFront(targetWindow));
            endTask = new ToolStripMenuItem("End Task", null, (s, e) => EndTask());
            openLocation = new ToolStripMenuItem("Open File Location", null, (s, e) => Report(ProcessActions.OpenFileLocation(target.Path)));
            properties = new ToolStripMenuItem("Properties", null, (s, e) => Report(ProcessActions.ShowProperties(owner.Handle, target.Path)));
            safetyReport = new ToolStripMenuItem("Safety Report…", null, (s, e) => SafetyReportRequested?.Invoke(target));
            connections = new ToolStripMenuItem("Connections…", null, (s, e) => ConnectionsRequested?.Invoke(target));
            copyValue = new ToolStripMenuItem("Copy Value");
            copyValue.Click += (s, e) => CopyText(copyValue.Tag as string);
            copyRow = new ToolStripMenuItem("Copy Row", null, (s, e) => CopyText(CellMenu.RowText(cells)));
            copySeparator = new ToolStripSeparator();
            // The items for the process's services go after this, and are rebuilt each time the menu opens.
            serviceSeparator = new ToolStripSeparator();
            Items.AddRange(new ToolStripItem[]
            {
                header, new ToolStripSeparator(), copyValue, copyRow, copySeparator, bringToFront, endTask, new ToolStripSeparator(),
                openLocation, properties, serviceSeparator, new ToolStripSeparator(), connections, safetyReport
            });
        }

        /// <summary>
        /// Adds the service commands for each Windows service the process hosts, with whatever the service
        /// accepts in its current state. A process hosting one service gets them in the menu itself; a
        /// shared service host gets a submenu for each.
        /// </summary>
        private void FillServices(ProcInfo process)
        {
            foreach (ToolStripItem item in serviceItems)
            {
                Items.Remove(item);
                item.Dispose();
            }
            serviceItems.Clear();
            ServiceInfo[] services = process.Alive ? process.Services ?? new ServiceInfo[0] : new ServiceInfo[0];
            serviceSeparator.Visible = services.Length > 0;
            if (services.Length == 0) return;

            int at = Items.IndexOf(serviceSeparator) + 1;
            if (services.Length == 1)
            {
                foreach (ToolStripItem item in ServiceItems(services[0], " Service"))
                {
                    Items.Insert(at++, item);
                    serviceItems.Add(item);
                }
                return;
            }
            foreach (ServiceInfo service in services)
            {
                ToolStripItem[] items = ServiceItems(service, "", out string status);
                var submenu = new ToolStripMenuItem(status == null ? service.DisplayName : $"{service.DisplayName}  ·  {status}");
                submenu.DropDownItems.AddRange(items);
                var dropDown = (ToolStripDropDownMenu)submenu.DropDown;
                dropDown.ShowImageMargin = false;
                dropDown.Renderer = Renderer;
                dropDown.Font = Font;
                Items.Insert(at++, submenu);
                serviceItems.Add(submenu);
            }
        }

        private ToolStripItem[] ServiceItems(ServiceInfo service, string suffix) => ServiceItems(service, suffix, out _);

        /// <param name="suffix">Follows each command's name: " Service" when it stands in the menu itself.</param>
        private ToolStripItem[] ServiceItems(ServiceInfo service, string suffix, out string status)
        {
            ServiceCommand[] commands = ServiceActions.Available(service.Name, out var state);
            status = ServiceActions.StatusText(state);
            var items = new List<ToolStripItem>
            {
                new ToolStripMenuItem((suffix.Length == 0 ? "Properties" : "Service Properties") + "…", null,
                                      (s, e) => ServicePropertiesRequested?.Invoke(service))
            };
            foreach (ServiceCommand command in commands)
                items.Add(new ToolStripMenuItem(ServiceActions.Verb(command) + suffix, null, (s, e) => RunService(service, command)));
            return items.ToArray();
        }

        private async void RunService(ServiceInfo service, ServiceCommand command)
        {
            if (command == ServiceCommand.Stop || command == ServiceCommand.Restart)
            {
                string[] dependents = ServiceActions.RunningDependents(service.Name);
                string also = dependents.Length == 0 ? ""
                    : "\n\nThese services depend on it and will also stop:\n" + string.Join("\n", dependents.Select(d => "    " + d));
                string verb = command == ServiceCommand.Stop ? "Stop" : "Restart";
                DialogResult answer = MessageBox.Show(owner,
                    $"{verb} {service.DisplayName} ({service.Name})?{also}\n\nPrograms relying on it may stop working until it runs again.",
                    verb + " Service", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (answer != DialogResult.Yes) return;
            }
            string error = await ServiceActions.RunAsync(command, service);
            ServiceDirectory.RefreshSoon();
            Report(error);
        }

        private static void CopyText(string text)
        {
            if (!string.IsNullOrEmpty(text)) Clipboard.SetText(text);
        }

        /// <summary>Raised when the Safety Report item is chosen.</summary>
        public event Action<ProcInfo> SafetyReportRequested;

        /// <summary>Raised when the Connections item is chosen.</summary>
        public event Action<ProcInfo> ConnectionsRequested;

        /// <summary>Raised when a service's Properties item is chosen.</summary>
        public event Action<ServiceInfo> ServicePropertiesRequested;

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

        /// <summary>Shows the menu for a process, with no cell values to copy.</summary>
        public void Show(ProcInfo process, Point screenLocation) => Show(process, screenLocation, null, -1);

        /// <param name="cells">The row's column titles and values, to copy from; null when there is no row.</param>
        /// <param name="clicked">Index into cells of the one right-clicked, offered first; -1 for none.</param>
        public void Show(ProcInfo process, Point screenLocation, List<KeyValuePair<string, string>> cells, int clicked)
        {
            this.cells = cells;
            target = process;
            targetWindow = process.Alive ? FindWindow(process) : IntPtr.Zero;
            header.Text = (process.DisplayName == process.Name ? process.Name : $"{process.DisplayName}  ·  {process.Name}") +
                          $"  (PID {process.Pid})" + (process.Alive ? "" : "  ·  exited");
            bringToFront.Enabled = targetWindow != IntPtr.Zero;
            bringToFront.Text = process.Alive && targetWindow == IntPtr.Zero ? "Bring to Front  (no window)" : "Bring to Front";
            endTask.Enabled = process.Alive && process.Pid != 0;
            openLocation.Enabled = properties.Enabled = !string.IsNullOrEmpty(process.Path);
            safetyReport.Enabled = process.Report != null;
            // Menus otherwise take the system menu font, which comes out larger than the table's.
            if (!Equals(Font, fontSource.Font)) Font = fontSource.Font;
            FillServices(process);
            CellMenu.Fill(copyValue, cells, clicked);
            copyRow.Visible = copySeparator.Visible = cells != null;
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
                $"End {target.DisplayName} ({target.Name}, PID {target.Pid})?\n\nAny unsaved data in it will be lost.", "End Task",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer == DialogResult.Yes) Report(ProcessActions.EndTask(target));
        }

        private void Report(string error)
        {
            if (error != null)
                MessageBox.Show(owner, error, "Process Streamgraph", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    /// <summary>The items of a right-click menu that copy a table's cell values.</summary>
    internal static class CellMenu
    {
        /// <summary>
        /// Sets up Copy Value to copy the cell clicked, whose value it keeps in its Tag; it is hidden when
        /// no cell was clicked, as when the menu comes from the keyboard.
        /// </summary>
        public static void Fill(ToolStripMenuItem copyValue, List<KeyValuePair<string, string>> cells, int clicked)
        {
            copyValue.Visible = cells != null && clicked >= 0 && clicked < cells.Count;
            string value = cells != null && clicked >= 0 && clicked < cells.Count ? cells[clicked].Value : "";
            copyValue.Enabled = value.Length > 0;
            copyValue.Tag = value;
        }

        /// <summary>A row's values separated by tabs, ready to paste into a spreadsheet.</summary>
        public static string RowText(List<KeyValuePair<string, string>> cells) =>
            cells == null ? null : string.Join("\t", cells.Select(c => c.Value.Replace('\t', ' ').Replace("\r", "").Replace('\n', ' ')));
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

        /// <summary>
        /// Updates each running process's window status (none, running, or not responding) and the
        /// title of its frontmost window.
        /// </summary>
        public static void UpdateWindowStates(IReadOnlyList<ProcInfo> processes)
        {
            Dictionary<int, IntPtr> windows = MainWindows();
            var title = new StringBuilder(256);
            // The Explorer process that draws the desktop and taskbar has no ordinary window to name it.
            NativeMethods.GetWindowThreadProcessId(NativeMethods.GetShellWindow(), out uint shellPid);
            foreach (ProcInfo process in processes)
            {
                if (process.Pid == shellPid && process.Alive && process.Role == null)
                {
                    process.Role = "Windows shell: desktop and taskbar";
                    process.RefreshDetails();
                }
                string text = null;
                if (!process.Alive || !windows.TryGetValue(process.Pid, out IntPtr window))
                {
                    process.WindowState = WindowState.None;
                }
                else
                {
                    process.WindowState = NativeMethods.IsHungAppWindow(window) ? WindowState.NotResponding : WindowState.Running;
                    // Reads the text Windows keeps for the window, without asking its process, so a hung
                    // program cannot hold this up.
                    title.Length = 0;
                    if (NativeMethods.GetWindowText(window, title, title.Capacity) > 0) text = title.ToString();
                }
                // Exited processes keep the last title they had.
                if (process.Alive && text != process.WindowTitle)
                {
                    process.WindowTitle = text;
                    process.RefreshDetails();
                }
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
