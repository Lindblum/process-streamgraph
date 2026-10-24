using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ProcessStreamgraph
{
    /// <summary>A process that has a file open, as the Restart Manager reports it.</summary>
    internal sealed class FileHolder
    {
        public int Pid;
        public long StartTime;          // FILETIME (UTC), to tell it from a later process given the same PID
        public string AppName;          // the Restart Manager's name for it
        public string Kind;             // what sort of program it is
        public bool WorkingFolder;      // found as a shell working inside the folder rather than through an open file
    }

    /// <summary>
    /// Finds the processes holding a file open, through the Windows Restart Manager: the same check
    /// installers and Explorer use before reporting that a file is in use. It sees open files and
    /// loaded program files, without touching the processes themselves.
    /// </summary>
    internal static class FileLocks
    {
        /// <summary>Most files of a folder that are checked; past this the search stops early.</summary>
        public const int MaxFiles = 20000;

        private const int ERROR_MORE_DATA = 234;
        private const int CCH_RM_SESSION_KEY = 32;

        [StructLayout(LayoutKind.Sequential)]
        private struct RM_UNIQUE_PROCESS
        {
            public int ProcessId;
            public uint StartLow, StartHigh;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string AppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string ServiceShortName;
            public int ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool Restartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint session, int flags, StringBuilder key);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint session);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(uint session, uint fileCount, string[] files,
            uint applicationCount, IntPtr applications, uint serviceCount, string[] services);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(uint session, out uint needed, ref uint count,
            [In, Out] RM_PROCESS_INFO[] processes, ref uint rebootReasons);

        public static bool IsElevated
        {
            get
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                    return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        /// <summary>
        /// The files to check for a path: the file itself, or every file inside a folder up to
        /// <see cref="MaxFiles"/>. Subfolders that cannot be read are skipped.
        /// </summary>
        public static List<string> FilesOf(string path, out bool truncated)
        {
            truncated = false;
            var files = new List<string>();
            if (File.Exists(path))
            {
                files.Add(path);
                return files;
            }
            var pending = new Stack<string>();
            pending.Push(path);
            while (pending.Count > 0)
            {
                string folder = pending.Pop();
                try
                {
                    foreach (string file in Directory.EnumerateFiles(folder))
                    {
                        if (files.Count == MaxFiles)
                        {
                            truncated = true;
                            return files;
                        }
                        files.Add(file);
                    }
                    foreach (string child in Directory.EnumerateDirectories(folder))
                    {
                        // Junctions and links can lead outside the folder, or round in a circle.
                        if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0) pending.Push(child);
                    }
                }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
                {
                }
            }
            return files;
        }

        /// <summary>The processes holding any of the files open. Throws Win32Exception if the check fails.</summary>
        public static List<FileHolder> Find(List<string> files)
        {
            var key = new StringBuilder(CCH_RM_SESSION_KEY + 1);
            int result = RmStartSession(out uint session, 0, key);
            if (result != 0) throw new Win32Exception(result);
            try
            {
                // In batches, so a big folder does not make one enormous call.
                for (int at = 0; at < files.Count; at += 1000)
                {
                    string[] batch = files.GetRange(at, Math.Min(1000, files.Count - at)).ToArray();
                    result = RmRegisterResources(session, (uint)batch.Length, batch, 0, IntPtr.Zero, 0, null);
                    if (result != 0) throw new Win32Exception(result);
                }

                uint count = 0, reasons = 0;
                RM_PROCESS_INFO[] found = null;
                result = RmGetList(session, out uint needed, ref count, null, ref reasons);
                // The list can grow between the two calls, so ask again until it fits.
                while (result == ERROR_MORE_DATA)
                {
                    found = new RM_PROCESS_INFO[needed];
                    count = needed;
                    result = RmGetList(session, out needed, ref count, found, ref reasons);
                }
                if (result != 0) throw new Win32Exception(result);

                var holders = new List<FileHolder>();
                for (int i = 0; i < count; i++)
                {
                    RM_PROCESS_INFO info = found[i];
                    holders.Add(new FileHolder
                    {
                        Pid = info.Process.ProcessId,
                        StartTime = ((long)info.Process.StartHigh << 32) | info.Process.StartLow,
                        AppName = info.AppName,
                        Kind = KindOf(info)
                    });
                }
                return holders;
            }
            finally
            {
                RmEndSession(session);
            }
        }

        /// <summary>
        /// The processes whose working folder is the folder or inside it. Windows keeps that folder open
        /// for them, so it cannot be renamed or deleted, yet the Restart Manager does not see it, since no
        /// file in it is open. Every process is read, not only shells: a dev server or any program
        /// started from the folder holds it the same way.
        /// </summary>
        public static List<FileHolder> WorkingInside(string folder, List<ProcInfo> processes)
        {
            string prefix = folder.TrimEnd('\\') + "\\";
            var holders = new List<FileHolder>();
            foreach (ProcInfo p in processes)
            {
                string working = NativeMethods.GetCurrentDirectory(p.Pid) ?? p.WorkingFolder;
                if (working == null || !(working.TrimEnd('\\') + "\\").StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                holders.Add(new FileHolder { Pid = p.Pid, StartTime = p.CreateTime, AppName = p.DisplayName, Kind = "Working in the folder", WorkingFolder = true });
            }
            return holders;
        }

        private static string KindOf(RM_PROCESS_INFO info)
        {
            switch (info.ApplicationType)
            {
                case 1: return "Program with a window";
                case 2: return "Program";
                case 3: return string.IsNullOrEmpty(info.ServiceShortName) ? "Service" : "Service: " + info.ServiceShortName;
                case 4: return "Windows Explorer";
                case 5: return "Console program";
                case 1000: return "Critical system process";
                default: return "Program";
            }
        }
    }

    /// <summary>
    /// Asks for a file or folder and lists the processes that have it open, for when Windows will not
    /// delete, move or rename it because it is in use.
    /// </summary>
    internal sealed class FileInUseForm : Form
    {
        private readonly ProcessMonitor monitor;
        private readonly IconCache icons;
        private readonly Theme theme;
        private readonly float scale;
        private readonly Action<ProcInfo> showInList;
        private readonly Action<ProcInfo, Point> showMenu;
        private readonly Func<ProcInfo, IWin32Window, bool> endTask;
        private readonly Action restartElevated;
        private readonly TextBox path;
        private readonly Button find, browse, show, elevate;
        private readonly ListView list;
        private readonly Label status;
        private ConnectionsView.HeaderFiller headerFiller;
        private bool searching;

        /// <param name="showInList">Selects a process in the main window's process list.</param>
        /// <param name="showMenu">Opens the process menu at a screen position.</param>
        /// <param name="endTask">Asks over the given window, then ends the process; true when it was ended.</param>
        public FileInUseForm(ProcessMonitor monitor, IconCache icons, Theme theme, int dpi, Font font,
                             Action<ProcInfo> showInList, Action<ProcInfo, Point> showMenu,
                             Func<ProcInfo, IWin32Window, bool> endTask, Action restartElevated)
        {
            this.monitor = monitor;
            this.icons = icons;
            this.theme = theme;
            this.showInList = showInList;
            this.showMenu = showMenu;
            this.endTask = endTask;
            this.restartElevated = restartElevated;
            scale = dpi / 96f;

            Text = "File in Use";
            using (var stream = typeof(FileInUseForm).Assembly.GetManifestResourceStream("ProcessStreamgraph.app.ico"))
                if (stream != null) Icon = new Icon(stream);
            Font = font;
            AutoScaleMode = AutoScaleMode.None;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(S(900), S(420));
            MinimumSize = new Size(S(520), S(280));

            // Every row centres its controls vertically, with the same gaps and button heights throughout.
            path = new TextBox { Anchor = AnchorStyles.Left | AnchorStyles.Right, Margin = new Padding(0, 0, S(6), 0) };
            path.TextChanged += (s, e) => UpdateButtons();
            browse = new Button { Text = "Browse…", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(S(6), S(2), S(6), S(2)), Margin = Padding.Empty };
            browse.Click += (s, e) => Browse();
            find = new Button { Text = "Find", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(S(10), S(2), S(10), S(2)), Margin = new Padding(S(6), 0, 0, 0) };
            find.Click += (s, e) => Find();
            AcceptButton = find;

            var top = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 4, Padding = new Padding(S(14), S(12), S(14), 0) };
            top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            top.Controls.Add(new Label { Text = "File or folder:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 0, S(6), 0) }, 0, 0);
            top.Controls.Add(path, 1, 0);
            top.Controls.Add(browse, 2, 0);
            top.Controls.Add(find, 3, 0);

            var note = new Label
            {
                AutoSize = true,
                Dock = DockStyle.Top,
                Padding = new Padding(S(14), S(8), S(14), S(8)),
                ForeColor = theme.MutedInk,
                Text = "Type a path, browse, or drop a file or folder here to see which programs have it open. For a folder, every file " +
                       $"inside is checked (up to {FileLocks.MaxFiles:N0}), along with programs working in it, which are listed first. " +
                       "Double-click a program to find it in the process list; press Delete or right-click it to end it."
            };

            list = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                HideSelection = false,
                MultiSelect = false,
                BorderStyle = BorderStyle.None,
                OwnerDraw = true,
                SmallImageList = icons.SmallImages,
                BackColor = theme.Window,
                ForeColor = theme.WindowText
            };
            list.Columns.Add(new ColumnHeader { Text = "Program", Width = S(220) });
            list.Columns.Add(new ColumnHeader { Text = "PID", Width = S(70), TextAlign = HorizontalAlignment.Right });
            list.Columns.Add(new ColumnHeader { Text = "Kind", Width = S(170) });
            list.Columns.Add(new ColumnHeader { Text = "Details", Width = S(220) });
            list.Columns.Add(new ColumnHeader { Text = "Path", Width = S(320) });
            list.DrawColumnHeader += DrawHeader;
            list.DrawItem += (s, e) => e.DrawDefault = true;
            list.DrawSubItem += (s, e) => e.DrawDefault = true;
            list.HandleCreated += (s, e) =>
            {
                NativeMethods.SetWindowTheme(list.Handle, theme.IsDark ? "DarkMode_Explorer" : null, null);
                headerFiller = new ConnectionsView.HeaderFiller(list, theme);
            };
            list.HandleDestroyed += (s, e) => headerFiller?.ReleaseHandle();
            list.SelectedIndexChanged += (s, e) => UpdateButtons();
            list.MouseDoubleClick += (s, e) =>
            {
                if (e.Button == MouseButtons.Left) ShowSelected();
            };
            list.KeyDown += (s, e) =>
            {
                if (e.KeyCode != Keys.Delete || e.Modifiers != Keys.None || list.SelectedItems.Count == 0) return;
                ListViewItem item = list.SelectedItems[0];
                // Gone from the list once ended, so what is left shows what still holds the file.
                if (item.Tag is ProcInfo process && endTask(process, this)) list.Items.Remove(item);
                e.Handled = true;
            };
            list.MouseUp += (s, e) =>
            {
                if (e.Button == MouseButtons.Right && list.HitTest(e.Location).Item?.Tag is ProcInfo process)
                    showMenu(process, list.PointToScreen(e.Location));
            };

            status = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 0, S(12), 0) };
            show = new Button { Text = "Show in Process List", AutoSize = true, Anchor = AnchorStyles.Right, Padding = new Padding(S(6), S(2), S(6), S(2)), Margin = new Padding(S(6), 0, 0, 0) };
            show.Click += (s, e) => ShowSelected();
            elevate = new Button { Text = "Restart as Administrator", AutoSize = true, Anchor = AnchorStyles.Right, Padding = new Padding(S(6), S(2), S(6), S(2)), Margin = new Padding(S(6), 0, 0, 0), Visible = false };
            elevate.Click += (s, e) => restartElevated();
            var close = new Button { Text = "Close", AutoSize = true, Anchor = AnchorStyles.Right, DialogResult = DialogResult.Cancel, Padding = new Padding(S(6), S(2), S(6), S(2)), Margin = new Padding(S(6), 0, 0, 0) };
            close.Click += (s, e) => Close();
            CancelButton = close;
            var buttons = new TableLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, ColumnCount = 4, Padding = new Padding(S(14), S(10), S(14), S(12)) };
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttons.Controls.Add(status, 0, 0);
            buttons.Controls.Add(elevate, 1, 0);
            buttons.Controls.Add(show, 2, 0);
            buttons.Controls.Add(close, 3, 0);

            var listFrame = new Panel { Dock = DockStyle.Fill, Padding = new Padding(S(14), 0, S(14), 0) };
            listFrame.Controls.Add(list);
            Controls.Add(listFrame);
            Controls.Add(note);
            Controls.Add(top);
            Controls.Add(buttons);
            SafetyDrawing.Style(this, theme);
            note.ForeColor = theme.MutedInk;
            list.BackColor = theme.Window;
            list.ForeColor = theme.WindowText;
            Resize += (s, e) =>
            {
                note.MaximumSize = new Size(Math.Max(S(200), ClientSize.Width - note.Padding.Horizontal), 0);
                status.MaximumSize = new Size(Math.Max(S(100), ClientSize.Width - S(460)), 0);
            };
            AcceptDrops(this);
            UpdateButtons();
        }

        private int S(int pixels) => (int)(pixels * scale);

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            NativeMethods.SetDarkTitleBar(Handle, theme.IsDark);
        }

        /// <summary>Lets a file or folder be dropped anywhere on the window, its controls included.</summary>
        private void AcceptDrops(Control control)
        {
            control.AllowDrop = true;
            control.DragEnter += (s, e) =>
            {
                if (!searching && e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
            };
            control.DragDrop += (s, e) =>
            {
                if (!(e.Data.GetData(DataFormats.FileDrop) is string[] dropped) || dropped.Length == 0) return;
                path.Text = dropped[0];
                Find();
            };
            foreach (Control child in control.Controls) AcceptDrops(child);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            Icon?.Dispose();
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
            var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix |
                        (e.Header.TextAlign == HorizontalAlignment.Right ? TextFormatFlags.Right : TextFormatFlags.Left);
            TextRenderer.DrawText(e.Graphics, e.Header.Text, Font, Rectangle.Inflate(e.Bounds, -S(6), 0), theme.ControlText, flags);
        }

        private void UpdateButtons()
        {
            find.Enabled = browse.Enabled = path.Enabled = !searching;
            find.Enabled &= path.Text.Trim().Length > 0;
            show.Enabled = list.SelectedItems.Count > 0 && list.SelectedItems[0].Tag is ProcInfo;
        }

        private void Browse()
        {
            using (var dialog = new OpenFileDialog { Title = "Choose the file that is in use", CheckFileExists = true })
            {
                if (File.Exists(path.Text.Trim())) dialog.FileName = path.Text.Trim();
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                path.Text = dialog.FileName;
            }
            Find();
        }

        private void ShowSelected()
        {
            if (list.SelectedItems.Count > 0 && list.SelectedItems[0].Tag is ProcInfo process) showInList(process);
        }

        private async void Find()
        {
            string target = path.Text.Trim().Trim('"');
            if (target.Length == 0 || searching) return;
            bool isFolder = Directory.Exists(target);
            if (!isFolder && !File.Exists(target))
            {
                ShowResults(new List<FileHolder>(), "There is no file or folder at that path.");
                return;
            }
            target = Path.GetFullPath(target);

            searching = true;
            UpdateButtons();
            list.Items.Clear();
            elevate.Visible = false;

            // Programs working in the folder are found in a moment; the Restart Manager can take minutes
            // over a big folder, so they are shown first rather than waiting on it.
            var working = new List<FileHolder>();
            if (isFolder)
            {
                status.Text = "Looking for programs working in the folder…";
                List<ProcInfo> live = new List<ProcInfo>(monitor.Processes).FindAll(p => p.Alive);
                working = await Task.Run(() => FileLocks.WorkingInside(target, live));
                if (IsDisposed) return;
                ShowResults(working, null);
            }

            var started = DateTime.UtcNow;
            int fileCount = 0;
            string checking = null;
            var ticker = new Timer { Interval = 1000 };
            ticker.Tick += (s, e) =>
            {
                if (checking != null && !IsDisposed) status.Text = Prefix(working) + checking + $" {DateTime.UtcNow - started:m\\:ss}";
            };
            ticker.Start();
            List<FileHolder> holders;
            string summary;
            try
            {
                bool truncated = false;
                List<string> files = await Task.Run(() => FileLocks.FilesOf(target, out truncated));
                fileCount = files.Count;
                checking = !isFolder ? "Checking…" : $"Checking {fileCount:N0} files, which can take minutes for a big folder…";
                status.Text = Prefix(working) + checking;
                holders = files.Count > 0 ? await Task.Run(() => FileLocks.Find(files)) : new List<FileHolder>();
                foreach (FileHolder holder in working)
                    if (!holders.Exists(h => h.Pid == holder.Pid)) holders.Add(holder);
                string found = holders.Count == 0 ? "No running program has it open"
                    : holders.Count == 1 ? "1 program has it open" : $"{holders.Count} programs have it open";
                summary = !isFolder ? found + "."
                    : $"{found}, checking {fileCount:N0} files" + (truncated ? $": the folder has more, and only the first {FileLocks.MaxFiles:N0} were checked." : ".");
            }
            catch (Win32Exception e)
            {
                // What was found working in the folder still stands.
                holders = working;
                summary = Prefix(working) + "Windows could not check the files: " + e.Message;
            }
            finally
            {
                ticker.Dispose();
                searching = false;
            }
            if (IsDisposed) return;
            ShowResults(holders, summary);
        }

        private static string Prefix(List<FileHolder> working) =>
            working.Count == 0 ? "" : working.Count == 1 ? "1 program is working in the folder. " : $"{working.Count} programs are working in the folder. ";

        /// <param name="summary">The finished search's summary, or null while files are still being checked.</param>
        private void ShowResults(List<FileHolder> holders, string summary)
        {
            list.BeginUpdate();
            list.Items.Clear();
            foreach (FileHolder holder in holders)
            {
                // The process as the main window knows it, unless it started after the latest sample.
                ProcInfo p = monitor.FindLive(holder.Pid);
                if (p != null && p.CreateTime != holder.StartTime) p = null;
                var item = new ListViewItem(p?.DisplayName ?? holder.AppName, icons.GetSmallIndex(p?.Path)) { Tag = p };
                item.SubItems.Add(holder.Pid.ToString());
                item.SubItems.Add(holder.Kind);
                item.SubItems.Add(p?.Details ?? "");
                item.SubItems.Add(p?.Path ?? "");
                item.ForeColor = theme.WindowText;
                list.Items.Add(item);
            }
            list.EndUpdate();
            if (list.Items.Count > 0) list.Items[0].Selected = true;
            if (summary == null)
            {
                UpdateButtons();
                return;
            }

            // Without administrator rights, the Restart Manager cannot see into elevated programs and
            // other users' processes.
            bool limited = holders.Count == 0 && !FileLocks.IsElevated && !summary.StartsWith("There is no", StringComparison.Ordinal);
            status.Text = summary + (limited ? " Programs running as administrator or as another user may only be found when this runs as administrator." : "");
            elevate.Visible = limited && restartElevated != null;
            UpdateButtons();
        }
    }
}
