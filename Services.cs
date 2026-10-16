using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ProcessStreamgraph
{
    internal enum ServiceCommand { Start, Stop, Pause, Resume, Restart }

    /// <summary>
    /// Starting, stopping, pausing and resuming Windows services. Each command is tried directly first,
    /// which works for the few services an ordinary user may control and for all of them when this app
    /// runs as administrator; when Windows refuses, it is run again from an elevated PowerShell, which
    /// brings up the elevation prompt.
    /// </summary>
    internal static class ServiceActions
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
        private const int ERROR_ACCESS_DENIED = 5, ERROR_CANCELLED = 1223;

        public static string Verb(ServiceCommand command) => command.ToString();

        /// <summary>The service's state as the Services console words it; null when it cannot be read.</summary>
        public static string StatusText(ServiceControllerStatus? status)
        {
            switch (status)
            {
                case ServiceControllerStatus.Running: return "Running";
                case ServiceControllerStatus.Stopped: return "Stopped";
                case ServiceControllerStatus.Paused: return "Paused";
                case ServiceControllerStatus.StartPending: return "Starting";
                case ServiceControllerStatus.StopPending: return "Stopping";
                case ServiceControllerStatus.PausePending: return "Pausing";
                case ServiceControllerStatus.ContinuePending: return "Resuming";
                default: return null;
            }
        }

        /// <summary>
        /// The service's current state and the commands it accepts in it: none while it is between
        /// states, or when it no longer exists.
        /// </summary>
        public static ServiceCommand[] Available(string serviceName, out ServiceControllerStatus? status)
        {
            status = null;
            var commands = new List<ServiceCommand>();
            try
            {
                using (var service = new ServiceController(serviceName))
                {
                    status = service.Status;
                    bool canStop = service.CanStop, canPause = service.CanPauseAndContinue;
                    switch (status)
                    {
                        case ServiceControllerStatus.Stopped:
                            commands.Add(ServiceCommand.Start);
                            break;
                        case ServiceControllerStatus.Running:
                            if (canStop) commands.Add(ServiceCommand.Stop);
                            if (canPause) commands.Add(ServiceCommand.Pause);
                            if (canStop) commands.Add(ServiceCommand.Restart);
                            break;
                        case ServiceControllerStatus.Paused:
                            if (canStop) commands.Add(ServiceCommand.Stop);
                            commands.Add(ServiceCommand.Resume);
                            if (canStop) commands.Add(ServiceCommand.Restart);
                            break;
                    }
                }
            }
            catch (InvalidOperationException)
            {
                // Gone, or not ours to query.
            }
            return commands.ToArray();
        }

        /// <summary>The display names of running services that stopping this one would also stop.</summary>
        public static string[] RunningDependents(string serviceName)
        {
            try
            {
                using (var service = new ServiceController(serviceName))
                {
                    ServiceController[] dependents = service.DependentServices;
                    try
                    {
                        return dependents.Where(d => d.Status != ServiceControllerStatus.Stopped).Select(d => d.DisplayName).ToArray();
                    }
                    finally
                    {
                        foreach (ServiceController d in dependents) d.Dispose();
                    }
                }
            }
            catch (InvalidOperationException)
            {
                return new string[0];
            }
        }

        /// <summary>Runs a command and waits for the service to settle. Returns an error message, or null.</summary>
        public static async Task<string> RunAsync(ServiceCommand command, ServiceInfo service)
        {
            (bool denied, string error) = await Task.Run(() => RunDirect(command, service.Name));
            if (!denied) return error == null ? null : Failure(command, service, error);
            error = await Task.Run(() => RunElevated(command, service.Name));
            return error == null ? null : Failure(command, service, error);
        }

        private static string Failure(ServiceCommand command, ServiceInfo service, string error) =>
            $"Could not {Verb(command).ToLowerInvariant()} {service.DisplayName} ({service.Name}): {error}";

        private static (bool denied, string error) RunDirect(ServiceCommand command, string serviceName)
        {
            using (var service = new ServiceController(serviceName))
            {
                try
                {
                    switch (command)
                    {
                        case ServiceCommand.Start:
                            service.Start();
                            service.WaitForStatus(ServiceControllerStatus.Running, Timeout);
                            break;
                        case ServiceCommand.Stop:
                            service.Stop();
                            service.WaitForStatus(ServiceControllerStatus.Stopped, Timeout);
                            break;
                        case ServiceCommand.Pause:
                            service.Pause();
                            service.WaitForStatus(ServiceControllerStatus.Paused, Timeout);
                            break;
                        case ServiceCommand.Resume:
                            service.Continue();
                            service.WaitForStatus(ServiceControllerStatus.Running, Timeout);
                            break;
                        case ServiceCommand.Restart:
                            if (service.Status != ServiceControllerStatus.Stopped)
                            {
                                service.Stop();
                                service.WaitForStatus(ServiceControllerStatus.Stopped, Timeout);
                            }
                            service.Start();
                            service.WaitForStatus(ServiceControllerStatus.Running, Timeout);
                            break;
                    }
                    return (false, null);
                }
                catch (InvalidOperationException e) when (e.InnerException is Win32Exception w && w.NativeErrorCode == ERROR_ACCESS_DENIED)
                {
                    return (true, null);
                }
                catch (InvalidOperationException e)
                {
                    return (false, e.InnerException?.Message ?? e.Message);
                }
                catch (System.ServiceProcess.TimeoutException)
                {
                    service.Refresh();
                    return (false, $"it did not finish within {Timeout.TotalSeconds:0} seconds, and is now {StatusText(service.Status)?.ToLowerInvariant() ?? "in an unknown state"}.");
                }
            }
        }

        private static string RunElevated(ServiceCommand command, string serviceName)
        {
            string cmdlet;
            switch (command)
            {
                case ServiceCommand.Start: cmdlet = "Start-Service"; break;
                // -Force also stops the services that depend on it, as the Services console does.
                case ServiceCommand.Stop: cmdlet = "Stop-Service -Force"; break;
                case ServiceCommand.Pause: cmdlet = "Suspend-Service"; break;
                case ServiceCommand.Resume: cmdlet = "Resume-Service"; break;
                default: cmdlet = "Restart-Service -Force"; break;
            }
            // An elevated process cannot hand back its output, so the error message comes back in a file.
            string errorFile = Path.Combine(Path.GetTempPath(), "ProcessStreamgraph-service-" + Guid.NewGuid().ToString("N") + ".txt");
            string script =
                "$ErrorActionPreference = 'Stop'\n" +
                $"try {{ {cmdlet} -Name {Quote(serviceName)} }}\n" +
                $"catch {{ [IO.File]::WriteAllText({Quote(errorFile)}, $_.Exception.Message); exit 1 }}";
            var start = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)))
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden
            };
            try
            {
                using (Process process = Process.Start(start))
                {
                    process.WaitForExit();
                    if (process.ExitCode == 0) return null;
                }
                string message = File.Exists(errorFile) ? File.ReadAllText(errorFile).Trim() : "";
                return message.Length > 0 ? message : "PowerShell reported an error.";
            }
            catch (Win32Exception e) when (e.NativeErrorCode == ERROR_CANCELLED)
            {
                return null;    // the elevation prompt was declined
            }
            catch (Win32Exception e)
            {
                return e.Message;
            }
            finally
            {
                try { File.Delete(errorFile); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }

        private static string Quote(string text) => "'" + text.Replace("'", "''") + "'";
    }

    /// <summary>What the Services console shows about a service, read-only.</summary>
    internal sealed class ServicePropertiesForm : Form
    {
        private readonly Theme theme;
        private readonly float scale;

        public ServicePropertiesForm(ServiceInfo info, Theme theme, int dpi, Font font)
        {
            this.theme = theme;
            scale = dpi / 96f;
            Text = info.DisplayName + " Properties";
            Font = font;
            AutoScaleMode = AutoScaleMode.None;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MinimizeBox = MaximizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            var layout = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Padding = new Padding(S(14)), Dock = DockStyle.Fill };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            void Row(string name, string value)
            {
                if (string.IsNullOrEmpty(value)) return;
                var label = new Label { Text = name, AutoSize = true, Margin = new Padding(0, S(4), S(14), S(4)), ForeColor = theme.MutedInk };
                // Read-only text boxes rather than labels, so paths and names can be selected and copied.
                var text = new TextBox
                {
                    Text = value, ReadOnly = true, BorderStyle = BorderStyle.None, Multiline = true, WordWrap = true,
                    Width = S(440), Margin = new Padding(0, S(4), 0, S(4)), TabStop = false
                };
                text.Height = TextRenderer.MeasureText(value, font, new Size(text.Width, 0), TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl).Height;
                layout.Controls.Add(label, 0, layout.RowCount);
                layout.Controls.Add(text, 1, layout.RowCount);
                layout.RowCount++;
            }

            ServiceDetails details = ServiceDetails.Read(info.Name);
            Row("Display name", info.DisplayName);
            Row("Service name", info.Name);
            Row("Description", ServiceDirectory.Describe(info.Name));
            Row("Status", details.Status);
            Row("Startup type", details.StartupType);
            Row("Service type", details.ServiceType);
            Row("Log on as", details.Account);
            Row("Path to executable", details.ImagePath);
            Row("Service DLL", details.ServiceDll);
            Row("Depends on", details.DependsOn);
            Row("Needed by", details.Dependents);

            var close = new Button { Text = "Close", DialogResult = DialogResult.Cancel, AutoSize = true, MinimumSize = new Size(S(80), 0) };
            var console = new Button { Text = "Open Services Console", AutoSize = true, MinimumSize = new Size(S(80), 0) };
            console.Click += (s, e) => SafetyDrawing.OpenLink(this, "services.msc");
            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, S(14), 0, 0) };
            buttons.Controls.AddRange(new Control[] { close, console });
            layout.Controls.Add(buttons, 0, layout.RowCount);
            layout.SetColumnSpan(buttons, 2);
            layout.RowCount++;
            AcceptButton = CancelButton = close;

            Controls.Add(layout);
            SafetyDrawing.Style(this, theme);
            // The values sit on the dialog's own background, like the labels in the Services console.
            foreach (Control control in layout.Controls)
                if (control is TextBox box) { box.BackColor = theme.Control; box.ForeColor = theme.ControlText; box.BorderStyle = BorderStyle.None; }
        }

        private int S(int pixels) => (int)(pixels * scale);

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            NativeMethods.SetDarkTitleBar(Handle, theme.IsDark);
        }

        /// <summary>A service's configuration, from the service manager and its registry key; null for what cannot be read.</summary>
        private sealed class ServiceDetails
        {
            public string Status, StartupType, ServiceType, Account, ImagePath, ServiceDll, DependsOn, Dependents;

            public static ServiceDetails Read(string name)
            {
                var details = new ServiceDetails();
                bool delayed = false;
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name))
                    {
                        if (key != null)
                        {
                            details.ImagePath = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                            details.Account = key.GetValue("ObjectName") as string;
                            delayed = key.GetValue("DelayedAutostart") is int d && d == 1;
                            using (RegistryKey parameters = key.OpenSubKey("Parameters"))
                                details.ServiceDll = parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                        }
                    }
                }
                catch (Exception e) when (e is System.Security.SecurityException || e is UnauthorizedAccessException || e is IOException)
                {
                }

                try
                {
                    using (var service = new ServiceController(name))
                    {
                        details.Status = ServiceActions.StatusText(service.Status);
                        switch (service.StartType)
                        {
                            case ServiceStartMode.Automatic: details.StartupType = delayed ? "Automatic (Delayed Start)" : "Automatic"; break;
                            case ServiceStartMode.Manual: details.StartupType = "Manual"; break;
                            case ServiceStartMode.Disabled: details.StartupType = "Disabled"; break;
                            case ServiceStartMode.Boot: details.StartupType = "Boot"; break;
                            case ServiceStartMode.System: details.StartupType = "System"; break;
                        }
                        System.ServiceProcess.ServiceType type = service.ServiceType;
                        details.ServiceType = (type & System.ServiceProcess.ServiceType.Win32ShareProcess) != 0 ? "Shares a process with other services"
                                            : (type & System.ServiceProcess.ServiceType.Win32OwnProcess) != 0 ? "Runs in its own process"
                                            : type.ToString();
                        details.DependsOn = Names(service.ServicesDependedOn);
                        details.Dependents = Names(service.DependentServices);
                    }
                }
                catch (InvalidOperationException)
                {
                }
                return details;
            }

            private static string Names(ServiceController[] services)
            {
                try
                {
                    return services.Length == 0 ? null : string.Join("\r\n", services.Select(s => s.DisplayName).OrderBy(n => n, StringComparer.CurrentCultureIgnoreCase));
                }
                finally
                {
                    foreach (ServiceController s in services) s.Dispose();
                }
            }
        }
    }
}
