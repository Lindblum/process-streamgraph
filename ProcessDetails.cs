using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace ProcessStreamgraph
{
    /// <summary>A Windows service hosted by a process.</summary>
    internal sealed class ServiceInfo
    {
        public string Name;             // the service's key name, such as "Audiosrv"
        public string DisplayName;      // such as "Windows Audio"
    }

    /// <summary>
    /// What a process is doing, as far as its command line says: the clues that tell apart processes
    /// running the same program, such as a browser's page renderers, GPU process and network service,
    /// or the scripts that copies of node.exe and python.exe are running.
    /// </summary>
    internal static class ProcessRoles
    {
        // Programs built on Chromium (browsers, and Electron and CEF apps) start their helper processes
        // with --type, and utility processes also with the service they run.
        private static readonly Regex ChromiumType = new Regex(@"(?:^|\s)""?--type=([\w-]+)", RegexOptions.Compiled);
        private static readonly Regex UtilitySubType = new Regex(@"--utility-sub-type=([\w.]+)", RegexOptions.Compiled);
        private static readonly Regex WebViewHost = new Regex(@"--webview-exe-name=([^\s""]+)", RegexOptions.Compiled);
        private static readonly Regex ComServer = new Regex(@"/Processid:(\{[0-9A-Fa-f-]{36}\})", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private const string PageRenderer = "Page renderer";

        private static readonly Dictionary<string, string> UtilityServices = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["network.mojom.NetworkService"] = "Network service",
            ["storage.mojom.StorageService"] = "Storage service",
            ["audio.mojom.AudioService"] = "Audio service",
            ["video_capture.mojom.VideoCaptureService"] = "Camera service",
            ["device.mojom.XRDeviceService"] = "VR headset service",
            ["node.mojom.NodeService"] = "Node.js service",
            ["data_decoder.mojom.DataDecoderService"] = "Data decoder",
            ["chrome.mojom.UtilWin"] = "Windows helper",
            ["proxy_resolver.mojom.ProxyResolverFactory"] = "Proxy resolver",
            ["printing.mojom.PrintBackendService"] = "Printing service",
            ["unzip.mojom.Unzipper"] = "Unzipper",
            ["on_device_model.mojom.OnDeviceModelService"] = "On-device AI model",
            ["screen_ai.mojom.ScreenAIServiceFactory"] = "Screen reader AI",
            ["media.mojom.CdmServiceBroker"] = "Media protection (DRM)",
            ["media.mojom.MediaFoundationServiceBroker"] = "Media protection (DRM)",
            ["quarantine.mojom.Quarantine"] = "Download scanner",
        };

        // Firefox names its child processes' kind as the last argument.
        private static readonly Dictionary<string, string> FirefoxKinds = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["tab"] = PageRenderer, ["gpu"] = "GPU process", ["rdd"] = "Media decoder", ["socket"] = "Network service",
            ["utility"] = "Utility", ["gmplugin"] = "Media plugin", ["forkserver"] = "Process launcher",
        };

        private static readonly HashSet<string> ScriptExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".js", ".mjs", ".cjs", ".ts", ".py", ".pyw", ".ps1", ".bat", ".cmd", ".vbs", ".jar", ".rb", ".pl", ".php", ".lua"
        };

        /// <summary>A Chromium-style helper process: one started with --type.</summary>
        public static bool IsChromiumHelper(string commandLine) =>
            commandLine != null && ChromiumType.IsMatch(commandLine);

        // Programs Windows runs once per sign-in session; their copies differ only in the session.
        private static readonly HashSet<string> PerSession = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "csrss.exe", "winlogon.exe", "dwm.exe", "fontdrvhost.exe", "LogonUI.exe"
        };

        // Programs that run a script or tool named as their first argument, whatever its extension.
        private static readonly HashSet<string> Interpreters = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "python", "pythonw", "py", "node", "deno", "bun", "java", "javaw", "ruby", "perl", "php", "wscript", "cscript"
        };

        // Shells, script hosts and command-line tools, whose working folder tells their copies apart.
        private static readonly HashSet<string> FolderTools = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "powershell", "pwsh", "bash", "sh", "zsh", "fish", "python", "pythonw", "py", "node", "deno", "bun",
            "java", "ruby", "perl", "php", "claude", "codex", "gemini", "git", "dotnet", "cargo", "go", "npm", "npx"
        };

        /// <summary>Whether to show the folder the process is working in: shells and command-line tools.</summary>
        public static bool ShowsFolder(string name, string commandLine) =>
            name != null && FolderTools.Contains(Path.GetFileNameWithoutExtension(name)) && !IsChromiumHelper(commandLine) &&
            // Desktop apps sharing a tool's name (such as the Claude app) start in their own folder; not telling.
            (commandLine == null || commandLine.IndexOf(@"\WindowsApps", StringComparison.OrdinalIgnoreCase) < 0);

        /// <summary>A short description of the process's part in its program, or null when nothing tells.</summary>
        public static string RoleOf(string name, string commandLine, int sessionId, ProcInfo parent)
        {
            if (name != null && PerSession.Contains(name))
                return sessionId == 0 ? "Session 0 (system services)" : "Session " + sessionId + " (signed-in user)";
            // The tree shows a console under the program it serves, but a sorted list does not.
            if (string.Equals(name, "conhost.exe", StringComparison.OrdinalIgnoreCase) && parent != null)
                return "Console for " + parent.Name + " " + parent.Pid;
            if (string.IsNullOrEmpty(commandLine)) return null;
            try
            {
                return ChromiumRole(commandLine) ?? FirefoxRole(commandLine) ?? ComRole(commandLine) ??
                       ShellRole(name, commandLine) ?? DocumentRole(commandLine);
            }
            catch (Exception)
            {
                // A command line is whatever its process was given; nothing in it should stop the sampling.
                return null;
            }
        }

        private static string ChromiumRole(string commandLine)
        {
            Match type = ChromiumType.Match(commandLine);
            Match host = WebViewHost.Match(commandLine);
            string forHost = host.Success ? " for " + host.Groups[1].Value : "";
            if (!type.Success)
                return host.Success ? "WebView2 main process" + forHost : null;

            string role;
            switch (type.Groups[1].Value)
            {
                case "renderer":
                    role = commandLine.Contains("--extension-process") ? "Extension renderer" : PageRenderer;
                    break;
                case "gpu-process": role = "GPU process"; break;
                case "crashpad-handler": role = "Crash reporter"; break;
                case "broker": role = "Sandbox broker"; break;
                case "ppapi": role = "Plugin"; break;
                case "utility":
                    Match sub = UtilitySubType.Match(commandLine);
                    role = !sub.Success ? "Utility"
                        : UtilityServices.TryGetValue(sub.Groups[1].Value, out string known) ? known
                        : Humanize(sub.Groups[1].Value);
                    break;
                default: role = Humanize(type.Groups[1].Value); break;
            }
            return role + forHost;
        }

        // "foo.mojom.PassageEmbeddingsService" -> "Passage embeddings service"; "gpu-process" -> "Gpu process".
        private static string Humanize(string id)
        {
            string last = id.Substring(id.LastIndexOf('.') + 1).Replace('-', ' ').Replace('_', ' ');
            string spaced = Regex.Replace(last, @"(?<=[a-z0-9])(?=[A-Z])", " ").ToLowerInvariant().Trim();
            return spaced.Length == 0 ? id : char.ToUpperInvariant(spaced[0]) + spaced.Substring(1);
        }

        private static string FirefoxRole(string commandLine)
        {
            if (commandLine.IndexOf("-contentproc", StringComparison.Ordinal) < 0) return null;
            string[] args = Split(commandLine);
            return args.Length > 0 && FirefoxKinds.TryGetValue(args[args.Length - 1], out string kind) ? kind : "Content process";
        }

        // COM surrogates (dllhost.exe) name the COM server they run by its class or application ID.
        private static string ComRole(string commandLine)
        {
            Match id = ComServer.Match(commandLine);
            if (!id.Success) return null;
            string guid = id.Groups[1].Value;
            string name = RegistryDefault(@"AppID\" + guid) ?? RegistryDefault(@"CLSID\" + guid);
            return "COM server: " + (string.IsNullOrWhiteSpace(name) ? guid : name);
        }

        private static string RegistryDefault(string key)
        {
            using (RegistryKey k = Registry.ClassesRoot.OpenSubKey(key))
                return k?.GetValue(null) as string;
        }

        // Shells and script hosts: the command or script they were given.
        private static string ShellRole(string name, string commandLine)
        {
            string[] args = Split(commandLine);
            string program = Path.GetFileNameWithoutExtension(name ?? "").ToLowerInvariant();
            if (program == "cmd")
            {
                for (int i = 1; i < args.Length; i++)
                    if (args[i].Equals("/c", StringComparison.OrdinalIgnoreCase) || args[i].Equals("/k", StringComparison.OrdinalIgnoreCase))
                        return Shorten("Running: " + string.Join(" ", args, i + 1, args.Length - i - 1));
                return null;
            }
            if (program == "powershell" || program == "pwsh")
            {
                for (int i = 1; i < args.Length - 1; i++)
                {
                    string a = args[i].ToLowerInvariant();
                    if (a == "-file" || a == "-f") return Path.GetFileName(args[i + 1]);
                    if (a == "-command" || a == "-c") return Shorten("Running: " + string.Join(" ", args, i + 1, args.Length - i - 1));
                    if (a.StartsWith("-enc")) return "Running an encoded command";
                }
                return null;
            }

            // A script handed to an interpreter (node, python, Electron's own node mode and so on), with
            // the plain words after it, which are usually its subcommand: "vite.js preview".
            bool interpreter = Interpreters.Contains(program);
            for (int i = 1; i < args.Length; i++)
            {
                string a = args[i];
                if (a.StartsWith("-") || a.StartsWith("/")) continue;
                string extension = SafeExtension(a);
                bool script = interpreter || ScriptExtensions.Contains(extension) ||
                              (extension.Length == 0 && (a.Contains("\\") || a.Contains("/")) && !Directory.Exists(a));
                if (!script) continue;
                var text = new StringBuilder(SafeFileName(a));
                for (int j = i + 1; j < args.Length && j <= i + 3; j++)
                {
                    if (args[j].StartsWith("-") || args[j].Contains("\\") || args[j].Contains("/") || args[j].Contains("=")) break;
                    text.Append(' ').Append(args[j]);
                }
                return Shorten(text.ToString());
            }
            return null;
        }

        // A document the program was asked to open: the last argument naming a file.
        private static string DocumentRole(string commandLine)
        {
            string[] args = Split(commandLine);
            for (int i = args.Length - 1; i >= 1; i--)
            {
                string a = args[i];
                if (a.StartsWith("-") || a.StartsWith("/") || a.Contains("=")) continue;
                if (!(a.Contains("\\") || a.Contains("/"))) continue;
                string extension = SafeExtension(a);
                if (extension.Length < 2 || extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                    extension.Equals(".dll", StringComparison.OrdinalIgnoreCase)) continue;
                return SafeFileName(a);
            }
            return null;
        }

        private static string SafeExtension(string path)
        {
            try { return Path.GetExtension(path) ?? ""; }
            catch (ArgumentException) { return ""; }
        }

        private static string SafeFileName(string path)
        {
            try { return Path.GetFileName(path.TrimEnd('\\', '/')); }
            catch (ArgumentException) { return path; }
        }

        private static string Shorten(string text) => text.Length <= 80 ? text : text.Substring(0, 79) + "…";

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        /// <summary>A command line split into arguments by the usual Windows rules.</summary>
        private static string[] Split(string commandLine)
        {
            IntPtr argv = CommandLineToArgvW(commandLine, out int count);
            if (argv == IntPtr.Zero) return new string[0];
            try
            {
                var args = new string[count];
                for (int i = 0; i < count; i++)
                    args[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size));
                return args;
            }
            finally
            {
                LocalFree(argv);
            }
        }
    }

    /// <summary>
    /// The names Task Manager gives processes: the description in the program file's version
    /// information ("Brave Browser", "Console Window Host"), and for service hosts the service they run.
    /// </summary>
    internal static class AppNames
    {
        // By program path; many processes share a program, and reading the version information means
        // opening the file.
        private static readonly Dictionary<string, string> descriptions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static string DisplayNameOf(ProcInfo p)
        {
            if (p.Services != null && p.Services.Length > 0 &&
                string.Equals(p.Name, "svchost.exe", StringComparison.OrdinalIgnoreCase))
            {
                return "Service Host: " + p.Services[0].DisplayName + (p.Services.Length > 1 ? " (" + p.Services.Length + ")" : "");
            }
            string description = Description(p.Path);
            return string.IsNullOrWhiteSpace(description) ? p.Name : description;
        }

        private static string Description(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            if (descriptions.TryGetValue(path, out string known)) return known;
            string description = null;
            try
            {
                description = System.Diagnostics.FileVersionInfo.GetVersionInfo(path).FileDescription?.Trim();
            }
            catch (Exception)
            {
                // Missing, locked or unreadable: the file name will do.
            }
            descriptions[path] = description;
            return description;
        }
    }

    /// <summary>The working folders of shells and command-line tools, which change as their users move about.</summary>
    internal static class WorkingFolders
    {
        private static DateTime nextRefresh;

        /// <summary>Re-reads the folders every few seconds, and at once for new processes.</summary>
        public static void Update(ProcessMonitor monitor)
        {
            DateTime now = DateTime.UtcNow;
            bool all = now >= nextRefresh;
            if (all) nextRefresh = now.AddSeconds(5);
            IEnumerable<ProcInfo> processes = all ? monitor.Processes : monitor.Added;
            foreach (ProcInfo p in processes)
            {
                if (!p.Alive || !ProcessRoles.ShowsFolder(p.Name, p.CommandLine)) continue;
                string folder = NativeMethods.GetCurrentDirectory(p.Pid);
                if (folder == null || folder == p.WorkingFolder) continue;
                p.WorkingFolder = folder;
                p.RefreshDetails();
            }
        }
    }

    /// <summary>
    /// The running Windows services and the processes hosting them, which is what tells the many
    /// copies of svchost.exe apart. Listing them takes about a millisecond; descriptions take longer
    /// and are only fetched for a tooltip.
    /// </summary>
    internal static class ServiceDirectory
    {
        private static readonly Dictionary<string, string> descriptions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static DateTime nextRefresh, busyUntil;

        /// <summary>
        /// Updates each live process's hosted services. Refreshed every 15 seconds, and every 2 while
        /// processes are starting, since a new service host registers its services a moment after it starts.
        /// </summary>
        public static void Update(ProcessMonitor monitor)
        {
            DateTime now = DateTime.UtcNow;
            if (monitor.Added.Count > 0)
            {
                busyUntil = now.AddSeconds(10);
                if (nextRefresh > now.AddSeconds(2)) nextRefresh = now;
            }
            if (now < nextRefresh) return;
            nextRefresh = now.AddSeconds(now < busyUntil ? 2 : 15);

            Dictionary<int, List<ServiceInfo>> byPid = Enumerate();
            if (byPid == null) return;
            foreach (ProcInfo p in monitor.Processes)
            {
                if (!p.Alive) continue;
                byPid.TryGetValue(p.Pid, out List<ServiceInfo> services);
                if (!SameServices(p.Services, services))
                {
                    p.Services = services?.ToArray();
                    p.RefreshDetails();
                }
            }
        }

        private static bool SameServices(ServiceInfo[] a, List<ServiceInfo> b)
        {
            int countA = a?.Length ?? 0, countB = b?.Count ?? 0;
            if (countA != countB) return false;
            for (int i = 0; i < countA; i++)
                if (a[i].Name != b[i].Name) return false;
            return true;
        }

        /// <summary>A service's description, as the Services console shows it; null when it has none.</summary>
        public static string Describe(string serviceName)
        {
            if (descriptions.TryGetValue(serviceName, out string known)) return known;
            string text = null;
            IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
            if (scm != IntPtr.Zero)
            {
                IntPtr service = OpenService(scm, serviceName, SERVICE_QUERY_CONFIG);
                if (service != IntPtr.Zero)
                {
                    QueryServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, IntPtr.Zero, 0, out int needed);
                    if (needed > 0)
                    {
                        IntPtr buffer = Marshal.AllocHGlobal(needed);
                        try
                        {
                            if (QueryServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, buffer, needed, out needed))
                            {
                                IntPtr chars = Marshal.ReadIntPtr(buffer);
                                if (chars != IntPtr.Zero) text = Marshal.PtrToStringUni(chars)?.Trim();
                            }
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(buffer);
                        }
                    }
                    CloseServiceHandle(service);
                }
                CloseServiceHandle(scm);
            }
            if (string.IsNullOrEmpty(text)) text = null;
            descriptions[serviceName] = text;
            return text;
        }

        private static Dictionary<int, List<ServiceInfo>> Enumerate()
        {
            IntPtr scm = OpenSCManager(null, null, SC_MANAGER_ENUMERATE_SERVICE);
            if (scm == IntPtr.Zero) return null;
            IntPtr buffer = IntPtr.Zero;
            try
            {
                int resume = 0;
                EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, IntPtr.Zero, 0,
                                     out int needed, out int count, ref resume, null);
                if (needed == 0) return null;
                // Room to spare, in case a service starts between the two calls.
                int size = needed + 4096;
                buffer = Marshal.AllocHGlobal(size);
                resume = 0;
                if (!EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, buffer, size,
                                          out needed, out count, ref resume, null))
                    return null;

                var byPid = new Dictionary<int, List<ServiceInfo>>();
                int stride = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESS>();
                for (int i = 0; i < count; i++)
                {
                    var entry = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESS>(IntPtr.Add(buffer, i * stride));
                    if (entry.ProcessId == 0) continue;
                    var service = new ServiceInfo
                    {
                        Name = Marshal.PtrToStringUni(entry.ServiceName),
                        DisplayName = Marshal.PtrToStringUni(entry.DisplayName),
                    };
                    // Per-user services carry a suffix such as "_4b2c1" on both names; it means nothing to a reader.
                    int underscore = service.Name.LastIndexOf('_');
                    if (underscore > 0)
                    {
                        string suffix = service.Name.Substring(underscore);
                        if (service.DisplayName.EndsWith(suffix, StringComparison.Ordinal))
                            service.DisplayName = service.DisplayName.Substring(0, service.DisplayName.Length - suffix.Length);
                    }
                    if (!byPid.TryGetValue(entry.ProcessId, out List<ServiceInfo> list))
                        byPid[entry.ProcessId] = list = new List<ServiceInfo>();
                    list.Add(service);
                }
                foreach (List<ServiceInfo> list in byPid.Values)
                    list.Sort((a, b) => string.Compare(a.DisplayName, b.DisplayName, StringComparison.CurrentCultureIgnoreCase));
                return byPid;
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                CloseServiceHandle(scm);
            }
        }

        private const int SC_MANAGER_CONNECT = 0x1, SC_MANAGER_ENUMERATE_SERVICE = 0x4, SERVICE_QUERY_CONFIG = 0x1;
        private const int SC_ENUM_PROCESS_INFO = 0, SERVICE_WIN32 = 0x30, SERVICE_ACTIVE = 1, SERVICE_CONFIG_DESCRIPTION = 1;

        [StructLayout(LayoutKind.Sequential)]
        private struct ENUM_SERVICE_STATUS_PROCESS
        {
            public IntPtr ServiceName, DisplayName;
            public int ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode,
                       CheckPoint, WaitHint, ProcessId, ServiceFlags;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string machine, string database, int access);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr scm, string name, int access);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool EnumServicesStatusEx(IntPtr scm, int level, int type, int state, IntPtr buffer, int size,
                                                        out int needed, out int count, ref int resume, string group);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryServiceConfig2(IntPtr service, int level, IntPtr buffer, int size, out int needed);

        [DllImport("advapi32.dll")]
        private static extern bool CloseServiceHandle(IntPtr handle);
    }
}
