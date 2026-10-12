// Discovery.cs — locate the WMPF browser process, load version offsets, and
// inject the hook DLL (classic CreateRemoteThread + LoadLibraryW).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace WxmpStorageDumper
{
    internal sealed class WmpfProcess
    {
        public int Pid;
        public string CommandLine;
        public int FlueVersion;
    }

    internal static class Discovery
    {
        /// <summary>
        /// Find the WMPF browser process: WeChatAppEx.exe carrying
        /// --flue-runtime-dir and no renderer --type= switch.
        /// </summary>
        public static WmpfProcess FindBrowserProcess(Action<string> log)
        {
            var procs = new List<WmpfProcess>();
            using (var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name='WeChatAppEx.exe'"))
            {
                foreach (var o in searcher.Get())
                {
                    using (o)
                    {
                        procs.Add(new WmpfProcess
                        {
                            Pid = Convert.ToInt32(o["ProcessId"]),
                            CommandLine = o["CommandLine"] as string ?? ""
                        });
                    }
                }
            }

            if (procs.Count == 0)
                throw new InvalidOperationException(
                    "No WeChatAppEx.exe found. Start WeChat (4.x) and open any mini program first.");

            WmpfProcess browser = null;
            foreach (var p in procs)
                if (p.CommandLine.Contains("--flue-runtime-dir") && !p.CommandLine.Contains("--type="))
                {
                    browser = p;
                    break;
                }
            if (browser == null)
                foreach (var p in procs)
                    if (p.CommandLine.Contains("--flue-runtime-dir"))
                    {
                        browser = p;
                        break;
                    }
            if (browser == null)
            {
                log("[discover] no browser process matched; is a mini program open?");
                throw new InvalidOperationException(
                    "No WMPF browser process (WeChatAppEx.exe with --flue-runtime-dir) found.");
            }

            browser.FlueVersion = ParseFlueVersion(browser.CommandLine);
            return browser;
        }

        public static int ParseFlueVersion(string commandLine)
        {
            var m = Regex.Match(commandLine, @"--flue-runtime-dir[=\s]+""?([^""\s]+)");
            if (!m.Success) return 0;
            var runs = Regex.Matches(m.Groups[1].Value, @"\d+");
            if (runs.Count == 0) return 0;
            return int.Parse(runs[runs.Count - 1].Value);
        }
    }

    // ------------------------------------------------------------- offsets ---

    internal sealed class Offsets
    {
        public int Version;
        public string LoadStart;      // "0x...."
        public string CdpFilter;
        public string CastToJson;     // null when absent (legacy CDP filter)
        public bool Modern;
        public long[] LaunchCfg;      // modern [3]
        public long[] RemoteDbg;      // modern [2]
        public long SceneOffset;
        public long WsUrlOffset;
        public long RemoteModeOffset;
        public long[] LegacyChain;    // legacy [6]

        private static readonly HttpClient Http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15)
        };

        public static Offsets Load(int version, Action<string> log)
        {
            string json = null;

            // 1) embedded copy of the WMPFDebugger offset table
            string resource = "offsets.addresses." + version + ".json";
            var asm = Assembly.GetExecutingAssembly();
            using (var s = asm.GetManifestResourceStream(resource))
            {
                if (s != null)
                {
                    using (var r = new StreamReader(s, Encoding.UTF8))
                        json = r.ReadToEnd();
                    log($"[offsets] {resource} (embedded)");
                }
            }

            // 2) upstream fetch for unknown versions
            if (json == null)
            {
                string url =
                    "https://raw.githubusercontent.com/evi0s/WMPFDebugger/master/frida/config/win32/" +
                    "addresses." + version + ".json";
                log($"[offsets] not embedded; fetching {url}");
                try
                {
                    json = Http.GetStringAsync(url).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException(
                        $"No offsets for WMPF {version} and upstream fetch failed: {ex.Message}");
                }
            }

            return Parse(json, version);
        }

        private static long[] ToLongArray(object arr)
        {
            var list = arr as System.Collections.ArrayList;
            if (list == null) return null;
            var outArr = new long[list.Count];
            for (int i = 0; i < list.Count; i++)
                outArr[i] = Convert.ToInt64(list[i]);
            return outArr;
        }

        public static Offsets Parse(string json, int fallbackVersion)
        {
            var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
            var dict = serializer.Deserialize<Dictionary<string, object>>(json);

            var off = new Offsets
            {
                Version = dict.ContainsKey("Version")
                    ? Convert.ToInt32(dict["Version"])
                    : fallbackVersion,
                LoadStart = dict["LoadStartHookOffset"] as string,
                CdpFilter = dict["CDPFilterHookOffset"] as string,
                CastToJson = dict.ContainsKey("CastToJsonHookOffset")
                    ? dict["CastToJsonHookOffset"] as string
                    : null
            };

            if (dict.ContainsKey("MiniAppConfigStructOffsets"))
            {
                var s = (Dictionary<string, object>)dict["MiniAppConfigStructOffsets"];
                off.Modern = true;
                off.LaunchCfg = ToLongArray(s["LaunchConfigOffsets"]);
                off.RemoteDbg = ToLongArray(s["RemoteDebugConfigOffsets"]);
                off.SceneOffset = Convert.ToInt64(s["SceneOffset"]);
                off.WsUrlOffset = Convert.ToInt64(s["WebSocketURLStringOffset"]);
                off.RemoteModeOffset = Convert.ToInt64(s["RemoteDebugModeOffset"]);
            }
            else if (dict.ContainsKey("SceneOffsets"))
            {
                off.Modern = false;
                off.LegacyChain = ToLongArray(dict["SceneOffsets"]);
            }
            else
            {
                throw new InvalidOperationException("offsets JSON has neither modern nor legacy layout");
            }
            return off;
        }

        /// <summary>Render the flat ini the hook DLL reads on every launch.</summary>
        public string ToIni(string listenUrl)
        {
            var sb = new StringBuilder();
            sb.AppendLine("listenUrl=" + listenUrl);
            sb.AppendLine("loadStart=" + LoadStart);
            sb.AppendLine("cdpFilter=" + CdpFilter);
            if (!string.IsNullOrEmpty(CastToJson))
                sb.AppendLine("castToJson=" + CastToJson);
            if (Modern)
            {
                sb.AppendLine("mode=modern");
                sb.AppendLine("launchCfg=" + string.Join(",", LaunchCfg));
                sb.AppendLine("remoteDbg=" + string.Join(",", RemoteDbg));
                sb.AppendLine("sceneOffset=" + SceneOffset);
                sb.AppendLine("wsUrlOffset=" + WsUrlOffset);
                sb.AppendLine("remoteModeOffset=" + RemoteModeOffset);
            }
            else
            {
                sb.AppendLine("mode=legacy");
                sb.AppendLine("sceneChain=" + string.Join(",", LegacyChain));
            }
            return sb.ToString();
        }
    }

    // ------------------------------------------------------------ injector ---

    internal static class Injector
    {
        // PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        // PROCESS_QUERY_INFORMATION — note VM_WRITE is 0x0020, not DUP_HANDLE.
        private const uint ProcessAccess = 0x0002 | 0x0008 | 0x0020 | 0x0400;
        private const uint MemCommitReserve = 0x3000;
        private const uint PageReadWrite = 0x04;
        private const uint MemRelease = 0x8000;
        private const uint Infinite = 0xFFFFFFFF;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr,
            UIntPtr size, uint allocType, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProc, IntPtr addr,
            byte[] buf, UIntPtr size, out UIntPtr written);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProc,
            IntPtr attrs, UIntPtr stackSize, IntPtr startAddr,
            IntPtr param, uint flags, out uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint ms);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeThread(IntPtr thread, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFreeEx(IntPtr hProc, IntPtr addr,
            UIntPtr size, uint freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string name);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string proc);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModulesEx(IntPtr hProc,
            [Out] IntPtr[] modules, uint cb, out uint needed, uint filterFlag);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleBaseName(IntPtr hProc, IntPtr module,
            StringBuilder baseName, uint size);

        private const uint ListModulesAll = 0x03;

        /// <summary>True when a module with this file name is already mapped.</summary>
        public static bool IsModuleLoaded(int pid, string moduleFileName)
        {
            // EnumProcessModulesEx wants QUERY_INFORMATION | VM_READ.
            var hProc = OpenProcess(0x0400 | 0x0010, false, pid);
            if (hProc == IntPtr.Zero) return false;
            try
            {
                var modules = new IntPtr[1024];
                uint needed;
                if (!EnumProcessModulesEx(hProc, modules,
                    (uint)(IntPtr.Size * modules.Length), out needed, ListModulesAll))
                    return false;
                int count = (int)(needed / (uint)IntPtr.Size);
                var name = new StringBuilder(260);
                for (int i = 0; i < count && i < modules.Length; i++)
                {
                    name.Length = 0;
                    if (GetModuleBaseName(hProc, modules[i], name, 260) > 0)
                        if (string.Equals(name.ToString(), moduleFileName,
                            StringComparison.OrdinalIgnoreCase))
                            return true;
                }
                return false;
            }
            finally
            {
                CloseHandle(hProc);
            }
        }

        /// <summary>Inject via CreateRemoteThread(LoadLibraryW). Returns remote HMODULE (low 32 bits).</summary>
        public static uint Inject(int pid, string dllPath, Action<string> log)
        {
            if (!File.Exists(dllPath))
                throw new FileNotFoundException("hook DLL not found", dllPath);
            dllPath = Path.GetFullPath(dllPath);

            var hProc = OpenProcess(ProcessAccess, false, pid);
            if (hProc == IntPtr.Zero)
                throw new InvalidOperationException(
                    "OpenProcess failed err=" + Marshal.GetLastWin32Error());

            IntPtr remote = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;
            try
            {
                byte[] payload = Encoding.Unicode.GetBytes(dllPath + '\0');
                var size = (UIntPtr)payload.Length;
                remote = VirtualAllocEx(hProc, IntPtr.Zero, size, MemCommitReserve, PageReadWrite);
                if (remote == IntPtr.Zero)
                    throw new InvalidOperationException(
                        "VirtualAllocEx failed err=" + Marshal.GetLastWin32Error());

                if (!WriteProcessMemory(hProc, remote, payload, size, out var written) ||
                    written.ToUInt64() != (ulong)payload.Length)
                    throw new InvalidOperationException(
                        "WriteProcessMemory failed err=" + Marshal.GetLastWin32Error());

                var kernel32 = GetModuleHandle("kernel32.dll");
                var loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
                if (loadLibrary == IntPtr.Zero)
                    throw new InvalidOperationException("GetProcAddress(LoadLibraryW) failed");

                hThread = CreateRemoteThread(hProc, IntPtr.Zero, UIntPtr.Zero,
                    loadLibrary, remote, 0, out var tid);
                if (hThread == IntPtr.Zero)
                    throw new InvalidOperationException(
                        "CreateRemoteThread failed err=" + Marshal.GetLastWin32Error());

                WaitForSingleObject(hThread, Infinite);
                GetExitCodeThread(hThread, out uint exitCode);
                if (exitCode == 0)
                    throw new InvalidOperationException(
                        "LoadLibraryW returned NULL in target (remote HMODULE=0)");
                log($"[inject] remote HMODULE=0x{exitCode:X} into pid {pid}");
                return exitCode;
            }
            finally
            {
                if (hThread != IntPtr.Zero) CloseHandle(hThread);
                if (remote != IntPtr.Zero)
                    VirtualFreeEx(hProc, remote, UIntPtr.Zero, MemRelease);
                CloseHandle(hProc);
            }
        }

        /// <summary>
        /// Extract the embedded, versioned hook DLL next to previous runs and
        /// inject it unless that exact file name is already mapped.
        /// </summary>
        public static string EnsureInjected(int pid, Action<string> log)
        {
            var asm = Assembly.GetExecutingAssembly();
            string resource = null;
            foreach (var name in asm.GetManifestResourceNames())
                if (name.StartsWith("hook.wmpf-hook-") && name.EndsWith(".dll"))
                {
                    resource = name;
                    break;
                }
            if (resource == null)
                throw new InvalidOperationException(
                    "no embedded hook DLL (build native\\wmpf-hook first, see build-all.cmd)");

            string fileName = resource.Substring("hook.".Length); // wmpf-hook-<ver>.dll
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "wxmp-storage-dumper");
            Directory.CreateDirectory(dir);
            string dllPath = Path.Combine(dir, fileName);

            // Never overwrite a possibly-mapped image: a file that is being
            // executed is locked, and same-name implies same build anyway
            // (the version is part of the file name).
            if (!File.Exists(dllPath) ||
                new FileInfo(dllPath).Length != GetResourceLength(asm, resource))
            {
                using (var input = asm.GetManifestResourceStream(resource))
                using (var output = File.Create(dllPath))
                {
                    input.CopyTo(output);
                }
            }
            log($"[inject] hook DLL: {dllPath}");

            if (Injector.IsModuleLoaded(pid, fileName))
            {
                log($"[inject] {fileName} already loaded in pid {pid} — skipping reinjection");
                return dllPath;
            }

            Inject(pid, dllPath, log);
            return dllPath;
        }

        private static long GetResourceLength(Assembly asm, string resource)
        {
            using (var s = asm.GetManifestResourceStream(resource))
                return s?.Length ?? -1;
        }
    }
}
