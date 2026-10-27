// Program.cs — wxmp-storage-dumper entry point.
//
// Flow:
//   1. find the WMPF browser process (WeChatAppEx.exe with --flue-runtime-dir)
//   2. load version offsets and write the flat hook config (%TEMP% ini)
//   3. inject the embedded wmpf-hook DLL (skipped when already mapped)
//   4. serve the debug WebSocket and wait for the mini program to connect
//   5. read storage via CDP and print appId + requested keys (or a full dump)

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace WxmpStorageDumper
{
    internal sealed class Options
    {
        public int Port = 9421;
        public List<string> Keys = new List<string> { "openId" };
        public bool Dump;
        public string AppId;
        public int TimeoutSeconds = 600;
        public bool Json;
        public int? Pid;
        public bool Verbose;
        public bool SelfTest;
        public string DetectFlue;
        public bool ShowHelp;
        public string Error;

        public static Options Parse(string[] args)
        {
            var o = new Options();
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                string Next(string flag)
                {
                    if (i + 1 >= args.Length)
                    {
                        o.Error = L10n.T(flag + " requires a value",
                                         flag + " 需要一个值");
                        return null;
                    }
                    return args[++i];
                }
                switch (a)
                {
                    case "--port":
                        if (int.TryParse(Next(a), out var p)) o.Port = p;
                        break;
                    case "--keys":
                        var v = Next(a);
                        if (v != null)
                        {
                            o.Keys.Clear();
                            foreach (var k in v.Split(','))
                                if (!string.IsNullOrWhiteSpace(k))
                                    o.Keys.Add(k.Trim());
                        }
                        break;
                    case "--dump":
                        o.Dump = true;
                        break;
                    case "--appid":
                        o.AppId = Next(a);
                        break;
                    case "--timeout":
                        if (int.TryParse(Next(a), out var t)) o.TimeoutSeconds = t;
                        break;
                    case "--json":
                        o.Json = true;
                        break;
                    case "--pid":
                        if (int.TryParse(Next(a), out var pid)) o.Pid = pid;
                        break;
                    case "--detect-flue":
                        o.DetectFlue = Next(a);
                        break;
                    case "--verbose":
                        o.Verbose = true;
                        break;
                    case "--selftest":
                        o.SelfTest = true;
                        break;
                    case "--lang":
                        var lang = Next(a);
                        if (lang != null && !L10n.TrySetLang(lang))
                            o.Error = "--lang must be zh or en";
                        break;
                    case "-h":
                    case "--help":
                        o.ShowHelp = true;
                        break;
                    default:
                        o.Error = L10n.T("unknown argument: " + a,
                                         "未知参数: " + a);
                        break;
                }
            }
            return o;
        }

        public static void PrintHelp()
        {
            Console.WriteLine(L10n.HelpText());
        }
    }

    internal static class Program
    {
        private static void Log(string message) => Console.WriteLine(message);

        private static int Main(string[] args)
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            int code;
            try
            {
                code = Run(args);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[extractor] failed: " + ex.Message);
                if (Environment.GetEnvironmentVariable("WMPF_DETECT_DEBUG") == "1")
                    Console.Error.WriteLine(ex);
                code = 1;
            }
            PauseIfWindowWouldClose();
            return code;
        }

        /// <summary>
        /// Process hosts that keep their own console open (shell, IDE, ...).
        /// Never block for those. Anything else — explorer/Win+R, unknown
        /// hosts — owns a window that would vanish the moment we exit.
        /// </summary>
        private static readonly HashSet<string> _consoleHosts =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "powershell", "pwsh", "windowsterminal", "conhost",
            "openconsole", "bash", "sh", "wsl", "ssh", "devenv", "code",
            "cursor",
        };

        private static void PauseIfWindowWouldClose()
        {
            try
            {
                if (Console.IsInputRedirected) return;
                string parent = ParentProcessName();
                if (parent.Length > 0 && _consoleHosts.Contains(parent)) return;
                Console.WriteLine();
                Console.WriteLine(L10n.T("Press any key to exit...",
                                         "按任意键退出..."));
                Console.ReadKey(true);
            }
            catch { }
        }

        /// <summary>Name of the parent process ("" when undeterminable).</summary>
        private static string ParentProcessName()
        {
            try
            {
                int pid = System.Diagnostics.Process.GetCurrentProcess().Id;
                using (var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT ParentProcessId FROM Win32_Process WHERE ProcessId=" + pid))
                {
                    foreach (System.Management.ManagementObject mo in searcher.Get())
                    {
                        int ppid = Convert.ToInt32(mo["ParentProcessId"]);
                        using (var p =
                            System.Diagnostics.Process.GetProcessById(ppid))
                            return p.ProcessName;
                    }
                }
            }
            catch { }
            return "";
        }

        private static int Run(string[] args)
        {
            var o = Options.Parse(args);
            if (o.ShowHelp)
            {
                Options.PrintHelp();
                return 0;
            }
            if (o.Error != null)
            {
                Console.Error.WriteLine("[extractor] " + o.Error);
                Options.PrintHelp();
                return 2;
            }
            if (o.SelfTest)
                return SelfTest() ? 0 : 1;

            // Hidden diagnostic: run the offset auto-detector against a
            // flue.dll file and print the upstream-shaped JSON. The result is
            // also round-tripped through Offsets.Parse, so the mode proves
            // the detection is consumable by the hook contract. No WMPF
            // process is touched.
            if (o.DetectFlue != null)
            {
                string json = Autodetect.DetectJson(o.DetectFlue);
                Offsets.Parse(json, 0);
                Console.WriteLine(json);
                return 0;
            }

            if (!Environment.Is64BitOperatingSystem)
            {
                Console.Error.WriteLine(L10n.T(
                    "[extractor] Windows x64 is required.",
                    "[extractor] 需要 Windows x64 系统。"));
                return 1;
            }

            // -- locate runtime ------------------------------------------------
            WmpfProcess process;
            if (o.Pid.HasValue)
            {
                process = new WmpfProcess { Pid = o.Pid.Value };
                Log($"[discover] using --pid {process.Pid}");
            }
            else
            {
                process = Discovery.FindBrowserProcess(Log);
            }
            Log($"[discover] browser pid={process.Pid} flue={process.FlueVersion}");

            var offsets = Offsets.Load(process.FlueVersion, Log,
                                       process.FlueRuntimeDir);

            // -- hook config + injection + WebSocket ---------------------------
            using (var server = new WsServer(o.Port, Log, o.Verbose))
            {
                string iniPath = Path.Combine(Path.GetTempPath(),
                    "wmpf-hook-" + process.Pid + ".ini");
                File.WriteAllText(iniPath,
                    offsets.ToIni("ws://127.0.0.1:" + server.Port),
                    new UTF8Encoding(false));
                Log($"[config] {iniPath} -> ws://127.0.0.1:{server.Port}");

                try
                {
                    Injector.EnsureInjected(process.Pid, Log);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("[inject] " + ex.Message);
                    return 1;
                }

                server.Start();
                Log("");
                Log(L10n.T(">>> Open the target mini program in WeChat now.",
                           ">>> 现在请在微信中打开目标小程序。"));
                Log(L10n.T(">>> (If it is already open, close it fully and reopen it.)",
                           ">>> （如果它已打开，请完全关闭后重新打开。）"));
                Log("");

                var deadline = Environment.TickCount + o.TimeoutSeconds * 1000;
                while (!server.ClientConnected)
                {
                    if (Environment.TickCount > deadline)
                    {
                        Console.Error.WriteLine(L10n.T(
                            "[extractor] timed out waiting for the mini program to connect.",
                            "[extractor] 等待小程序连接超时——请确认已按提示重新打开它。"));
                        return 1;
                    }
                    Thread.Sleep(250);
                }
                Log("[ws] mini program debug channel connected");

                // Give the appservice a moment to boot after the socket opens.
                Thread.Sleep(3000);

                using (var cdp = new CdpClient(server, o.Verbose, Log))
                {
                    int contextId = cdp.FindAppserviceContext();

                    Dictionary<string, string> values;
                    if (o.Dump)
                        values = cdp.DumpStorage(contextId);
                    else
                        values = cdp.ReadStorage(contextId, o.Keys);

                    string appId = values.TryGetValue("__appId", out var a) ? a : "";
                    values.Remove("__appId");
                    string keyList = null;
                    if (values.TryGetValue("__keys", out var kl))
                    {
                        keyList = kl;
                        values.Remove("__keys");
                    }

                    if (o.AppId != null && appId != "" && appId != o.AppId)
                    {
                        Console.Error.WriteLine(L10n.T(
                            $"[extractor] connected mini program is {appId}, expected {o.AppId}.",
                            $"[extractor] 连接到的小程序是 {appId}，与期望的 {o.AppId} 不符。"));
                        return 1;
                    }

                    Report(o, appId, values, keyList);
                }
            }
            return 0;
        }

        private static void Report(Options o, string appId,
                                   Dictionary<string, string> values, string keyList)
        {
            if (o.Json)
            {
                var sb = new StringBuilder();
                sb.Append("{\"ok\":true,\"appId\":");
                AppendJsonString(sb, appId);
                sb.Append(",\"values\":{");
                bool first = true;
                foreach (var kv in values)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    AppendJsonString(sb, kv.Key);
                    sb.Append(':');
                    AppendJsonString(sb, kv.Value);
                }
                sb.Append("}}");
                Console.WriteLine(sb.ToString());
                return;
            }

            string line = new string('─', 46);
            Console.WriteLine();
            Console.WriteLine(line);
            Console.WriteLine(L10n.T("Mini program storage", "小程序本地存储"));
            Console.WriteLine(line);
            Console.WriteLine(Pad("appId") + ": " +
                (appId == "" ? L10n.T("(unknown)", "(未知)") : appId));
            if (keyList != null)
                Console.WriteLine(Pad("keys") + ": " + keyList);
            foreach (var kv in values)
                Console.WriteLine(Pad(kv.Key) + ": " + kv.Value);
            if (values.Count == 0)
                Console.WriteLine(L10n.T("(no values)", "(无数据)"));
            Console.WriteLine(line);
        }

        private static string Pad(string key)
        {
            key = key.Length > 16 ? key.Substring(0, 16) : key;
            return key.PadRight(17);
        }

        private static void AppendJsonString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s ?? "")
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else
                            sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }

        // ---------------------------------------------------------- selftest ---

        private static bool SelfTest()
        {
            bool ok = true;
            void Check(string name, bool cond)
            {
                Console.WriteLine($"[selftest] {(cond ? "PASS" : "FAIL")} {name}");
                if (!cond) ok = false;
            }

            // Round-trip a CDP frame through encode/decode.
            byte[] frame = DebugProtocol.BuildCdpFrame(7,
                "{\"id\":7,\"method\":\"Runtime.evaluate\",\"params\":{}}");
            var decoded = DebugProtocol.DecodeDebugMessage(frame);
            Check("envelope category", decoded.Category == "chromeDevtools");
            Check("envelope seq", decoded.Seq == 7);
            string innerPayload = null;
            try
            {
                // Re-encode the inner message to inspect it.
                var inner = DebugProtocol.DecodeChromeDevtoolsResultPayload(decoded.Data);
                innerPayload = inner; // same field layout for both directions
            }
            catch { /* expected: payload field decodes as null on request msg? no */ }
            Check("inner payload roundtrip",
                innerPayload != null && innerPayload.Contains("Runtime.evaluate"));

            // Simulated response frame with zlib payload.
            string cdpResponse = "{\"id\":42,\"result\":{\"result\":{\"value\":\"APPCTX\"}}}";
            byte[] frameResp = BuildZlibResponse(42, cdpResponse);
            var msg = DebugProtocol.DecodeDebugMessage(frameResp);
            Check("zlib flag", (msg.CompressAlgo & DebugProtocol.CompressAlgoZlib) != 0);
            string extracted = DebugProtocol.TryExtractCdpResponse(frameResp, false, null);
            Check("zlib+result extraction",
                extracted != null && extracted.Contains("\"APPCTX\""));

            // Varint boundary: large seq.
            byte[] big = DebugProtocol.EncodeDebugMessage(300, "x", new byte[0], 0, 0);
            Check("varint seq 300", DebugProtocol.DecodeDebugMessage(big).Seq == 300);

            // Full loopback integration: fake miniapp client <-> real server + CDP.
            Check("ws+cdp integration", WsCdpSelfTest());

            // Parent-process lookup backs the Win+R pause decision.
            Check("parent process detection", ParentProcessName().Length > 0);

            return ok;
        }

        private static byte[] BuildZlibResponse(int id, string payload)
        {
            byte[] inner = DebugProtocol.EncodeChromeDevtools(0, payload, "");
            byte[] deflated;
            using (var ms = new MemoryStream())
            {
                using (var z = new System.IO.Compression.DeflateStream(ms,
                    System.IO.Compression.CompressionLevel.Optimal, true))
                {
                    z.Write(inner, 0, inner.Length);
                }
                byte[] raw = ms.ToArray();
                // wrap: 0x78 0x9C header + raw deflate + adler32
                using (var outMs = new MemoryStream())
                {
                    outMs.WriteByte(0x78);
                    outMs.WriteByte(0x9C);
                    outMs.Write(raw, 0, raw.Length);
                    uint adler = Adler32(inner);
                    outMs.WriteByte((byte)(adler >> 24));
                    outMs.WriteByte((byte)(adler >> 16));
                    outMs.WriteByte((byte)(adler >> 8));
                    outMs.WriteByte((byte)adler);
                    deflated = outMs.ToArray();
                }
            }
            return DebugProtocol.EncodeDebugMessage(1,
                DebugProtocol.CategoryChromeDevtoolsResult, deflated,
                DebugProtocol.CompressAlgoZlib, (uint)inner.Length);
        }

        private static uint Adler32(byte[] data)
        {
            uint a = 1, b = 0;
            foreach (byte by in data)
            {
                a = (a + by) % 65521;
                b = (b + a) % 65521;
            }
            return (b << 16) | a;
        }

        /// <summary>
        /// End-to-end loopback test: a fake miniapp client speaks RFC 6455 to
        /// the real WsServer while a real CdpClient drives it. Exercises the
        /// handshake (with a pipelined first frame), client masking, text
        /// frames, fragmentation, event capture and response correlation.
        /// Trap: evaluate reports APPCTX for context 1 AND 7, but only 7 is
        /// announced by an event — the test passes only if event-first
        /// candidate ordering works.
        /// </summary>
        private static bool WsCdpSelfTest()
        {
            try
            {
                using (var server = new WsServer(0, m => { }, false))
                {
                    server.Start();
                    var handshakeDone = new ManualResetEventSlim(false);
                    Exception clientError = null;
                    var client = new Thread(() =>
                    {
                        try { FakeMiniappClient(server.Port, handshakeDone); }
                        catch (Exception ex) { clientError = ex; }
                        finally { handshakeDone.Set(); }
                    })
                    { IsBackground = true };
                    client.Start();

                    if (!handshakeDone.Wait(10000) || clientError != null)
                    {
                        Console.WriteLine("[selftest]   ws handshake: " +
                            (clientError?.Message ?? "timeout"));
                        return false;
                    }
                    // The 101 is written just before _current is published —
                    // wait for the server side to be fully ready.
                    for (int i = 0; i < 100 && !server.ClientConnected; i++)
                        Thread.Sleep(50);
                    if (!server.ClientConnected)
                    {
                        Console.WriteLine("[selftest]   server never published the connection");
                        return false;
                    }

                    int ctx = -1;
                    Dictionary<string, string> vals = null;
                    Exception findError = null;
                    var done = new ManualResetEventSlim(false);
                    var findThread = new Thread(() =>
                    {
                        try
                        {
                            using (var cdp = new CdpClient(server, false, m => { }))
                            {
                                ctx = cdp.FindAppserviceContext();
                                vals = cdp.ReadStorage(ctx, new List<string> { "openId" });
                            }
                        }
                        catch (Exception ex) { findError = ex; }
                        finally { done.Set(); }
                    })
                    { IsBackground = true };
                    findThread.Start();

                    if (!done.Wait(30000))
                    {
                        Console.WriteLine("[selftest]   cdp flow timed out (transport broken?)");
                        return false;
                    }
                    if (findError != null)
                    {
                        Console.WriteLine("[selftest]   cdp flow: " + findError.Message);
                        return false;
                    }
                    if (ctx != 7)
                    {
                        Console.WriteLine(
                            $"[selftest]   expected event-announced context 7, got {ctx} " +
                            "(event-first ordering broken)");
                        return false;
                    }
                    string appId = null;
                    if (vals == null ||
                        !vals.TryGetValue("openId", out var openId) || openId != "TEST_OPENID" ||
                        !vals.TryGetValue("__appId", out appId) || appId != "wxTEST")
                    {
                        Console.WriteLine("[selftest]   storage read mismatch");
                        return false;
                    }
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[selftest]   ws integration: " + ex.Message);
                return false;
            }
        }

        /// <summary>Fake miniapp side of the debug channel (masked client frames).</summary>
        private static void FakeMiniappClient(int port, ManualResetEventSlim handshakeDone)
        {
            using (var tcp = new System.Net.Sockets.TcpClient("127.0.0.1", port))
            {
                tcp.NoDelay = true;
                var stream = tcp.GetStream();
                var rng = new Random(1234);
                byte[] keyBytes = new byte[16];
                rng.NextBytes(keyBytes);
                string upgrade =
                    "GET / HTTP/1.1\r\n" +
                    "Host: 127.0.0.1:" + port + "\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: " + Convert.ToBase64String(keyBytes) + "\r\n" +
                    "Sec-WebSocket-Version: 13\r\n\r\n";

                // Pipeline the first WS frame in the same write as the upgrade
                // request — exercises the server's leftover-byte handling.
                byte[] earlyEvent = WrapResultFrame(
                    BuildEventJson(7, "appservice"), ++_fakeSeq);
                byte[] reqBytes = Encoding.ASCII.GetBytes(upgrade);
                byte[] pipelined = new byte[reqBytes.Length + ClientFrameLength(earlyEvent)];
                Array.Copy(reqBytes, pipelined, reqBytes.Length);
                WriteClientFrameInto(pipelined, reqBytes.Length, 0x2, earlyEvent, rng);
                stream.Write(pipelined, 0, pipelined.Length);

                // Read the HTTP 101 response before speaking frames.
                var header = new MemoryStream();
                int prev = -1;
                while (true)
                {
                    int c = stream.ReadByte();
                    if (c < 0) throw new EndOfStreamException("closed during upgrade");
                    header.WriteByte((byte)c);
                    if (prev == '\n' && c == '\r')
                    {
                        int next = stream.ReadByte();
                        if (next < 0) throw new EndOfStreamException("closed during upgrade");
                        header.WriteByte((byte)next);
                        if (next == '\n') break;
                        prev = next;
                        continue;
                    }
                    prev = c;
                }
                string response = Encoding.ASCII.GetString(header.ToArray());
                if (!response.StartsWith("HTTP/1.1 101"))
                    throw new InvalidOperationException("bad upgrade response: " +
                        response.Substring(0, Math.Min(60, response.Length)));
                handshakeDone.Set();

                while (true)
                {
                    byte[] frame = ReadServerFrame(stream);
                    if (frame == null) return;
                    var env = DebugProtocol.DecodeDebugMessage(frame);
                    if (env.Category != DebugProtocol.CategoryChromeDevtools) continue;
                    string payload = DebugProtocol.DecodeChromeDevtoolsResultPayload(env.Data);
                    if (payload == null) continue;

                    var jss = new System.Web.Script.Serialization.JavaScriptSerializer();
                    var msg = jss.Deserialize<Dictionary<string, object>>(payload);
                    if (msg == null || !msg.ContainsKey("id")) continue;
                    int id = Convert.ToInt32(msg["id"]);
                    string method = msg["method"]?.ToString() ?? "";
                    var p = msg.ContainsKey("params")
                        ? msg["params"] as Dictionary<string, object>
                        : null;

                    if (method == "Runtime.enable")
                    {
                        // Result reply as a normal binary frame...
                        SendServerFrame(stream, 0x2, WrapResultFrame(
                            "{\"id\":" + id + ",\"result\":{}}", ++_fakeSeq));
                        // ...and a duplicate context event as a TEXT frame.
                        SendServerFrame(stream, 0x1, WrapResultFrame(
                            BuildEventJson(7, "appservice"), ++_fakeSeq));
                    }
                    else if (method == "Runtime.evaluate")
                    {
                        int contextId = p != null && p.ContainsKey("contextId")
                            ? Convert.ToInt32(p["contextId"]) : 0;
                        string expression = p?["expression"]?.ToString() ?? "";
                        if (expression.Contains("getAccountInfoSync") &&
                            !expression.Contains("return r;"))
                        {
                            // Regression guard: a double-stringifying expression
                            // makes the result a JSON *string* of an object.
                            SendServerFrame(stream, 0x2, WrapResultFrame(
                                "{\"id\":" + id +
                                ",\"error\":{\"message\":\"expression double-stringifies\"}}",
                                ++_fakeSeq));
                            continue;
                        }
                        string value;
                        if (expression.Contains("getAccountInfoSync"))
                        {
                            value = "{\"appId\":\"wxTEST\",\"values\":{\"openId\":\"TEST_OPENID\"}}";
                        }
                        else if (contextId == 1 || contextId == 7)
                        {
                            value = "APPCTX"; // trap: only event-first ordering returns 7
                        }
                        else
                        {
                            value = "-";
                        }
                        string resultJson =
                            "{\"id\":" + id + ",\"result\":{\"result\":{\"type\":\"string\"," +
                            "\"value\":" + jss.Serialize(value) + "}}}";
                        byte[] envBytes = WrapResultFrame(resultJson, ++_fakeSeq);
                        if (expression.Contains("getAccountInfoSync"))
                        {
                            // Fragmented delivery: FIN=0 binary + FIN=1 continuation.
                            int half = envBytes.Length / 2;
                            var first = new byte[half];
                            var rest = new byte[envBytes.Length - half];
                            Array.Copy(envBytes, 0, first, 0, half);
                            Array.Copy(envBytes, half, rest, 0, rest.Length);
                            SendServerFrame(stream, 0x2, first, fin: false);
                            SendServerFrame(stream, 0x0, rest, fin: true);
                        }
                        else
                        {
                            SendServerFrame(stream, 0x2, envBytes);
                        }
                    }
                    // unknown methods: reply with an empty result so no send stalls
                    else
                    {
                        SendServerFrame(stream, 0x2, WrapResultFrame(
                            "{\"id\":" + id + ",\"result\":{}}", ++_fakeSeq));
                    }
                }
            }
        }

        private static uint _fakeSeq;

        private static string BuildEventJson(int contextId, string name)
        {
            return "{\"method\":\"Runtime.executionContextCreated\",\"params\":" +
                   "{\"context\":{\"id\":" + contextId + ",\"name\":" +
                   new System.Web.Script.Serialization.JavaScriptSerializer()
                       .Serialize(name) + ",\"origin\":\"\"}}}";
        }

        private static byte[] WrapResultFrame(string cdpJson, uint seq)
        {
            byte[] inner = DebugProtocol.EncodeChromeDevtools(0, cdpJson, "");
            return DebugProtocol.EncodeDebugMessage(
                seq, DebugProtocol.CategoryChromeDevtoolsResult, inner, 0, 0);
        }

        private static int ClientFrameLength(byte[] payload)
        {
            int n = 2 + 4; // header + mask
            if (payload.Length >= 126) n += payload.Length <= ushort.MaxValue ? 2 : 8;
            return n + payload.Length;
        }

        /// <summary>Serialize a masked client frame into buffer at offset.</summary>
        private static void WriteClientFrameInto(byte[] buffer, int offset, int opcode,
                                                 byte[] payload, Random rng)
        {
            byte[] mask = new byte[4];
            rng.NextBytes(mask);
            buffer[offset] = (byte)(0x80 | opcode);
            int h = 1;
            if (payload.Length < 126)
            {
                buffer[offset + h++] = (byte)(0x80 | payload.Length);
            }
            else if (payload.Length <= ushort.MaxValue)
            {
                buffer[offset + h++] = 0x80 | 126;
                buffer[offset + h++] = (byte)(payload.Length >> 8);
                buffer[offset + h++] = (byte)payload.Length;
            }
            else
            {
                buffer[offset + h++] = 0x80 | 127;
                ulong l = (ulong)payload.Length;
                for (int i = 7; i >= 0; i--) buffer[offset + h++] = (byte)(l >> (8 * i));
            }
            Array.Copy(mask, 0, buffer, offset + h, 4);
            h += 4;
            for (int i = 0; i < payload.Length; i++)
                buffer[offset + h + i] = (byte)(payload[i] ^ mask[i % 4]);
        }

        /// <summary>Serialize a frame as the fake client sends it (unmasked; the
        /// pipelined handshake frame above covers the masked path).</summary>
        private static void SendServerFrame(Stream s, int opcode, byte[] payload, bool fin = true)
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte((byte)((fin ? 0x80 : 0) | opcode));
                if (payload.Length < 126) ms.WriteByte((byte)payload.Length);
                else if (payload.Length <= ushort.MaxValue)
                {
                    ms.WriteByte(126);
                    ms.WriteByte((byte)(payload.Length >> 8));
                    ms.WriteByte((byte)payload.Length);
                }
                else
                {
                    ms.WriteByte(127);
                    ulong l = (ulong)payload.Length;
                    for (int i = 7; i >= 0; i--) ms.WriteByte((byte)(l >> (8 * i)));
                }
                ms.Write(payload, 0, payload.Length);
                var b = ms.ToArray();
                s.Write(b, 0, b.Length);
            }
        }

        /// <summary>Read one server→client (unmasked) frame; null on close.</summary>
        private static byte[] ReadServerFrame(Stream s)
        {
            int b0 = s.ReadByte();
            if (b0 < 0) return null;
            int b1 = s.ReadByte();
            if (b1 < 0) return null;
            long len = b1 & 0x7f;
            if (len == 126)
            {
                len = (s.ReadByte() << 8) | s.ReadByte();
            }
            else if (len == 127)
            {
                len = 0;
                for (int i = 0; i < 8; i++) len = (len << 8) | (uint)s.ReadByte();
            }
            if (len < 0 || len > 64 * 1024 * 1024) return null;
            var payload = new byte[len];
            int read = 0;
            while (read < len)
            {
                int n = s.Read(payload, read, (int)len - read);
                if (n <= 0) return null;
                read += n;
            }
            return payload;
        }
    }
}
