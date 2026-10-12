// CdpClient.cs — CDP request/response multiplexer over the debug WebSocket,
// plus the storage-extraction probes.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace WxmpStorageDumper
{
    internal sealed class CdpResponse
    {
        public int Id;
        public Dictionary<string, object> Result;
        public string ErrorMessage;
    }

    internal sealed class CdpClient : IDisposable
    {
        private readonly WsServer _ws;
        private readonly bool _verbose;
        private readonly Action<string> _log;
        private readonly ConcurrentDictionary<int, TaskCompletionSource<CdpResponse>> _pending =
            new ConcurrentDictionary<int, TaskCompletionSource<CdpResponse>>();
        // Execution contexts announced by Runtime.executionContextCreated events.
        private readonly ConcurrentDictionary<int, byte> _eventContexts =
            new ConcurrentDictionary<int, byte>();
        // contextId -> what the probe expression returned there (for diagnostics).
        private readonly ConcurrentDictionary<int, string> _observed =
            new ConcurrentDictionary<int, string>();
        private readonly System.Web.Script.Serialization.JavaScriptSerializer _json =
            new System.Web.Script.Serialization.JavaScriptSerializer();
        private Thread _pump;
        private volatile bool _disposed;
        private uint _seq;
        private long _sent;
        private long _matched;
        private long _events;
        private int _anomalies;

        public CdpClient(WsServer ws, bool verbose, Action<string> log)
        {
            _ws = ws;
            _verbose = verbose;
            _log = log;
            _json.MaxJsonLength = 16 * 1024 * 1024;
            _pump = new Thread(PumpLoop) { IsBackground = true };
            _pump.Start();
        }

        private void PumpLoop()
        {
            while (!_disposed)
            {
                if (!_ws.WaitForMessage(out var frame, 500))
                    continue;
                string payloadJson = DebugProtocol.TryExtractCdpResponse(frame, _verbose, _log);
                if (payloadJson == null)
                    continue;
                Dictionary<string, object> msg;
                try
                {
                    msg = _json.Deserialize<Dictionary<string, object>>(payloadJson);
                }
                catch
                {
                    Anomaly($"non-JSON payload: {Trunc(payloadJson)}");
                    continue;
                }
                if (msg == null) continue;

                // CDP *events* (Runtime.executionContextCreated etc.) have no id.
                if (msg.ContainsKey("method"))
                {
                    HandleEvent(msg);
                    continue;
                }

                if (!msg.ContainsKey("id"))
                {
                    Anomaly($"message with neither id nor method: {Trunc(payloadJson)}");
                    continue;
                }
                int id = Convert.ToInt32(msg["id"]);
                if (_pending.TryRemove(id, out var tcs))
                {
                    Interlocked.Increment(ref _matched);
                    var resp = new CdpResponse { Id = id, Result = msg };
                    if (msg.ContainsKey("error"))
                    {
                        var err = msg["error"] as Dictionary<string, object>;
                        resp.ErrorMessage = err != null && err.ContainsKey("message")
                            ? err["message"].ToString()
                            : "CDP error";
                    }
                    tcs.TrySetResult(resp);
                }
                else if (_verbose)
                {
                    _log($"[cdp] unmatched response id={id}");
                }
            }
        }

        private void HandleEvent(Dictionary<string, object> msg)
        {
            Interlocked.Increment(ref _events);
            string method = msg["method"]?.ToString();
            if (method == "Runtime.executionContextCreated")
            {
                var p = msg["params"] as Dictionary<string, object>;
                var ctx = p?["context"] as Dictionary<string, object>;
                if (ctx != null && ctx.ContainsKey("id"))
                {
                    int cid = Convert.ToInt32(ctx["id"]);
                    string name = ctx.ContainsKey("name") ? ctx["name"]?.ToString() : "";
                    string origin = ctx.ContainsKey("origin") ? ctx["origin"]?.ToString() : "";
                    if (_eventContexts.TryAdd(cid, 1) || _verbose)
                        _log($"[cdp] context created: id={cid} name={Trunc(name)} origin={Trunc(origin)}");
                }
            }
            else if (method == "Runtime.executionContextsCleared")
            {
                _eventContexts.Clear();
                if (_verbose) _log("[cdp] all execution contexts cleared");
            }
            else if (_verbose)
            {
                _log($"[cdp] event {method}");
            }
        }

        private void Anomaly(string detail)
        {
            int n = Interlocked.Increment(ref _anomalies);
            if (n <= 5)
                _log($"[cdp] odd message ({n}): {detail}");
        }

        private static string Trunc(string s)
        {
            if (s == null) return "";
            return s.Length <= 80 ? s : s.Substring(0, 80) + "…";
        }

        public CdpResponse Send(string method, Dictionary<string, object> parameters,
                                int timeoutMs)
        {
            if (!_ws.ClientConnected)
                throw new InvalidOperationException("debug channel not connected");
            int id = unchecked((int)(++_seq));
            var body = new Dictionary<string, object>
            {
                ["id"] = id,
                ["method"] = method,
                ["params"] = parameters ?? new Dictionary<string, object>()
            };
            string bodyJson = _json.Serialize(body);
            byte[] frame = DebugProtocol.BuildCdpFrame(_seq, bodyJson);

            var tcs = new TaskCompletionSource<CdpResponse>();
            _pending[id] = tcs;
            try
            {
                _ws.SendBinary(frame);
            }
            catch
            {
                _pending.TryRemove(id, out _);
                throw;
            }
            Interlocked.Increment(ref _sent);
            if (_verbose)
                _log($"[cdp] send #{id} {method}");

            if (!tcs.Task.Wait(timeoutMs))
            {
                _pending.TryRemove(id, out _);
                throw new TimeoutException($"CDP {method} timed out after {timeoutMs} ms");
            }
            var resp = tcs.Task.Result;
            if (resp.ErrorMessage != null)
                throw new InvalidOperationException($"CDP {method}: {resp.ErrorMessage}");
            return resp;
        }

        public string Evaluate(string expression, int contextId, int timeoutMs)
        {
            var parameters = new Dictionary<string, object>
            {
                ["expression"] = expression,
                ["returnByValue"] = true,
                ["contextId"] = contextId
            };
            var resp = Send("Runtime.evaluate", parameters, timeoutMs);
            // Runtime.evaluate → { result: { result: RemoteObject } }
            if (resp.Result == null || !resp.Result.ContainsKey("result")) return null;
            var outer = resp.Result["result"] as Dictionary<string, object>;
            if (outer == null || !outer.ContainsKey("result")) return null;
            var remote = outer["result"] as Dictionary<string, object>;
            if (remote == null || !remote.ContainsKey("value")) return null;
            return remote["value"] as string;
        }

        private const string AppserviceProbe =
            "(typeof wx !== 'undefined' && typeof wx.getStorageSync === 'function') ? 'APPCTX' : '-'";

        /// <summary>Find the mini program's appservice JS context.</summary>
        public int FindAppserviceContext()
        {
            // Standard CDP clients open with Runtime.enable; the miniapp agent
            // expects it (the reference frontend sends it as its first command),
            // and the resulting executionContextCreated events give us the real
            // context ids instead of a blind scan. Failure is non-fatal.
            try
            {
                Send("Runtime.enable", new Dictionary<string, object>(), 5000);
                _log("[cdp] Runtime.enable ok");
            }
            catch (Exception ex)
            {
                _log("[cdp] Runtime.enable failed (continuing): " + ex.Message);
            }

            for (int attempt = 0; attempt < 6; attempt++)
            {
                foreach (int contextId in CandidateContextIds())
                {
                    string value;
                    try
                    {
                        value = Evaluate(AppserviceProbe, contextId, 4000);
                    }
                    catch (Exception ex)
                    {
                        _observed[contextId] = "error: " + Short(ex.Message);
                        continue;
                    }
                    _observed[contextId] = value ?? "(no value)";
                    if (value == "APPCTX")
                    {
                        _log($"[cdp] appservice context found (contextId={contextId})");
                        return contextId;
                    }
                    if (_verbose)
                        _log($"[cdp] context {contextId} -> {value ?? "(no value)"}");
                }
                Thread.Sleep(1500);
            }
            throw new InvalidOperationException(
                "connected, but no appservice context found — " + DescribeState());
        }

        private IEnumerable<int> CandidateContextIds()
        {
            // Event-announced contexts first (these definitely exist), then a
            // numeric scan for builds that never send the events.
            var seen = new HashSet<int>();
            foreach (int id in _eventContexts.Keys.OrderBy(k => k))
                if (seen.Add(id)) yield return id;
            for (int id = 1; id <= 96; id++)
                if (seen.Add(id)) yield return id;
        }

        private string Short(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            return s.Length <= 60 ? s : s.Substring(0, 60) + "…";
        }

        private string DescribeState()
        {
            var observed = string.Join(", ", _observed
                .OrderBy(kv => kv.Key)
                .Select(kv => $"{kv.Key}={kv.Value}"));
            if (observed.Length > 400) observed = observed.Substring(0, 400) + "…";
            if (observed.Length == 0) observed = "(none)";
            var eventCtx = string.Join(",", _eventContexts.Keys.OrderBy(k => k));
            return $"sent={_sent} matched={_matched} events={_events} " +
                   $"framesIn={_ws.ReceivedFrames} announced=[{eventCtx}] " +
                   $"observed=[{observed}] " +
                   "— open the mini program's main page and retry";
        }

        /// <summary>Read appId plus the requested storage keys.</summary>
        public Dictionary<string, string> ReadStorage(int contextId, IList<string> keys)
        {
            string keysJson = _json.Serialize(keys);
            string expression =
                "JSON.stringify((function(){\n" +
                "  var r = {appId:'', values:{}};\n" +
                "  try { r.appId = wx.getAccountInfoSync().miniProgram.appId; } catch (e) {}\n" +
                "  var keys = " + keysJson + ";\n" +
                "  for (var i = 0; i < keys.length; i++) {\n" +
                "    var v = '';\n" +
                "    try { v = wx.getStorageSync(keys[i]); } catch (e) { v = 'ERROR: ' + e; }\n" +
                "    if (v === null || v === undefined) v = String(v);\n" +
                "    else if (typeof v === 'object') { try { v = JSON.stringify(v); } catch (e2) { v = String(v); } }\n" +
                "    else v = String(v);\n" +
                "    r.values[keys[i]] = v;\n" +
                "  }\n" +
                "  return r;\n" +
                "})())";

            string raw = EvaluateWithRetry(expression, contextId);
            var data = DeserializeObject(raw);
            var values = new Dictionary<string, string>();
            var stored = data.ContainsKey("values")
                ? data["values"] as Dictionary<string, object>
                : null;
            if (stored != null)
                foreach (var kv in stored)
                    values[kv.Key] = kv.Value as string ?? kv.Value?.ToString() ?? "";
            values["__appId"] = data.ContainsKey("appId") ? data["appId"] as string ?? "" : "";
            return values;
        }

        /// <summary>Dump every storage key (capped) plus the appId.</summary>
        public Dictionary<string, string> DumpStorage(int contextId)
        {
            string expression =
                "JSON.stringify((function(){\n" +
                "  var r = {appId:'', keys:[], values:{}};\n" +
                "  try { r.appId = wx.getAccountInfoSync().miniProgram.appId; } catch (e) {}\n" +
                "  try { r.keys = wx.getStorageInfoSync().keys || []; } catch (e) { r.keys = []; }\n" +
                "  for (var i = 0; i < r.keys.length && i < 300; i++) {\n" +
                "    var k = r.keys[i], v = '';\n" +
                "    try { v = wx.getStorageSync(k); } catch (e) { v = 'ERROR: ' + e; }\n" +
                "    if (v === null || v === undefined) v = String(v);\n" +
                "    else if (typeof v === 'object') { try { v = JSON.stringify(v); } catch (e2) { v = String(v); } }\n" +
                "    else v = String(v);\n" +
                "    if (v.length > 2048) v = v.substring(0, 2048) + '…';\n" +
                "    r.values[k] = v;\n" +
                "  }\n" +
                "  return r;\n" +
                "})())";

            string raw = EvaluateWithRetry(expression, contextId);
            var data = DeserializeObject(raw);
            var values = new Dictionary<string, string>();
            var stored = data.ContainsKey("values")
                ? data["values"] as Dictionary<string, object>
                : null;
            if (stored != null)
                foreach (var kv in stored)
                    values[kv.Key] = kv.Value as string ?? kv.Value?.ToString() ?? "";
            values["__appId"] = data.ContainsKey("appId") ? data["appId"] as string ?? "" : "";
            values["__keys"] = string.Join(",",
                (data.ContainsKey("keys") ? data["keys"] as System.Collections.ArrayList
                    : null) ?? new System.Collections.ArrayList());
            return values;
        }

        /// <summary>Parse an evaluate result into an object map, tolerating a
        /// JSON-string-wrapped object (double-encoded responses).</summary>
        private Dictionary<string, object> DeserializeObject(string raw)
        {
            object obj = _json.DeserializeObject(raw);
            if (obj is string s)
                obj = _json.DeserializeObject(s);
            var dict = obj as Dictionary<string, object>;
            if (dict == null)
                throw new InvalidOperationException(
                    "storage read returned unexpected shape: " + Trunc(raw));
            return dict;
        }

        private string EvaluateWithRetry(string expression, int contextId)
        {
            Exception last = null;
            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    string raw = Evaluate(expression, contextId, 10000);
                    if (raw != null) return raw;
                }
                catch (Exception ex)
                {
                    last = ex;
                }
                Thread.Sleep(2000);
            }
            throw last ?? new InvalidOperationException("storage read returned no value");
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }
}
