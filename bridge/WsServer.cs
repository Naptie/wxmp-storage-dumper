// WsServer.cs — minimal RFC 6455 WebSocket *server* on loopback. net48 only
// ships a WebSocket client, and HttpListener's server side needs URL ACLs, so
// we speak the protocol directly over TcpListener. Just enough for one binary
// client (the mini program's remote-debug runtime), with reference-parity
// behaviour: a NEW connection replaces a stale previous one.

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace WxmpStorageDumper
{
    internal sealed class WsServer : IDisposable
    {
        private sealed class Connection
        {
            public TcpClient Tcp;
            public Stream Stream;      // possibly a PrefixStream over the raw NetworkStream
            public NetworkStream Raw;
            public volatile bool Dead;
        }

        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly ConcurrentQueue<byte[]> _inbox = new ConcurrentQueue<byte[]>();
        private readonly AutoResetEvent _inboxSignal = new AutoResetEvent(false);
        private readonly object _sendLock = new object();
        private readonly Action<string> _log;
        private readonly bool _verbose;
        private Connection _current;
        private long _received;
        private long _sent;
        private int _loggedFrames;

        public int Port { get; }
        public bool ClientConnected => _current != null && !_current.Dead;
        public long ReceivedFrames => Interlocked.Read(ref _received);
        public long SentFrames => Interlocked.Read(ref _sent);

        public WsServer(int requestedPort, Action<string> log = null, bool verbose = false)
        {
            _log = log;
            _verbose = verbose;
            _listener = new TcpListener(IPAddress.Loopback, requestedPort);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        }

        public void Start()
        {
            var t = new Thread(AcceptLoop) { IsBackground = true };
            t.Start();
        }

        private void AcceptLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient tcp;
                try
                {
                    tcp = _listener.AcceptTcpClient();
                }
                catch
                {
                    return; // listener closed
                }

                try
                {
                    tcp.NoDelay = true;
                    var raw = tcp.GetStream();
                    byte[] leftover;
                    if (!CompleteHandshake(raw, out leftover))
                    {
                        tcp.Close();
                        continue;
                    }

                    var conn = new Connection
                    {
                        Tcp = tcp,
                        Raw = raw,
                        Stream = leftover.Length > 0 ? new PrefixStream(raw, leftover) : raw
                    };

                    Connection previous;
                    lock (_sendLock)
                    {
                        previous = _current;
                        _current = conn;
                    }
                    if (previous != null && !previous.Dead)
                    {
                        _log?.Invoke("[ws] new client — closing previous (stale) connection");
                        try { previous.Tcp.Close(); } catch { }
                    }

                    var reader = new Thread(() => ReadLoop(conn)) { IsBackground = true };
                    reader.Start();
                    _log?.Invoke("[ws] client handshake complete" +
                                 (previous != null ? " (replaced previous)" : ""));
                }
                catch (Exception ex)
                {
                    _log?.Invoke("[ws] accept/handshake error: " + ex.Message);
                    try { tcp.Close(); } catch { }
                }
            }
        }

        private static readonly string WsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        private bool CompleteHandshake(NetworkStream stream, out byte[] leftover)
        {
            leftover = new byte[0];
            var buf = new byte[8192];
            int used = 0;
            int headerEnd = -1;
            while (used < buf.Length)
            {
                int n = stream.Read(buf, used, buf.Length - used);
                if (n <= 0) return false;
                used += n;
                string sofar = Encoding.ASCII.GetString(buf, 0, used);
                headerEnd = sofar.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (headerEnd >= 0) break;
            }
            if (headerEnd < 0) return false;

            string header = Encoding.ASCII.GetString(buf, 0, headerEnd);
            string key = null;
            foreach (string line in header.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.StartsWith("Sec-WebSocket-Key:", StringComparison.OrdinalIgnoreCase))
                {
                    key = line.Substring("Sec-WebSocket-Key:".Length).Trim();
                    break;
                }
            }
            if (key == null) return false;

            string accept;
            using (var sha1 = SHA1.Create())
            {
                byte[] hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(key + WsGuid));
                accept = Convert.ToBase64String(hash);
            }
            var response = Encoding.ASCII.GetBytes(
                "HTTP/1.1 101 Switching Protocols\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Accept: " + accept + "\r\n\r\n");
            stream.Write(response, 0, response.Length);

            // Bytes after the header that arrived in the same TCP read belong to
            // the frame stream — do not lose them.
            int leftStart = headerEnd + 4;
            if (used > leftStart)
            {
                leftover = new byte[used - leftStart];
                Array.Copy(buf, leftStart, leftover, 0, leftover.Length);
            }
            return true;
        }

        private void ReadLoop(Connection conn)
        {
            var stream = conn.Stream;
            MemoryStream frag = null;
            int fragOpcode = 0;
            try
            {
                while (!_cts.IsCancellationRequested && !conn.Dead)
                {
                    int b0 = stream.ReadByte();
                    if (b0 < 0) break;
                    int b1 = stream.ReadByte();
                    if (b1 < 0) break;

                    bool fin = (b0 & 0x80) != 0;
                    int opcode = b0 & 0x0f;
                    bool masked = (b1 & 0x80) != 0;
                    long len = b1 & 0x7f;
                    if (len == 126)
                    {
                        len = ((long)ReadByte(stream) << 8) | (uint)ReadByte(stream);
                    }
                    else if (len == 127)
                    {
                        len = 0;
                        for (int i = 0; i < 8; i++)
                            len = (len << 8) | (uint)ReadByte(stream);
                    }
                    if (len < 0 || len > 64 * 1024 * 1024) break;

                    byte[] mask = null;
                    if (masked)
                    {
                        mask = new byte[4];
                        for (int i = 0; i < 4; i++) mask[i] = (byte)ReadByte(stream);
                    }
                    var payload = new byte[len];
                    int read = 0;
                    while (read < len)
                    {
                        int n = stream.Read(payload, read, (int)len - read);
                        if (n <= 0) break;
                        read += n;
                    }
                    if (read != len) break;
                    if (masked)
                        for (int i = 0; i < payload.Length; i++) payload[i] ^= mask[i % 4];

                    switch (opcode)
                    {
                        case 0x0: // continuation
                            if (frag == null) { fin = true; break; } // stray — drop
                            frag.Write(payload, 0, payload.Length);
                            if (fin)
                            {
                                Deliver(frag.ToArray());
                                frag.Dispose();
                                frag = null;
                            }
                            break;
                        case 0x1: // text (payload is opaque bytes for us)
                        case 0x2: // binary
                            if (fin)
                            {
                                Deliver(payload);
                            }
                            else
                            {
                                frag = new MemoryStream();
                                frag.Write(payload, 0, payload.Length);
                                fragOpcode = opcode;
                            }
                            break;
                        case 0x8: // close
                            try { SendFrame(conn, 0x8, new byte[0]); } catch { }
                            return;
                        case 0x9: // ping -> pong
                            SendFrame(conn, 0xA, payload);
                            break;
                            // 0xA pong: ignore
                    }
                    _ = fragOpcode;
                }
            }
            catch
            {
                // connection torn down
            }
            finally
            {
                conn.Dead = true;
                frag?.Dispose();
                lock (_sendLock)
                {
                    if (ReferenceEquals(_current, conn))
                        _current = null;
                }
                try { conn.Tcp.Close(); } catch { }
                _log?.Invoke($"[ws] client disconnected (frames in={ReceivedFrames} out={SentFrames})");
            }
        }

        private void Deliver(byte[] payload)
        {
            Interlocked.Increment(ref _received);
            int n = Interlocked.Increment(ref _loggedFrames);
            if (_verbose || n <= 15 || n % 100 == 0)
                _log?.Invoke($"[recv] {payload.Length}B frame #{n}");
            _inbox.Enqueue(payload);
            _inboxSignal.Set();
        }

        private static int ReadByte(Stream s)
        {
            int b = s.ReadByte();
            if (b < 0) throw new EndOfStreamException();
            return b;
        }

        /// <summary>Wait for the next message; false on timeout/cancel.</summary>
        public bool WaitForMessage(out byte[] payload, int timeoutMs)
        {
            var deadline = Environment.TickCount + timeoutMs;
            while (true)
            {
                if (_inbox.TryDequeue(out payload)) return true;
                int remaining = deadline - Environment.TickCount;
                if (remaining <= 0 || _cts.IsCancellationRequested)
                {
                    payload = null;
                    return false;
                }
                _inboxSignal.WaitOne(Math.Min(remaining, 200));
            }
        }

        public void SendBinary(byte[] payload)
        {
            var conn = _current;
            if (conn == null || conn.Dead)
                throw new InvalidOperationException("debug channel not connected");
            SendFrame(conn, 0x2, payload);
            Interlocked.Increment(ref _sent);
        }

        private void SendFrame(Connection conn, int opcode, byte[] payload)
        {
            var stream = conn.Stream;
            if (stream == null || conn.Dead)
                throw new InvalidOperationException("debug channel closed");
            using (var ms = new MemoryStream())
            {
                ms.WriteByte((byte)(0x80 | opcode)); // FIN + opcode
                if (payload.Length < 126)
                {
                    ms.WriteByte((byte)payload.Length);
                }
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
                    for (int i = 7; i >= 0; i--)
                        ms.WriteByte((byte)(l >> (8 * i)));
                }
                ms.Write(payload, 0, payload.Length);
                var frame = ms.ToArray();
                lock (_sendLock)
                {
                    stream.Write(frame, 0, frame.Length);
                }
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            try { _current?.Tcp.Close(); } catch { }
        }

        /// <summary>Serves a byte prefix already read from the socket, then the socket.</summary>
        private sealed class PrefixStream : Stream
        {
            private readonly Stream _inner;
            private byte[] _prefix;
            private int _pos;

            public PrefixStream(Stream inner, byte[] prefix)
            {
                _inner = inner;
                _prefix = prefix;
            }

            private int ServePrefix(byte[] buffer, int offset, int count)
            {
                if (_prefix == null || _pos >= _prefix.Length) return 0;
                int n = Math.Min(count, _prefix.Length - _pos);
                Array.Copy(_prefix, _pos, buffer, offset, n);
                _pos += n;
                if (_pos >= _prefix.Length) { _prefix = null; _pos = 0; }
                return n;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                int n = ServePrefix(buffer, offset, count);
                if (n > 0) return n;
                return _inner.Read(buffer, offset, count);
            }

            public override int ReadByte()
            {
                if (_prefix != null && _pos < _prefix.Length)
                    return _prefix[_pos++];
                return _inner.ReadByte();
            }

            public override void Write(byte[] buffer, int offset, int count)
                => _inner.Write(buffer, offset, count);

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }
            public override void Flush() => _inner.Flush();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
        }
    }
}
