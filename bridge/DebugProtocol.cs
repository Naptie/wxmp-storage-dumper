// DebugProtocol.cs — hand-rolled codec for WeChat's private remote-debug
// framing, reimplemented from the wire format used by WMPFDebugger's
// RemoteDebugCodex.js / WARemoteDebugProtobuf.js (see PROVENANCE.md).
//
// Frame layout (binary WebSocket payload):
//   DebugMessage { seq, after, category, data, compressAlgo, originalSize }
// CDP traffic uses category "chromeDevtools" / "chromeDevtoolsResult" with
// inner ChromeDevtools { opId, payload, jscontextId }.

using System;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace WxmpStorageDumper
{
    internal sealed class DebugMessage
    {
        public uint Seq;
        public string Category = "";
        public byte[] Data = new byte[0];
        public uint CompressAlgo;
        public uint OriginalSize;
    }

    internal static class DebugProtocol
    {
        public const uint CompressAlgoZlib = 1;
        public const string CategoryChromeDevtools = "chromeDevtools";
        public const string CategoryChromeDevtoolsResult = "chromeDevtoolsResult";

        // ------------------------------------------------------------ proto ---

        private static void WriteVarint(MemoryStream ms, ulong v)
        {
            while (v >= 0x80)
            {
                ms.WriteByte((byte)(v | 0x80));
                v >>= 7;
            }
            ms.WriteByte((byte)v);
        }

        private static void WriteTag(MemoryStream ms, int field, int wireType)
        {
            WriteVarint(ms, (ulong)((field << 3) | wireType));
        }

        private static void WriteLengthDelimited(MemoryStream ms, int field, byte[] payload)
        {
            WriteTag(ms, field, 2);
            WriteVarint(ms, (ulong)payload.Length);
            ms.Write(payload, 0, payload.Length);
        }

        private static void WriteString(MemoryStream ms, int field, string s)
        {
            WriteLengthDelimited(ms, field, Encoding.UTF8.GetBytes(s ?? ""));
        }

        private static ulong ReadVarint(byte[] buf, ref int pos)
        {
            ulong v = 0;
            int shift = 0;
            while (pos < buf.Length)
            {
                byte b = buf[pos++];
                v |= (ulong)(b & 0x7f) << shift;
                if ((b & 0x80) == 0) return v;
                shift += 7;
                if (shift > 63) throw new InvalidDataException("varint too long");
            }
            throw new InvalidDataException("truncated varint");
        }

        /// <summary>Encode the outer DebugMessage envelope.</summary>
        public static byte[] EncodeDebugMessage(uint seq, string category, byte[] data,
                                                uint compressAlgo, uint originalSize)
        {
            using (var ms = new MemoryStream())
            {
                WriteTag(ms, 1, 0);
                WriteVarint(ms, seq);
                WriteString(ms, 3, category);
                if (data != null && data.Length > 0)
                    WriteLengthDelimited(ms, 4, data);
                if (compressAlgo != 0)
                {
                    WriteTag(ms, 5, 0);
                    WriteVarint(ms, compressAlgo);
                }
                if (originalSize != 0)
                {
                    WriteTag(ms, 6, 0);
                    WriteVarint(ms, originalSize);
                }
                return ms.ToArray();
            }
        }

        public static DebugMessage DecodeDebugMessage(byte[] buf)
        {
            var msg = new DebugMessage();
            int pos = 0;
            while (pos < buf.Length)
            {
                ulong tag = ReadVarint(buf, ref pos);
                int field = (int)(tag >> 3);
                int wireType = (int)(tag & 7);
                switch (field)
                {
                    case 1 when wireType == 0:
                        msg.Seq = (uint)ReadVarint(buf, ref pos);
                        break;
                    case 3 when wireType == 2:
                        msg.Category = Encoding.UTF8.GetString(ReadBytes(buf, ref pos));
                        break;
                    case 4 when wireType == 2:
                        msg.Data = ReadBytes(buf, ref pos);
                        break;
                    case 5 when wireType == 0:
                        msg.CompressAlgo = (uint)ReadVarint(buf, ref pos);
                        break;
                    case 6 when wireType == 0:
                        msg.OriginalSize = (uint)ReadVarint(buf, ref pos);
                        break;
                    default:
                        SkipField(buf, ref pos, wireType);
                        break;
                }
            }
            return msg;
        }

        /// <summary>Inner ChromeDevtools message: opId(1), payload(2), jscontextId(3).</summary>
        public static byte[] EncodeChromeDevtools(ulong opId, string payload, string jscontextId)
        {
            using (var ms = new MemoryStream())
            {
                WriteTag(ms, 1, 0);
                WriteVarint(ms, opId);
                WriteString(ms, 2, payload);
                WriteString(ms, 3, jscontextId ?? "");
                return ms.ToArray();
            }
        }

        /// <summary>Extract the CDP JSON payload from a ChromeDevtoolsResult inner message.</summary>
        public static string DecodeChromeDevtoolsResultPayload(byte[] data)
        {
            int pos = 0;
            while (pos < data.Length)
            {
                ulong tag = ReadVarint(data, ref pos);
                int field = (int)(tag >> 3);
                int wireType = (int)(tag & 7);
                if (field == 2 && wireType == 2)
                    return Encoding.UTF8.GetString(ReadBytes(data, ref pos));
                SkipField(data, ref pos, wireType);
            }
            return null;
        }

        private static byte[] ReadBytes(byte[] buf, ref int pos)
        {
            ulong len = ReadVarint(buf, ref pos);
            if (pos + (int)len > buf.Length) throw new InvalidDataException("truncated bytes");
            var outBuf = new byte[len];
            Array.Copy(buf, pos, outBuf, 0, (int)len);
            pos += (int)len;
            return outBuf;
        }

        private static void SkipField(byte[] buf, ref int pos, int wireType)
        {
            switch (wireType)
            {
                case 0:
                    ReadVarint(buf, ref pos);
                    break;
                case 1:
                    pos += 8;
                    break;
                case 2:
                    pos += (int)ReadVarint(buf, ref pos);
                    break;
                case 5:
                    pos += 4;
                    break;
                default:
                    throw new InvalidDataException("bad wire type " + wireType);
            }
            if (pos > buf.Length) throw new InvalidDataException("field overruns buffer");
        }

        // ------------------------------------------------------------- zlib ---

        /// <summary>
        /// Inflate a zlib-wrapped deflate stream (RFC 1950, what node's
        /// zlib.inflateSync produces). .NET Framework DeflateStream expects raw
        /// deflate (RFC 1951), so strip the 2-byte zlib header and the 4-byte
        /// Adler-32 trailer.
        /// </summary>
        public static byte[] InflateZlib(byte[] data, uint originalSize)
        {
            if (data == null || data.Length < 6)
                throw new InvalidDataException("zlib buffer too small");
            try
            {
                return InflateRaw(data, 2, data.Length - 6, originalSize);
            }
            catch (InvalidDataException)
            {
                // Some stacks hand us raw deflate already; retry whole buffer.
                return InflateRaw(data, 0, data.Length, originalSize);
            }
        }

        private static byte[] InflateRaw(byte[] data, int offset, int count, uint originalSize)
        {
            using (var input = new MemoryStream(data, offset, count, false))
            using (var deflate = new DeflateStream(input, CompressionMode.Decompress))
            using (var output = new MemoryStream(originalSize > 0 ? (int)originalSize : 0))
            {
                deflate.CopyTo(output);
                return output.ToArray();
            }
        }

        // ------------------------------------------------------- convenience ---

        /// <summary>Wrap a CDP request JSON string into a ready-to-send WS binary frame.</summary>
        public static byte[] BuildCdpFrame(uint seq, string cdpRequestJson)
        {
            byte[] inner = EncodeChromeDevtools(0, cdpRequestJson, "");
            return EncodeDebugMessage(seq, CategoryChromeDevtools, inner, 0, 0);
        }

        /// <summary>
        /// Decode a received WS binary frame; returns the CDP response JSON for
        /// chromeDevtoolsResult messages, or null for anything else
        /// (ping/pong/login/etc. — ignored, same as the reference client).
        /// </summary>
        public static string TryExtractCdpResponse(byte[] frame, bool verbose, Action<string> log)
        {
            DebugMessage msg;
            try
            {
                msg = DecodeDebugMessage(frame);
            }
            catch (Exception ex)
            {
                log?.Invoke($"[proto] decode failed: {ex.Message} ({frame.Length} bytes)");
                return null;
            }

            byte[] data = msg.Data;
            if (data != null && data.Length > 0 &&
                (msg.CompressAlgo & CompressAlgoZlib) != 0)
            {
                try
                {
                    data = InflateZlib(data, msg.OriginalSize);
                }
                catch (Exception ex)
                {
                    log?.Invoke($"[proto] inflate failed: {ex.Message}");
                    return null;
                }
            }

            if (msg.Category != CategoryChromeDevtoolsResult)
            {
                if (verbose)
                    log?.Invoke($"[proto] ignoring category={msg.Category}");
                return null;
            }

            return DecodeChromeDevtoolsResultPayload(data ?? new byte[0]);
        }
    }
}
