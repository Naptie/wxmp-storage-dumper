// PeFile.cs — minimal read-only PE32+ file parser for the offset
// auto-detector. The detector analyzes the on-disk flue.dll (the same image
// the WMPF browser process maps), so no process attachment is needed. Only
// what the detector consumes is parsed: the section table, whole-section
// reads, and the .pdata exception-function table that provides exact
// function boundaries on x64.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WxmpStorageDumper
{
    internal sealed class PeFile : IDisposable
    {
        public sealed class Section
        {
            public string Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint RawSize;
            public uint RawOffset;
            public uint Characteristics;

            public bool Executable =>
                (Characteristics & 0x20000000) != 0;   // IMAGE_SCN_MEM_EXECUTE
            public bool Uninitialized =>
                (Characteristics & 0x00000080) != 0;   // IMAGE_SCN_CNT_UNINITIALIZED_DATA
        }

        public struct FuncRange
        {
            public uint Begin;   // RVA
            public uint End;     // RVA, exclusive
        }

        private const int IMAGE_SCN_MEM_EXECUTE = 0x20000000;

        private readonly FileStream _file;

        public IReadOnlyList<Section> Sections { get; }
        public uint SizeOfImage { get; }

        public PeFile(string path)
        {
            _file = File.OpenRead(path);
            try
            {
                var header = new byte[0x1000];
                ReadExact(header, 0, header.Length);

                uint peOff = LittleEndianU32(header, 0x3c);
                if (peOff + 24 + 2 > (uint)header.Length ||
                    header[peOff] != 'P' || header[peOff + 1] != 'E' ||
                    header[peOff + 2] != 0 || header[peOff + 3] != 0)
                    throw new InvalidOperationException("not a PE image");

                int coff = (int)peOff + 4;
                ushort sectionCount = LittleEndianU16(header, coff + 2);
                ushort optSize = LittleEndianU16(header, coff + 16);

                int opt = coff + 20;
                if (opt + optSize > header.Length)
                    throw new InvalidOperationException("optional header out of range");
                ushort magic = LittleEndianU16(header, opt);
                if (magic != 0x20b)
                    throw new InvalidOperationException("not a PE32+ (x64) image");
                SizeOfImage = LittleEndianU32(header, opt + 56);

                int secOff = opt + optSize;
                var sections = new List<Section>(sectionCount);
                for (int i = 0; i < sectionCount; i++)
                {
                    int b = secOff + i * 40;
                    if (b + 40 > header.Length)
                        throw new InvalidOperationException("section table out of range");
                    var s = new Section
                    {
                        Name = AsciiName(header, b),
                        VirtualSize = LittleEndianU32(header, b + 8),
                        VirtualAddress = LittleEndianU32(header, b + 12),
                        RawSize = LittleEndianU32(header, b + 16),
                        RawOffset = LittleEndianU32(header, b + 20),
                        Characteristics = LittleEndianU32(header, b + 36),
                    };
                    sections.Add(s);
                }
                Sections = sections;
            }
            catch
            {
                _file.Dispose();
                throw;
            }
        }

        // Maps an RVA to the file offset of its raw bytes. RVAs that only
        // exist virtually (uninitialized tail, raw size 0) cannot be read
        // from a file and are rejected.
        public uint RvaToOffset(uint rva)
        {
            foreach (var s in Sections)
            {
                uint size = Math.Max(s.VirtualSize, s.RawSize);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
                {
                    uint into = rva - s.VirtualAddress;
                    if (into >= s.RawSize)
                        throw new InvalidOperationException(
                            "RVA 0x" + rva.ToString("x") +
                            " has no raw data in section " + s.Name);
                    return s.RawOffset + into;
                }
            }
            throw new InvalidOperationException(
                "RVA 0x" + rva.ToString("x") + " not in any section");
        }

        public byte[] ReadRva(uint rva, int length)
        {
            var data = new byte[length];
            _file.Position = RvaToOffset(rva);
            ReadExact(data, 0, length);
            return data;
        }

        public byte[] ReadSectionRaw(Section s)
        {
            var data = new byte[s.RawSize];
            _file.Position = s.RawOffset;
            ReadExact(data, 0, data.Length);
            return data;
        }

        // Ports autodetect/win32.js loadFunctions: the x64 PE exception table
        // gives exact function boundaries. Duplicated start RVAs keep the
        // widest record; entries are validated and sorted by start.
        public FuncRange[] LoadFunctions()
        {
            Section pdata = null;
            foreach (var s in Sections)
                if (s.Name == ".pdata") { pdata = s; break; }
            if (pdata == null || pdata.RawSize == 0)
                throw new InvalidOperationException(".pdata section not found");

            var bytes = ReadSectionRaw(pdata);
            var byStart = new Dictionary<uint, uint>();
            for (int off = 0; off + 12 <= bytes.Length; off += 12)
            {
                uint begin = LittleEndianU32(bytes, off);
                uint end = LittleEndianU32(bytes, off + 4);
                if (begin == 0 || begin >= end || end > SizeOfImage)
                    continue;
                uint prevEnd;
                if (!byStart.TryGetValue(begin, out prevEnd) || end > prevEnd)
                    byStart[begin] = end;
            }

            var functions = new List<FuncRange>(byStart.Count);
            foreach (var kv in byStart)
                functions.Add(new FuncRange { Begin = kv.Key, End = kv.Value });
            functions.Sort((a, b) => a.Begin.CompareTo(b.Begin));
            if (functions.Count == 0)
                throw new InvalidOperationException("no functions found in .pdata");
            return functions.ToArray();
        }

        // Binary search over sorted function ranges; -1 when not inside any.
        public static int FindFunction(FuncRange[] sorted, uint rva)
        {
            int low = 0, high = sorted.Length - 1;
            while (low <= high)
            {
                int mid = (low + high) >> 1;
                if (rva < sorted[mid].Begin) high = mid - 1;
                else if (rva >= sorted[mid].End) low = mid + 1;
                else return mid;
            }
            return -1;
        }

        public void Dispose() => _file.Dispose();

        // ------------------------------------------------------------ helpers

        private void ReadExact(byte[] buffer, int offset, int count)
        {
            int read = 0;
            while (read < count)
            {
                int got = _file.Read(buffer, offset + read, count - read);
                if (got == 0)
                    throw new InvalidOperationException("truncated PE file");
                read += got;
            }
        }

        private static ushort LittleEndianU16(byte[] b, int off) =>
            (ushort)(b[off] | (b[off + 1] << 8));

        private static uint LittleEndianU32(byte[] b, int off) =>
            (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));

        private static string AsciiName(byte[] b, int off)
        {
            int len = 0;
            while (len < 8 && b[off + len] != 0) len++;
            return Encoding.ASCII.GetString(b, off, len);
        }
    }
}
