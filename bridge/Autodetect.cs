// Autodetect.cs — C# port of WMPFDebugger's offset auto-detector
// (frida/autodetect/win32.js, upstream evi0s/WMPFDebugger @ 9be0b2d, modern
// path only). Recovers the per-build hook offsets for WMPF >= 13331 from the
// on-disk flue.dll alone, using the .pdata function table, compiler-generated
// assert/log strings as anchors, RIP-relative LEA cross-references, and
// backward register slicing over the disassembly of the identified functions.
//
// Every stage requires exactly one candidate and independent recovery paths
// must agree; anything else throws. Like the JavaScript original, a wrong
// detection is structured out: the failure mode is "no offsets", never a
// wrong hook address.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace WxmpStorageDumper
{
    internal static class Autodetect
    {
        // ------------------------------------------------- registers (canonical)

        private const int RAX = 0, RCX = 1, RDX = 2;

        private static readonly HashSet<int> VolatileRegisters = new HashSet<int>
        { 0, 1, 2, 8, 9, 10, 11 };      // rax rcx rdx r8 r9 r10 r11

        // Windows x64 calling convention: rcx, rdx, r8, r9.
        private static readonly Dictionary<int, int> ArgumentRegisters =
            new Dictionary<int, int>
        { { 1, 0 }, { 2, 1 }, { 8, 2 }, { 9, 3 } };

        // ---------------------------------------------------------- instruction

        // What resolveRegister and the comparison recovery consume, in the
        // shape capstone reports upstream: operand 0 is the destination
        // (Intel syntax), operand 1 the source; at most one true memory
        // operand per instruction.
        private enum Cls { Other, Mov, Lea, AddSub, Call, Cmp }

        private sealed class Insn
        {
            public int Rva;
            public int Len;
            public Cls Class;
            public int DstReg = -1;         // canonical; operand 0 register
            public bool DstWritten;         // operand 0 is a written register
            public int SrcReg = -1;         // canonical; operand 1 register
            public bool HasImm;
            public long Imm;
            public int MemBase = -1;        // canonical raw base register
            public bool MemHasIndex;        // SIB index register present
            public long MemDisp;
            public int MemSize;             // bytes accessed through the memory operand
            public uint CallTarget = uint.MaxValue;  // rel32 target RVA
        }

        // Turns an HDE64 result into an Insn. Register operands canonicalize
        // to their 64-bit parents (al/ah/ax/eax -> rax), matching upstream's
        // REGISTER_ALIASES. Instructions outside the recognized set decode
        // for boundaries but keep no register semantics — except the writer
        // flag, which resolveRegister needs so that an unrecognized
        // instruction clobbering the traced register fails closed instead of
        // being skipped. The writer set below is the integer ISA subset MSVC
        // emits; an exotic writer that slips through cannot forge a passing
        // detection because every candidate is cross-validated downstream.
        private static Insn BuildInsn(Hde64 h, int rva)
        {
            var ins = new Insn { Rva = rva, Len = h.Len };

            bool hasModrm = (h.Flags & Hde64Engine.F_MODRM) != 0;
            bool mod3 = hasModrm && h.ModrmMod == 3;
            int regExt = h.ModrmReg | (h.RexR << 3);
            int rmExt = h.ModrmRm | (h.RexB << 3);
            bool p66 = h.P66 != 0;
            bool w64 = h.RexW != 0;

            // Memory operand: mod != 3 always addresses memory. SIB and
            // RIP-relative handling mirror the hardware encoding.
            if (hasModrm && !mod3)
            {
                if ((h.Flags & Hde64Engine.F_SIB) != 0)
                {
                    if (h.SibBase == 5 && h.ModrmMod == 0)
                        ins.MemBase = -1;               // disp32, no base
                    else
                        ins.MemBase = h.SibBase | (h.RexB << 3);
                    if (h.SibIndex != 4)                // rsp index means none
                        ins.MemHasIndex = true;
                }
                else if (h.ModrmMod == 0 && h.ModrmRm == 5)
                {
                    ins.MemBase = -1;                   // RIP-relative
                }
                else
                {
                    ins.MemBase = rmExt;
                }
                if ((h.Flags & Hde64Engine.F_DISP8) != 0)
                    ins.MemDisp = (sbyte)h.Disp;
                else if ((h.Flags & Hde64Engine.F_DISP32) != 0)
                    ins.MemDisp = (int)h.Disp;
            }

            // Operand size of the memory access (only mov/cmp sizes are
            // load-bearing for the detector; others are approximate).
            int native = w64 ? 8 : (p66 ? 2 : 4);

            // VEX/EVEX/XOP escapes (Opcode2 set by the escape path, not the
            // 0F/REX2 ones): keep the mechanically extracted memory operand
            // but no GPR writer semantics — their register operands are
            // vector registers, which never match a traced GPR anyway.
            if (h.Opcode2 != 0 && h.Opcode != 0x0f && h.Opcode != 0xd5)
                return ins;

            byte op = h.Opcode;
            if (!h.Map0f)
            {
                switch (op)
                {
                    case 0x88:
                    case 0x89:               // mov r/m, r
                        ins.Class = Cls.Mov;
                        ins.DstWritten = mod3;
                        ins.DstReg = mod3 ? rmExt : -1;
                        ins.SrcReg = regExt;
                        ins.MemSize = (op == 0x88) ? 1 : native;
                        break;
                    case 0x8a:
                    case 0x8b:               // mov r, r/m
                        ins.Class = Cls.Mov;
                        ins.DstWritten = true;
                        ins.DstReg = regExt;
                        if (mod3) ins.SrcReg = rmExt;
                        ins.MemSize = (op == 0x8a) ? 1 : native;
                        break;
                    case 0x8d:                          // lea r, m
                        ins.Class = Cls.Lea;
                        ins.DstWritten = true;
                        ins.DstReg = regExt;
                        ins.MemSize = native;
                        break;
                    case 0xc6:
                    case 0xc7:               // mov r/m, imm
                        ins.Class = Cls.Mov;
                        ins.DstWritten = mod3;
                        ins.DstReg = mod3 ? rmExt : -1;
                        ins.HasImm = true;
                        ins.Imm = Immediate(h);
                        ins.MemSize = (op == 0xc6) ? 1 : native;
                        break;
                    case 0xa0:
                    case 0xa1:               // mov al/rax, [moffs]
                        ins.Class = Cls.Mov;
                        ins.DstWritten = true;
                        ins.DstReg = RAX;
                        break;
                    case 0xa2:
                    case 0xa3:               // mov [moffs], al/rax
                        ins.Class = Cls.Mov;
                        break;
                    case 0x63:                          // movsxd r, r/m
                        ins.DstWritten = true;
                        ins.DstReg = regExt;
                        break;
                    default:
                        if (op >= 0xb0 && op <= 0xb7)   // mov r8, imm8
                        {
                            ins.Class = Cls.Mov;
                            ins.DstWritten = true;
                            ins.DstReg = (op & 7) | (h.RexB << 3);
                            ins.HasImm = true;
                            ins.Imm = Immediate(h);
                        }
                        else if (op >= 0xb8 && op <= 0xbf)   // mov r, imm
                        {
                            ins.Class = Cls.Mov;
                            ins.DstWritten = true;
                            ins.DstReg = (op & 7) | (h.RexB << 3);
                            ins.HasImm = true;
                            ins.Imm = Immediate(h);
                        }
                        else if (op < 0x40 && (op & 7) <= 5)
                        {
                            // ALU family: add/or/adc/sbb/and/sub/xor/cmp in
                            // blocks of 8. Position in the block selects the
                            // form; the block selects the operation.
                            int pos = op & 7;
                            int type = (op >> 3) & 7;
                            bool isCmp = type == 7;
                            bool isAddSub = type == 0 || type == 5;
                            if (pos <= 3)
                            {
                                if (pos <= 1)
                                {
                                    // op r/m, r
                                    ins.DstWritten = mod3 && !isCmp;
                                    ins.DstReg = mod3 ? rmExt : -1;
                                    ins.SrcReg = regExt;
                                    ins.MemSize = (pos == 0) ? 1 : native;
                                }
                                else
                                {
                                    // op r, r/m
                                    ins.DstWritten = !isCmp;
                                    ins.DstReg = regExt;
                                    if (mod3) ins.SrcReg = rmExt;
                                    ins.MemSize = (pos == 2) ? 1 : native;
                                }
                            }
                            else
                            {
                                // op al/rax, imm
                                ins.DstWritten = !isCmp;
                                ins.DstReg = RAX;
                                ins.HasImm = true;
                                ins.Imm = Immediate(h);
                            }
                            ins.Class = isCmp ? Cls.Cmp : (isAddSub ? Cls.AddSub : Cls.Other);
                        }
                        else if (op == 0x69 || op == 0x6b)   // imul r, r/m, imm
                        {
                            ins.DstWritten = true;
                            ins.DstReg = regExt;
                            ins.HasImm = true;
                            ins.Imm = Immediate(h);
                        }
                        else if (op == 0x80 || op == 0x81 || op == 0x83)
                        {
                            // group 1: op r/m, imm — /7 is cmp
                            int type = h.ModrmReg;
                            bool isCmp = type == 7;
                            bool isAddSub = type == 0 || type == 5;
                            ins.DstWritten = mod3 && !isCmp;
                            ins.DstReg = mod3 ? rmExt : -1;
                            ins.HasImm = true;
                            ins.Imm = Immediate(h);
                            ins.MemSize = (op == 0x80) ? 1 : native;
                            ins.Class = isCmp ? Cls.Cmp : (isAddSub ? Cls.AddSub : Cls.Other);
                        }
                        else if (op == 0xc0 || op == 0xc1)   // shifts by imm8
                        {
                            ins.DstWritten = mod3;
                            ins.DstReg = mod3 ? rmExt : -1;
                            ins.MemSize = (op == 0xc0) ? 1 : native;
                        }
                        else if (op == 0x84 || op == 0x85)   // test r/m, r
                        {
                            ins.SrcReg = regExt;
                            ins.MemSize = (op == 0x84) ? 1 : native;
                        }
                        else if (op == 0x86 || op == 0x87)   // xchg r/m, r
                        {
                            ins.DstWritten = mod3;
                            ins.DstReg = mod3 ? rmExt : -1;
                            ins.SrcReg = regExt;
                            ins.MemSize = (op == 0x86) ? 1 : native;
                        }
                        else if (op == 0x8c)            // mov r/m16, sreg
                        {
                            ins.DstWritten = mod3;
                            ins.DstReg = mod3 ? rmExt : -1;
                        }
                        else if (op == 0x8f)            // pop r/m
                        {
                            ins.DstWritten = mod3;
                            ins.DstReg = mod3 ? rmExt : -1;
                            ins.MemSize = native;
                        }
                        else if (op >= 0x58 && op <= 0x5f)   // pop r
                        {
                            ins.DstWritten = true;
                            ins.DstReg = (op & 7) | (h.RexB << 3);
                        }
                        else if (op == 0x90)
                        {
                            if (h.Rex != 0)             // xchg rAX, r (rex)
                            {
                                ins.DstWritten = true;
                                ins.DstReg = (op & 7) | (h.RexB << 3);
                            }
                            // plain 0x90 is nop
                        }
                        else if (op == 0x98)
                        {
                            ins.DstWritten = true;
                            ins.DstReg = RAX;           // cwde/cdqe
                        }
                        else if (op == 0x99)
                        {
                            ins.DstWritten = true;
                            ins.DstReg = 2;             // cdq/cqo -> rdx
                        }
                        else if (op == 0xe8)            // call rel32
                        {
                            ins.Class = Cls.Call;
                            long rel = (int)h.Imm;
                            long target = (long)rva + 5 + rel;
                            if (target >= 0 && target < 0x100000000L)
                                ins.CallTarget = (uint)target;
                        }
                        else if (op == 0xfe)            // inc/dec r/m8
                        {
                            ins.DstWritten = mod3;
                            ins.DstReg = mod3 ? rmExt : -1;
                            ins.MemSize = 1;
                        }
                        else if (op == 0xff)            // group 5
                        {
                            if (h.ModrmReg == 2)        // call r/m
                                ins.Class = Cls.Call;
                            else if (h.ModrmReg <= 1)   // inc/dec r/m
                            {
                                ins.DstWritten = mod3;
                                ins.DstReg = mod3 ? rmExt : -1;
                                ins.MemSize = native;
                            }
                            else if (h.ModrmReg == 6)   // push r/m
                            {
                                ins.MemSize = native;
                            }
                        }
                        else if (op == 0xf6 || op == 0xf7)   // group 3
                        {
                            int type = h.ModrmReg;
                            if (type <= 1)              // test r/m, imm
                            {
                                ins.HasImm = true;
                                ins.Imm = Immediate(h);
                            }
                            ins.DstWritten = mod3 && (type == 2 || type == 3);
                            ins.DstReg = mod3 ? rmExt : -1;
                            ins.MemSize = (op == 0xf6) ? 1 : native;
                        }
                        else if (op >= 0xd0 && op <= 0xd3)   // shifts by 1/cl
                        {
                            ins.DstWritten = mod3;
                            ins.DstReg = mod3 ? rmExt : -1;
                            ins.MemSize = (op == 0xd0 || op == 0xd2) ? 1 : native;
                        }
                        // everything else: opaque, no register semantics
                        break;
                }
            }
            else
            {
                byte op2 = h.Opcode2;
                switch (op2)
                {
                    case 0xaf:                          // imul r, r/m
                    case 0xb6:
                    case 0xb7:               // movzx
                    case 0xbe:
                    case 0xbf:               // movsx
                    case 0x40:
                    case 0x41:
                    case 0x42:
                    case 0x43:   // cmovcc
                    case 0x44:
                    case 0x45:
                    case 0x46:
                    case 0x47:
                    case 0x48:
                    case 0x49:
                    case 0x4a:
                    case 0x4b:
                    case 0x4c:
                    case 0x4d:
                    case 0x4e:
                    case 0x4f:
                        ins.DstWritten = true;
                        ins.DstReg = regExt;
                        if (mod3) ins.SrcReg = rmExt;
                        break;
                    case 0xb8:                          // popcnt/lzcnt/tzcnt
                        ins.DstWritten = true;
                        ins.DstReg = regExt;
                        if (mod3) ins.SrcReg = rmExt;
                        break;
                    case 0xbc:
                    case 0xbd:               // bsf/bsr
                        ins.DstWritten = true;
                        ins.DstReg = regExt;
                        break;
                    case 0xc0:
                    case 0xc1:               // xadd
                        ins.DstWritten = mod3;
                        ins.DstReg = mod3 ? rmExt : -1;
                        ins.SrcReg = regExt;
                        break;
                    case 0xc7:                          // cmpxchg8b/16b
                        ins.DstWritten = mod3;
                        ins.DstReg = mod3 ? rmExt : -1;
                        break;
                    case 0xa4:
                    case 0xa5:               // shld
                    case 0xac:
                    case 0xad:               // shrd
                        ins.DstWritten = mod3;
                        ins.DstReg = mod3 ? rmExt : -1;
                        ins.SrcReg = regExt;
                        break;
                    case 0xc8:
                    case 0xc9:               // bswap r32/64
                    case 0xca:
                    case 0xcb:
                    case 0xcc:
                    case 0xcd:
                    case 0xce:
                    case 0xcf:
                        ins.DstWritten = true;
                        ins.DstReg = (op2 & 7) | (h.RexB << 3);   // no modrm
                        break;
                    case 0x90:
                    case 0x91:
                    case 0x92:
                    case 0x93:   // setcc
                    case 0x94:
                    case 0x95:
                    case 0x96:
                    case 0x97:
                        ins.DstWritten = mod3;
                        ins.DstReg = mod3 ? rmExt : -1;
                        ins.MemSize = 1;
                        break;
                    case 0x7e:                          // movd (66): r/m <- xmm
                        if (p66)
                        {
                            ins.DstWritten = mod3;
                            ins.DstReg = mod3 ? rmExt : -1;
                        }
                        break;
                    case 0x6e:                          // movd (66): xmm <- r/m
                        if (p66 && mod3) ins.SrcReg = rmExt;
                        break;
                    case 0x3a:                          // pextrb/w/d/q, extractps
                        if (h.Opcode3 >= 0x14 && h.Opcode3 <= 0x17)
                        {
                            ins.DstWritten = mod3;
                            ins.DstReg = mod3 ? rmExt : -1;
                        }
                        break;
                    case 0x38:                          // movbe, crc32
                        if (h.Opcode3 == 0xf0 || h.Opcode3 == 0xf1)
                        {
                            ins.DstWritten = true;
                            ins.DstReg = regExt;
                        }
                        break;
                        // SIMD moves and everything else: opaque; the memory
                        // operand, if any, was extracted above.
                }
            }

            return ins;
        }

        // Sign-extended immediate at the width the encoding used.
        private static long Immediate(Hde64 h)
        {
            if ((h.Flags & Hde64Engine.F_IMM64) != 0) return unchecked((long)h.Imm);
            if ((h.Flags & Hde64Engine.F_IMM32) != 0) return (int)h.Imm;
            if ((h.Flags & Hde64Engine.F_IMM16) != 0) return (short)h.Imm;
            return (sbyte)h.Imm;
        }

        // ------------------------------------------------------------ expressions

        // Port of the expression algebra: arg(i), constant(v), load(base, off),
        // add(base, off). Equality flows through the canonical string key,
        // exactly like upstream.
        private sealed class Expr
        {
            public const int KindArg = 0, KindConst = 1, KindLoad = 2, KindAdd = 3;
            public int Kind;
            public int ArgIndex;
            public long Value;
            public Expr Base;
            public long Offset;
        }

        private static Expr Arg(int index) =>
            new Expr { Kind = Expr.KindArg, ArgIndex = index };

        private static Expr Const(long value) =>
            new Expr { Kind = Expr.KindConst, Value = value };

        private static Expr Load(Expr baseExpr, long offset) =>
            new Expr { Kind = Expr.KindLoad, Base = baseExpr, Offset = offset };

        private static Expr Add(Expr baseExpr, long offset)
        {
            if (offset == 0) return baseExpr;
            if (baseExpr.Kind == Expr.KindAdd)
                return new Expr
                {
                    Kind = Expr.KindAdd,
                    Base = baseExpr.Base,
                    Offset = baseExpr.Offset + offset
                };
            return new Expr { Kind = Expr.KindAdd, Base = baseExpr, Offset = offset };
        }

        private static string Key(Expr e)
        {
            if (e == null) return "unknown";
            switch (e.Kind)
            {
                case Expr.KindArg: return "arg" + e.ArgIndex;
                case Expr.KindConst:
                    return "constant:" + e.Value.ToString(CultureInfo.InvariantCulture);
                default:
                    return (e.Kind == Expr.KindLoad ? "load(" : "add(") +
                           Key(e.Base) + "," +
                           e.Offset.ToString(CultureInfo.InvariantCulture) + ")";
            }
        }

        // ---------------------------------------------------------- disassembly

        private sealed class CodeImage
        {
            public byte[] Bytes;
            public uint Rva;

            public byte this[int rva] => Bytes[rva - (int)Rva];
        }

        // Linear disassembly from the function start (upstream disassemble()).
        // Decoding must stay inside the .pdata function; a decode failure
        // throws, matching Instruction.parse's rejection upstream.
        private static List<Insn> Disassemble(CodeImage image, PeFile.FuncRange entry,
                                               long maximumSize)
        {
            var insns = new List<Insn>();
            ulong span = (ulong)(entry.End - entry.Begin);
            ulong max = maximumSize < 0 ? span : (ulong)maximumSize;
            uint size = (uint)Math.Min(span, max);
            uint end = entry.Begin + size;
            uint offset = entry.Begin;
            while (offset < end)
            {
                int pos = (int)(offset - image.Rva);
                if (pos < 0 || pos + 15 > image.Bytes.Length)
                    throw new InvalidOperationException(
                        "function 0x" + entry.Begin.ToString("x") +
                        " leaves the executable section");
                int len = Hde64Engine.Decode(image.Bytes, pos, out var h);
                if ((h.Flags & Hde64Engine.F_ERROR_LENGTH) != 0)
                    throw new InvalidOperationException(
                        "undecodable instruction at 0x" + offset.ToString("x"));
                if (offset + (uint)len > end) break;
                insns.Add(BuildInsn(h, (int)offset));
                offset += (uint)len;
            }
            return insns;
        }

        private static uint? DirectCallTarget(Insn ins)
        {
            if (ins.Class != Cls.Call || ins.CallTarget == uint.MaxValue) return null;
            return ins.CallTarget;
        }

        // ----------------------------------------------------- register slicing

        // Backward provenance walk (upstream resolveRegister): through mov /
        // movabs / lea / add-sub-imm only. Reaching an unrecognized writer
        // fails; volatile registers do not survive calls; indexed addressing
        // is rejected, so ambiguous data flow fails closed.
        private static Expr ResolveRegister(List<Insn> insns, int beforeIndex,
                                            int register, int depth = 0)
        {
            if (depth > 48) return null;

            for (int index = beforeIndex - 1; index >= 0; index--)
            {
                Insn ins = insns[index];
                if (ins.Class == Cls.Call && VolatileRegisters.Contains(register))
                    return null;

                if (!ins.DstWritten || ins.DstReg != register) continue;

                if (ins.Class == Cls.Mov)
                {
                    if (ins.SrcReg >= 0)
                        return ResolveRegister(insns, index, ins.SrcReg, depth + 1);
                    if (ins.MemBase >= 0 && !ins.MemHasIndex && ins.MemSize == 8)
                    {
                        Expr baseExpr = ResolveRegister(insns, index, ins.MemBase, depth + 1);
                        return baseExpr == null ? null : Load(baseExpr, ins.MemDisp);
                    }
                    if (ins.HasImm)
                        return Const(ins.Imm);
                    return null;
                }

                if (ins.Class == Cls.Lea)
                {
                    if (ins.MemBase < 0 || ins.MemHasIndex) return null;
                    Expr baseExpr = ResolveRegister(insns, index, ins.MemBase, depth + 1);
                    return baseExpr == null ? null : Add(baseExpr, ins.MemDisp);
                }

                if (ins.Class == Cls.AddSub && ins.HasImm)
                {
                    Expr baseExpr = ResolveRegister(insns, index, register, depth + 1);
                    if (baseExpr == null) return null;
                    return Add(baseExpr, ins.Imm);
                }

                return null;    // a writer the slicer does not understand
            }

            return ArgumentRegisters.TryGetValue(register, out int arg)
                ? Arg(arg) : null;
        }

        private sealed class Chain
        {
            public int ArgumentIndex;
            public List<long> Offsets = new List<long>();
        }

        // Root-to-leaf order, matching the launch/remote chains the hook
        // dereferences (upstream unwrapLoadChain).
        private static Chain UnwrapLoadChain(Expr e)
        {
            if (e == null) return null;
            if (e.Kind == Expr.KindArg)
                return new Chain { ArgumentIndex = e.ArgIndex };
            if (e.Kind != Expr.KindLoad) return null;
            Chain parent = UnwrapLoadChain(e.Base);
            if (parent == null) return null;
            parent.Offsets.Add(e.Offset);
            return parent;
        }

        private sealed class CmpAccess
        {
            public long Immediate;
            public long Displacement;
            public int BaseRegister;        // canonical raw base register
            public Expr Base;
        }

        // cmp mem, imm with no index register (upstream
        // comparisonMemoryAndImmediate; x86 puts mem first).
        private static CmpAccess ComparisonMemoryAndImmediate(Insn ins)
        {
            if (ins.Class != Cls.Cmp || !ins.HasImm || ins.MemBase < 0 ||
                ins.MemHasIndex)
                return null;
            return new CmpAccess
            {
                Immediate = ins.Imm,
                Displacement = ins.MemDisp,
                BaseRegister = ins.MemBase,
            };
        }

        private sealed class Guard
        {
            public List<long> RootOffsets;
            public long SceneOffset;
            public long ModeOffset;
            public Expr SceneBase;
        }

        // Recovers the remote-debug guard: a scene comparison against 1101
        // and a mode comparison against 1 that share the same base expression,
        // both rooted at argument 0 (upstream recoverRemoteGuard).
        private static Guard RecoverRemoteGuard(List<Insn> insns, string name)
        {
            var comparisons = new List<CmpAccess>();
            for (int index = 0; index < insns.Count; index++)
            {
                CmpAccess cmp = ComparisonMemoryAndImmediate(insns[index]);
                if (cmp == null || (cmp.Immediate != 1101 && cmp.Immediate != 1))
                    continue;
                Expr baseExpr = ResolveRegister(insns, index, cmp.BaseRegister);
                Chain chain = UnwrapLoadChain(baseExpr);
                if (baseExpr == null || chain == null || chain.ArgumentIndex != 0)
                    continue;
                cmp.Base = baseExpr;
                comparisons.Add(cmp);
            }

            var candidates = new List<Guard>();
            foreach (var scene in comparisons)
            {
                if (scene.Immediate != 1101) continue;
                foreach (var mode in comparisons)
                {
                    if (mode.Immediate != 1 || Key(mode.Base) != Key(scene.Base))
                        continue;
                    candidates.Add(new Guard
                    {
                        RootOffsets = new List<long>(UnwrapLoadChain(scene.Base).Offsets),
                        SceneOffset = scene.Displacement,
                        ModeOffset = mode.Displacement,
                        SceneBase = scene.Base,
                    });
                }
            }

            var unique = new Dictionary<string, Guard>();
            foreach (var candidate in candidates)
            {
                string id = string.Join(":", candidate.RootOffsets) + ":" +
                            candidate.SceneOffset + ":" + candidate.ModeOffset;
                unique[id] = candidate;
            }
            if (unique.Count != 1)
                throw new InvalidOperationException(name +
                    ": expected one scene/mode guard, found " + unique.Count);
            Guard result = null;
            foreach (var kv in unique) result = kv.Value;
            return result;
        }

        // Recovers the pointer chain of the rcx argument at the call site(s)
        // of one target function (upstream recoverCallArgumentChain).
        private static List<long> RecoverCallArgumentChain(List<Insn> insns,
                                                           uint target, string name)
        {
            var candidates = new List<List<long>>();
            for (int index = 0; index < insns.Count; index++)
            {
                uint? callTarget = DirectCallTarget(insns[index]);
                if (callTarget != target) continue;
                Expr expr = ResolveRegister(insns, index, RCX);
                Chain chain = UnwrapLoadChain(expr);
                if (chain != null && chain.ArgumentIndex == 0)
                    candidates.Add(chain.Offsets);
            }

            var unique = new Dictionary<string, List<long>>();
            foreach (var offsets in candidates)
                unique[string.Join(":", offsets)] = offsets;
            if (unique.Count != 1)
                throw new InvalidOperationException(name +
                    ": expected one call argument chain, found " + unique.Count);
            List<long> result = null;
            foreach (var kv in unique) result = kv.Value;
            return result;
        }

        private sealed class MemAccess
        {
            public long Displacement;
            public int RawBase;             // canonical raw base register
            public string BaseKey;
        }

        private static List<MemAccess> MemoryAccesses(List<Insn> insns)
        {
            var accesses = new List<MemAccess>();
            for (int index = 0; index < insns.Count; index++)
            {
                Insn ins = insns[index];
                if (ins.MemBase < 0 || ins.MemHasIndex) continue;
                Expr baseExpr = ResolveRegister(insns, index, ins.MemBase);
                if (baseExpr != null)
                {
                    accesses.Add(new MemAccess
                    {
                        Displacement = ins.MemDisp,
                        RawBase = ins.MemBase,
                        BaseKey = Key(baseExpr),
                    });
                }
            }
            return accesses;
        }

        // Recovers the std::string offset of the debug WebSocket URL inside
        // the launch config: the libc++ short-string check reads the length
        // byte at +23 of the string (upstream recoverWebSocketUrlOffset).
        private static long RecoverWebSocketUrlOffset(List<Insn> insns, Expr launchExpr)
        {
            string launchKey = Key(launchExpr);
            var launchDisplacements = new HashSet<long>();
            var accesses = MemoryAccesses(insns);
            foreach (var access in accesses)
                if (access.BaseKey == launchKey)
                    launchDisplacements.Add(access.Displacement);

            var candidates = new HashSet<long>();
            foreach (var ins in insns)
            {
                CmpAccess cmp = ComparisonMemoryAndImmediate(ins);
                if (cmp == null || cmp.Immediate != 0 || ins.MemSize != 1)
                    continue;
                long stringOffset = cmp.Displacement - 23;
                if (stringOffset < 0) continue;

                // MSVC may place the long-string branch (which contains a
                // call) before the short-string marker test in address order.
                // A linear backward slice cannot safely carry the volatile
                // base register to the marker there, so correlate the marker
                // with the data/length loads by displacement and require the
                // same raw base register.
                bool sameBase = false;
                foreach (var access in accesses)
                {
                    if ((access.Displacement == stringOffset ||
                         access.Displacement == stringOffset + 8) &&
                        access.RawBase == cmp.BaseRegister)
                    {
                        sameBase = true;
                        break;
                    }
                }
                if (sameBase &&
                    launchDisplacements.Contains(stringOffset) &&
                    launchDisplacements.Contains(stringOffset + 8))
                {
                    candidates.Add(stringOffset);
                }
            }

            if (candidates.Count != 1)
                throw new InvalidOperationException(
                    "websocket URL string: expected one offset, found " +
                    candidates.Count);
            long result = -1;
            foreach (var c in candidates) result = c;
            return result;
        }

        private static void AssertPointerOffsets(string name, List<long> offsets)
        {
            if (offsets.Count == 0)
                throw new InvalidOperationException(name + ": implausible pointer chain []");
            foreach (long offset in offsets)
                if (offset < 0 || offset > 0x10000 || offset % 8 != 0)
                    throw new InvalidOperationException(name +
                        ": implausible pointer chain element " + offset);
        }

        private static void AssertFieldOffset(string name, long offset, int alignment)
        {
            if (offset < 0 || offset > 0x10000 || offset % alignment != 0)
                throw new InvalidOperationException(name +
                    ": implausible field offset " + offset);
        }

        private static bool ContainsDirectCall(List<Insn> insns, uint target)
        {
            foreach (var ins in insns)
                if (DirectCallTarget(ins) == target) return true;
            return false;
        }

        // CastToJson must read the CBOR input's pointer/length pair from its
        // second argument (upstream validateCastToJsonAbi).
        private static void ValidateCastToJsonAbi(List<Insn> castPrefix)
        {
            var inputOffsets = new HashSet<long>();
            string arg1Key = Key(Arg(1));
            foreach (var access in MemoryAccesses(castPrefix))
                if (access.BaseKey == arg1Key)
                    inputOffsets.Add(access.Displacement);
            if (!inputOffsets.Contains(0) || !inputOffsets.Contains(8))
                throw new InvalidOperationException(
                    "CastToJson candidate does not read the input pointer/length pair");
        }

        // --------------------------------------------------------------- anchors

        // Hit lists hold [start, end] pairs: an exact match pairs the address
        // with itself, a containing match widens to the whole NUL-terminated
        // string, since a compiler-pooled source path is often a suffix of a
        // longer string and the LEA may target any byte of it (upstream
        // exactStringRanges / containingStringRanges).
        private sealed class Anchors
        {
            public List<uint> LoadFile;      // "applet_index_container.cc"
            public List<uint> LoadName;      // "AppletIndexContainer::OnLoadStart(bool"
            public List<uint> FilterName;    // exact "SendToClientFilter"
            public List<uint> FilterFile;    // "devtools_message_filter_applet_webview.cc"
            public List<uint> CastName;      // exact "CastToJson"
            public List<uint> CastFile;      // "devtools_message_filter.cc"
            public List<uint> StartUrl;      // exact " request.url="
            public List<uint> StartFailure;  // exact "create webview devtools failed."
        }

        private static Anchors FindAnchors(PeFile pe)
        {
            var targets = new List<KeyValuePair<string, bool>>   // value: exact match
            {
                new KeyValuePair<string, bool>("applet_index_container.cc", false),
                new KeyValuePair<string, bool>("AppletIndexContainer::OnLoadStart(bool", false),
                new KeyValuePair<string, bool>("SendToClientFilter", true),
                new KeyValuePair<string, bool>("devtools_message_filter_applet_webview.cc", false),
                new KeyValuePair<string, bool>("CastToJson", true),
                new KeyValuePair<string, bool>("devtools_message_filter.cc", false),
                new KeyValuePair<string, bool>(" request.url=", true),
                new KeyValuePair<string, bool>("create webview devtools failed.", true),
            };
            var hits = new Dictionary<string, List<uint>>();
            foreach (var target in targets)
                hits[target.Key] = new List<uint>();

            foreach (var section in pe.Sections)
            {
                if (section.Name == ".text" || section.Name == ".pdata")
                    continue;
                if (section.RawSize == 0 || section.Uninitialized)
                    continue;
                byte[] data = pe.ReadSectionRaw(section);
                foreach (var target in targets)
                {
                    byte[] needle = Encoding.ASCII.GetBytes(target.Key);
                    int from = 0;
                    while (true)
                    {
                        int at = IndexOf(data, needle, from);
                        if (at < 0) break;
                        uint matchRva = section.VirtualAddress + (uint)at;
                        if (target.Value)
                        {
                            hits[target.Key].Add(matchRva);     // [addr, addr]
                            hits[target.Key].Add(matchRva);
                        }
                        else
                        {
                            int start = at;
                            for (int count = 0; count < 4096 && start > 0; count++)
                            {
                                if (data[start - 1] == 0) break;
                                start--;
                            }
                            hits[target.Key].Add(section.VirtualAddress + (uint)start);
                            hits[target.Key].Add(section.VirtualAddress + (uint)at +
                                (uint)needle.Length - 1);
                        }
                        from = at + 1;
                    }
                }
            }

            return new Anchors
            {
                LoadFile = hits["applet_index_container.cc"],
                LoadName = hits["AppletIndexContainer::OnLoadStart(bool"],
                FilterName = hits["SendToClientFilter"],
                FilterFile = hits["devtools_message_filter_applet_webview.cc"],
                CastName = hits["CastToJson"],
                CastFile = hits["devtools_message_filter.cc"],
                StartUrl = hits[" request.url="],
                StartFailure = hits["create webview devtools failed."],
            };
        }

        private static int IndexOf(byte[] haystack, byte[] needle, int from)
        {
            if (needle.Length == 0) return from;
            byte first = needle[0];
            int last = haystack.Length - needle.Length;
            for (int i = from; i <= last; i++)
            {
                if (haystack[i] != first) continue;
                int j = 1;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        // Maps RIP-relative LEA instructions to the functions that own them
        // and the string ranges they reference (upstream findXrefFunctions).
        // Scanning for the byte pair is deliberately preferred over a full
        // disassembly sweep: it is what keeps the pass fast on a ~200 MB text
        // section, and the mod/rm check keeps false positives out of the
        // candidate sets.
        private static Dictionary<string, HashSet<uint>> FindXrefFunctions(
            PeFile pe, PeFile.FuncRange[] functions, Anchors targets)
        {
            var ranges = new Dictionary<string, List<uint>>
            {
                { "loadFile", targets.LoadFile },
                { "loadName", targets.LoadName },
                { "filterName", targets.FilterName },
                { "filterFile", targets.FilterFile },
                { "castName", targets.CastName },
                { "castFile", targets.CastFile },
                { "startUrl", targets.StartUrl },
                { "startFailure", targets.StartFailure },
            };
            var results = new Dictionary<string, HashSet<uint>>();
            foreach (var name in ranges.Keys)
                results[name] = new HashSet<uint>();

            foreach (var section in pe.Sections)
            {
                if (!section.Executable || section.RawSize == 0 ||
                    section.Uninitialized)
                    continue;
                byte[] code = pe.ReadSectionRaw(section);
                uint baseRva = section.VirtualAddress;
                // i is the 0x8d position; the instruction starts at the REX
                // byte in front of it (upstream keys everything off that
                // address: modrm at +2, disp32 at +3, next instruction at +7).
                for (int i = 1; i + 6 <= code.Length; i++)
                {
                    if (code[i] != 0x8d) continue;
                    byte rex = code[i - 1];
                    if (rex != 0x48 && rex != 0x4c) continue;
                    if ((code[i + 1] & 0xc7) != 0x05) continue;
                    int disp = code[i + 2] | (code[i + 3] << 8) |
                               (code[i + 4] << 16) | (code[i + 5] << 24);
                    uint rva = baseRva + (uint)(i - 1);
                    uint target = (uint)(rva + 7 + disp);
                    int owner = PeFile.FindFunction(functions, rva);
                    if (owner < 0) continue;
                    uint ownerBegin = functions[owner].Begin;
                    foreach (var name in ranges.Keys)
                        if (RangeContains(ranges[name], target))
                            results[name].Add(ownerBegin);
                }
            }
            return results;
        }

        private static bool RangeContains(List<uint> pairs, uint target)
        {
            for (int i = 0; i + 1 < pairs.Count; i += 2)
                if (target >= pairs[i] && target <= pairs[i + 1]) return true;
            return false;
        }

        // ---------------------------------------------------------------- gates

        private static HashSet<uint> Intersect(HashSet<uint> a, HashSet<uint> b)
        {
            var result = new HashSet<uint>(a);
            result.IntersectWith(b);
            return result;
        }

        private static uint RequireUnique(string name, HashSet<uint> values)
        {
            var candidates = new List<uint>(values);
            if (candidates.Count != 1)
            {
                var hex = new List<string>();
                foreach (uint c in candidates) hex.Add("0x" + c.ToString("x"));
                throw new InvalidOperationException(name +
                    ": expected one function, found " + candidates.Count +
                    (candidates.Count == 0 ? ""
                        : " (" + string.Join(", ", hex) + ")"));
            }
            return candidates[0];
        }

        private static PeFile.FuncRange RequireFunction(PeFile.FuncRange[] functions,
                                                        uint address, string name)
        {
            int index = PeFile.FindFunction(functions, address);
            if (index < 0)
                throw new InvalidOperationException(name +
                    ": function boundary not found for 0x" + address.ToString("x"));
            return functions[index];
        }

        private static string Hex(uint value) => "0x" + value.ToString("x");

        // .text is the image the anchor functions live in; refuse to
        // disassemble any anchor that starts outside it.
        private static CodeImage ImageFor(PeFile pe, params PeFile.FuncRange[] anchors)
        {
            foreach (var section in pe.Sections)
            {
                if (!section.Executable || section.RawSize == 0) continue;
                bool allInside = true;
                foreach (var f in anchors)
                    if (f.Begin < section.VirtualAddress ||
                        f.End > section.VirtualAddress + section.RawSize)
                    {
                        allInside = false;
                        break;
                    }
                if (allInside)
                {
                    return new CodeImage
                    {
                        Bytes = pe.ReadSectionRaw(section),
                        Rva = section.VirtualAddress,
                    };
                }
            }
            throw new InvalidOperationException(
                "anchor functions are not inside one executable section");
        }

        // Recovers the modern-layout offsets (upstream detectModern), with
        // every cross-validation the upstream script applies.
        private static string DetectModern(PeFile pe, PeFile.FuncRange[] functions,
            Dictionary<string, HashSet<uint>> xrefs, PeFile.FuncRange loadStart)
        {
            uint startOffset = RequireUnique("DevToolsWebSocketServer::Start",
                Intersect(xrefs["startUrl"], xrefs["startFailure"]));
            uint filterOffset = RequireUnique("applet-webview SendToClientFilter",
                Intersect(xrefs["filterName"], xrefs["filterFile"]));
            uint castOffset = RequireUnique("CastToJson",
                Intersect(xrefs["castName"], xrefs["castFile"]));

            var start = RequireFunction(functions, startOffset,
                "DevToolsWebSocketServer::Start");
            var filter = RequireFunction(functions, filterOffset,
                "SendToClientFilter");
            var cast = RequireFunction(functions, castOffset, "CastToJson");

            CodeImage image = ImageFor(pe, loadStart, start, filter, cast);
            var loadInstructions = Disassemble(image, loadStart, -1);
            var startInstructions = Disassemble(image, start, 0x1200);
            var filterInstructions = Disassemble(image, filter, -1);
            var castPrefix = Disassemble(image, cast, 0x100);

            var serverChain = RecoverCallArgumentChain(loadInstructions, start.Begin,
                "OnLoadStart -> DevToolsWebSocketServer::Start");
            Guard loadGuard = RecoverRemoteGuard(loadInstructions, "OnLoadStart");
            Guard startGuard = RecoverRemoteGuard(startInstructions,
                "DevToolsWebSocketServer::Start");

            AssertPointerOffsets("server pointer chain", serverChain);
            AssertPointerOffsets("OnLoadStart remote config chain",
                loadGuard.RootOffsets);
            AssertPointerOffsets("Start remote config chain",
                startGuard.RootOffsets);
            if (serverChain.Count != 2 || loadGuard.RootOffsets.Count != 3 ||
                startGuard.RootOffsets.Count != 3)
                throw new InvalidOperationException(
                    "unexpected modern WMPF pointer-chain depth");
            if (serverChain[0] != loadGuard.RootOffsets[0])
                throw new InvalidOperationException(
                    "OnLoadStart server and remote-config roots disagree");
            if (!RangeListEqual(
                    loadGuard.RootOffsets.GetRange(1, loadGuard.RootOffsets.Count - 1),
                    startGuard.RootOffsets.GetRange(1, startGuard.RootOffsets.Count - 1)))
                throw new InvalidOperationException(
                    "OnLoadStart and Start remote-config chains disagree");
            if (loadGuard.SceneOffset != startGuard.SceneOffset ||
                loadGuard.ModeOffset != startGuard.ModeOffset)
                throw new InvalidOperationException(
                    "OnLoadStart and Start remote-debug fields disagree");

            var launchExpression = Load(Arg(0), startGuard.RootOffsets[0]);
            long websocketUrlOffset = RecoverWebSocketUrlOffset(startInstructions,
                launchExpression);
            AssertFieldOffset("scene", startGuard.SceneOffset, 4);
            AssertFieldOffset("remote debug mode", startGuard.ModeOffset, 4);
            AssertFieldOffset("websocket URL string", websocketUrlOffset, 8);

            if (!ContainsDirectCall(filterInstructions, cast.Begin))
                throw new InvalidOperationException(
                    "SendToClientFilter does not call the detected CastToJson");
            ValidateCastToJsonAbi(castPrefix);

            var sb = new StringBuilder();
            sb.Append("{\n");
            sb.Append("  \"LoadStartHookOffset\": \"").Append(Hex(loadStart.Begin)).Append("\",\n");
            sb.Append("  \"CDPFilterHookOffset\": \"").Append(Hex(filter.Begin)).Append("\",\n");
            sb.Append("  \"CastToJsonHookOffset\": \"").Append(Hex(cast.Begin)).Append("\",\n");
            sb.Append("  \"MiniAppConfigStructOffsets\": {\n");
            sb.Append("    \"LaunchConfigOffsets\": [");
            sb.Append(string.Join(", ", serverChain));
            sb.Append(", ").Append(startGuard.RootOffsets[0]).Append("],\n");
            sb.Append("    \"RemoteDebugConfigOffsets\": [");
            sb.Append(string.Join(", ", startGuard.RootOffsets.GetRange(1,
                startGuard.RootOffsets.Count - 1)));
            sb.Append("],\n");
            sb.Append("    \"SceneOffset\": ").Append(startGuard.SceneOffset).Append(",\n");
            sb.Append("    \"WebSocketURLStringOffset\": ").Append(websocketUrlOffset).Append(",\n");
            sb.Append("    \"RemoteDebugModeOffset\": ").Append(startGuard.ModeOffset).Append("\n");
            sb.Append("  }\n");
            sb.Append("}");
            return sb.ToString();
        }

        private static bool RangeListEqual(List<long> a, List<long> b)
        {
            if (a.Count != b.Count) return false;
            for (int i = 0; i < a.Count; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        // Detects the offsets for flue.dll at the given path and returns the
        // upstream-shaped JSON. Only the modern layout is supported: legacy
        // builds (no modern anchors) stay on the static tables.
        public static string DetectJson(string flueDllPath)
        {
            bool dbg = Environment.GetEnvironmentVariable("WMPF_DETECT_DEBUG") == "1";
            using (var pe = new PeFile(flueDllPath))
            {
                var functions = pe.LoadFunctions();
                if (dbg)
                {
                    Console.Error.WriteLine("[detect] functions: " + functions.Length);
                    Console.Error.WriteLine("[detect] image: 0x" + pe.SizeOfImage.ToString("x"));
                    foreach (var s in pe.Sections)
                        Console.Error.WriteLine("[detect] section " + s.Name +
                            " va=0x" + s.VirtualAddress.ToString("x") +
                            " vsz=0x" + s.VirtualSize.ToString("x") +
                            " raw=0x" + s.RawSize.ToString("x") +
                            " exec=" + s.Executable);
                }
                Anchors anchors = FindAnchors(pe);
                if (dbg)
                {
                    Console.Error.WriteLine("[detect] loadFile hits: " + anchors.LoadFile.Count +
                        (anchors.LoadFile.Count > 0 ? " first 0x" + anchors.LoadFile[0].ToString("x") : ""));
                    Console.Error.WriteLine("[detect] loadName hits: " + anchors.LoadName.Count +
                        (anchors.LoadName.Count > 0 ? " first 0x" + anchors.LoadName[0].ToString("x") : ""));
                    Console.Error.WriteLine("[detect] filterName hits: " + anchors.FilterName.Count +
                        (anchors.FilterName.Count > 0 ? " first 0x" + anchors.FilterName[0].ToString("x") : ""));
                }
                if (anchors.LoadFile.Count == 0)
                    throw new InvalidOperationException(
                        "string not found: applet_index_container.cc");
                if (anchors.LoadName.Count == 0)
                    throw new InvalidOperationException(
                        "string not found: AppletIndexContainer::OnLoadStart(bool");
                if (anchors.FilterName.Count == 0)
                    throw new InvalidOperationException(
                        "string not found: SendToClientFilter");

                bool modernAnchorsPresent =
                    anchors.FilterFile.Count != 0 && anchors.CastName.Count != 0 &&
                    anchors.CastFile.Count != 0 && anchors.StartUrl.Count != 0 &&
                    anchors.StartFailure.Count != 0;
                if (!modernAnchorsPresent)
                    throw new InvalidOperationException(
                        "no modern anchors in flue.dll; this build needs a " +
                        "static offset table (legacy layouts are not auto-detected)");

                var xrefs = FindXrefFunctions(pe, functions, anchors);
                if (dbg)
                    foreach (var name in xrefs.Keys)
                        Console.Error.WriteLine("[detect] xrefs " + name + ": " + xrefs[name].Count);
                uint loadStartOffset = RequireUnique("AppletIndexContainer::OnLoadStart",
                    Intersect(xrefs["loadFile"], xrefs["loadName"]));
                var loadStart = RequireFunction(functions, loadStartOffset,
                    "AppletIndexContainer::OnLoadStart");

                return DetectModern(pe, functions, xrefs, loadStart);
            }
        }
    }
}
