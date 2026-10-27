// Hde64.cs — C# translation of the Hacker Disassembler Engine 64 vendored in
// native/third_party/minhook/src/hde (hde64.c + table64.h, Vyacheslav
// Patkov). The auto-detector needs faithful instruction lengths plus the
// ModR/M, SIB, immediate and displacement fields; the engine is translated
// verbatim, error flags included, so a truncated or hostile stream fails
// loudly instead of silently mis-decoding.

using System;

namespace WxmpStorageDumper
{
    internal struct Hde64
    {
        public byte Len;
        public byte PRep, PLock, PSeg, P66, P67;
        public byte Rex, RexW, RexR, RexX, RexB;
        public byte Opcode, Opcode2;
        public byte Opcode3;    // third byte of 0F 38 / 0F 3A instructions
        public byte Modrm, ModrmMod, ModrmReg, ModrmRm;
        public byte Sib, SibScale, SibIndex, SibBase;
        public ulong Imm;
        public uint Disp;
        public uint Flags;
        public bool Map0f;   // not in the C struct; the decoder records it
    }

    internal static class Hde64Engine
    {
        // table64.h shape flags
        private const int C_NONE = 0x00, C_MODRM = 0x01, C_IMM8 = 0x02,
            C_IMM16 = 0x04, C_IMM_P66 = 0x10, C_REL8 = 0x20, C_REL32 = 0x40,
            C_GROUP = 0x80, C_ERROR = 0xff;
        // table64.h prefix classes
        private const int PRE_NONE = 0x01, PRE_F2 = 0x02, PRE_F3 = 0x04,
            PRE_66 = 0x08, PRE_67 = 0x10, PRE_LOCK = 0x20, PRE_SEG = 0x40;
        // table64.h deltas into the table
        private const int DELTA_OPCODES = 0x4a, DELTA_FPU_REG = 0xfd,
            DELTA_FPU_MODRM = 0x104, DELTA_PREFIXES = 0x13c,
            DELTA_OP_LOCK_OK = 0x1ae, DELTA_OP2_LOCK_OK = 0x1c6,
            DELTA_OP_ONLY_MEM = 0x1d8, DELTA_OP2_ONLY_MEM = 0x1e7;

        // hde64.h output flags (the subset the decoder sets)
        public const uint F_MODRM = 0x00000001, F_SIB = 0x00000002,
            F_IMM8 = 0x00000004, F_IMM16 = 0x00000008, F_IMM32 = 0x00000010,
            F_IMM64 = 0x00000020, F_DISP8 = 0x00000040, F_DISP16 = 0x00000080,
            F_DISP32 = 0x00000100, F_RELATIVE = 0x00000200,
            F_ERROR = 0x00001000, F_ERROR_OPCODE = 0x00002000,
            F_ERROR_LENGTH = 0x00004000, F_ERROR_LOCK = 0x00008000,
            F_ERROR_OPERAND = 0x00010000,
            F_PREFIX_REX = 0x40000000, F_PREFIX_REX2 = 0x80000000;

        private static readonly byte[] T =
        {
            0xa5,0xaa,0xa5,0xaa,0xa5,0xaa,0xa5,0xaa,0xa5,0xb8,0xa5,0xb8,0xa5,0xb8,0xa5,
            0xb8,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xac,0xc0,0xcc,0xc0,0xa1,0xa1,
            0xa1,0xa1,0xb1,0xa5,0xa5,0xa6,0xc0,0xc0,0xd7,0xda,0xe0,0xc0,0xe4,0xc0,0xea,
            0xea,0xe0,0xe0,0x98,0xc8,0xee,0xf1,0xa5,0xd3,0xa5,0xa5,0xa1,0xea,0x9e,0xc0,
            0xc0,0xc2,0xc0,0xe6,0x03,0x7e,0x11,0x7e,0x01,0x7f,0x01,0x3f,0x01,0x01,0xab,
            0x8b,0x90,0x64,0x5b,0x5b,0x5b,0x5b,0x5b,0x92,0x5b,0x5b,0x76,0x90,0x92,0x92,
            0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x6a,0x73,0x90,
            0x5b,0x52,0x52,0x52,0x52,0x5b,0x5b,0x5b,0x5b,0x77,0x7c,0x77,0x85,0x5b,0x5b,
            0x70,0x5b,0x7a,0xaf,0x76,0x76,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,
            0x5b,0x5b,0x86,0x01,0x01,0x01,0x00,0x03,0xd5,0x03,0xd5,0x03,0xcc,0x01,0xa0,
            0x03,0xf0,0x03,0x03,0x04,0x00,0x50,0x50,0x50,0x50,0xff,0x20,0x20,0x20,0x20,
            0x01,0x01,0x01,0x01,0xc4,0x02,0x10,0xff,0xff,0xff,0x01,0x00,0x03,0x11,0xff,
            0x03,0xc4,0xc6,0xc8,0x02,0x10,0x00,0xff,0xcc,0x01,0x01,0x01,0x00,0x00,0x00,
            0x00,0x01,0x01,0x03,0x01,0xff,0xff,0xc0,0xc2,0x10,0x11,0x02,0x03,0x01,0x01,
            0x01,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0x00,0x00,0xff,0xff,0xff,0xff,0x10,
            0x10,0x10,0x10,0x02,0x10,0x00,0x00,0xc6,0xc8,0x02,0x02,0x02,0x02,0x06,0x00,
            0x04,0x00,0x02,0xff,0x00,0xc0,0xc2,0x01,0x01,0x03,0x03,0x03,0xca,0x40,0x00,
            0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0xff,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
            0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7f,0x00,0x00,
            0xff,0x40,0x40,0x40,0x40,0x41,0x49,0x40,0x40,0x40,0x40,0x4c,0x42,0x40,0x40,
            0x40,0x40,0x40,0x40,0x40,0x40,0x4f,0x44,0x53,0x40,0x40,0x40,0x44,0x57,0x43,
            0x5c,0x40,0x60,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
            0x40,0x40,0x64,0x64,0x6e,0x6b,0x40,0x40,0x6a,0x46,0x40,0x40,0x44,0x46,0x40,
            0x40,0x5b,0x44,0x40,0x40,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x06,0x01,0x06,
            0x06,0x02,0x06,0x06,0x00,0x06,0x00,0x0a,0x0a,0x00,0x00,0x00,0x02,0x07,0x07,
            0x06,0x02,0x0d,0x06,0x06,0x06,0x0e,0x05,0x05,0x02,0x02,0x00,0x00,0x00,0x00,
            0x04,0x04,0x05,0x06,0x06,0x06,0x00,0x00,0x00,0x0e,0x00,0x00,0x08,0x00,0x10,
            0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,0x86,0x00,
            0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,0xf8,0xbb,
            0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,0xc4,0xff,
            0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0xff,0x12,0x08,0x00,0x13,0x09,
            0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0xff,0xb2,0xff,
            0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,0xe7,0x09,
            0x00,0xf0,0x02,0x00
        };

        // Decodes the instruction at code[pos]. Returns its length; hs carries
        // the decoded fields. A length error yields len 15 with F_ERROR_LENGTH,
        // exactly like the C engine.
        public static int Decode(byte[] code, int pos, out Hde64 hsOut)
        {
            Hde64 hs = new Hde64();
            int p = pos;
            int limit = pos + 15;
            if (limit > code.Length) limit = code.Length;

            byte c = 0, cflags, opcode = 0, pref = 0, mand = 0;
            byte rex = 0;
            bool haveRex2 = false;
            bool extPath = false;       // the VEX/XOP/EVEX escape paths
            int map0f = 0;              // the opcode came from the 0F map
            int ht = 0, m_mod = 0, m_reg = 0, m_rm = 0, dispSize = 0;
            int op64 = 0, x = 0;

            for (x = 15; x != 0; x--)
            {
                if (p >= code.Length) goto errorLength;
                c = code[p++];
                switch (c)
                {
                    case 0xf3:
                        hs.PRep = c; pref |= PRE_F3; mand = PRE_F3; rex = 0;
                        break;
                    case 0xf2:
                        hs.PRep = c; pref |= PRE_F2; mand = PRE_F2; rex = 0;
                        break;
                    case 0xf0:
                        hs.PLock = c; pref |= PRE_LOCK; rex = 0;
                        break;
                    case 0x26:
                    case 0x2e:
                    case 0x36:
                    case 0x3e:
                    case 0x64:
                    case 0x65:
                        hs.PSeg = c; pref |= PRE_SEG; rex = 0;
                        break;
                    case 0x66:
                        hs.P66 = c; pref |= PRE_66;
                        if (mand == 0) mand = PRE_66;
                        rex = 0;
                        break;
                    case 0x67:
                        hs.P67 = c; pref |= PRE_67; rex = 0;
                        break;
                    default:
                        if ((c & 0xf0) != 0x40) goto prefDone;
                        // REX counts only as the last prefix before the
                        // opcode: a legacy prefix after it, or a further REX,
                        // discards it.
                        rex = c;
                        break;
                }
            }
            goto errorLength;       // 15 prefixes leave no room for an opcode

        prefDone:

            hs.Flags = (uint)pref << 23;

            if (pref == 0) pref = PRE_NONE;
            // pref says which prefix classes are present, which is what an
            // operand-size or LOCK rule asks. A mandatory prefix is a choice
            // between 66, F2 and F3 rather than a set, so the rules that
            // select an instruction read mand instead.
            if (mand == 0) mand = PRE_NONE;

            if (rex != 0)
            {
                hs.Flags |= F_PREFIX_REX;
                hs.Rex = rex;
                hs.RexW = (byte)((rex & 0xf) >> 3);
                hs.RexR = (byte)((rex & 7) >> 2);
                hs.RexX = (byte)((rex & 3) >> 1);
                hs.RexB = (byte)(rex & 1);
                if (hs.RexW != 0 && (c & 0xf8) == 0xb8) op64++;
            }

            // VEX, EVEX and XOP. C4, C5 and 62 are always escapes in long
            // mode; 8F is one only from map 8 upwards, which leaves 8F /0 as
            // POP. The header names the opcode map, the map decides the
            // immediate, and every instruction reached this way has a ModR/M
            // byte.
            if (c == 0xc4 || c == 0xc5 || c == 0x62 ||
                (c == 0x8f && p < limit && (code[p] & 0x1f) >= 8))
            {
                byte map;
                hs.Opcode = c;
                if (c == 0xc5)
                {
                    if (limit - p < 3) goto errorLength;
                    map = 1;
                    p++;
                }
                else if (c == 0x62)
                {
                    if (limit - p < 5) goto errorLength;
                    map = (byte)(code[p] & 0x07);   // the bit above the map is APX's B4
                    p += 3;
                }
                else
                {
                    if (limit - p < 4) goto errorLength;
                    map = (byte)(code[p] & 0x1f);
                    p += 2;
                }
                opcode = code[p++];
                hs.Opcode2 = opcode;

                // The escape carries the operand size and the register
                // extensions itself, so a 66, F2, F3, LOCK or REX in front of
                // it is invalid. A segment or 67 prefix still applies.
                if (rex != 0 || (pref & (PRE_66 | PRE_F2 | PRE_F3 | PRE_LOCK)) != 0)
                    hs.Flags |= F_ERROR | F_ERROR_OPCODE;
                pref &= 0xf7;               // pref &= ~PRE_66

                cflags = C_MODRM;
                if (c == 0x8f)
                {
                    switch (map)
                    {
                        case 8:                 // every XOP8 opcode takes an imm8
                            cflags |= C_IMM8;
                            break;
                        case 9:                 // no XOP9 opcode takes one
                            break;
                        case 10:                // bextr and the lwp forms: imm32
                            cflags |= C_IMM_P66;
                            break;
                        default:
                            hs.Flags |= F_ERROR | F_ERROR_OPCODE;
                            break;
                    }
                }
                else
                {
                    switch (map)
                    {
                        case 1:                 // 0F map
                            if (opcode == 0x70 || (opcode >= 0x71 && opcode <= 0x73) ||
                                opcode == 0xc2 || (opcode >= 0xc4 && opcode <= 0xc6))
                                cflags |= C_IMM8;
                            else if (c != 0x62 && opcode == 0x77)
                                cflags = C_NONE;    // vzeroupper and vzeroall: no ModR/M
                            else if (c != 0x62 && (opcode == 0x84 || opcode == 0x85))
                                cflags = C_REL32;   // jkzd and jknzd: rel32, no ModR/M
                            break;
                        case 2:                 // 0F 38 map: never an immediate
                            break;
                        case 3:                 // 0F 3A map: always an imm8
                            cflags |= C_IMM8;
                            break;
                        case 5:
                        case 6:         // half-precision maps, EVEX only
                            if (c != 0x62)
                                hs.Flags |= F_ERROR | F_ERROR_OPCODE;
                            else if (map == 5 && (opcode == 0x08 || opcode == 0x0a ||
                                                  opcode == 0x26 || opcode == 0x27 ||
                                                  opcode == 0x56 || opcode == 0x57 ||
                                                  opcode == 0x66 || opcode == 0x67 ||
                                                  opcode == 0xc2))
                                cflags |= C_IMM8;   // the 0F 3A forms of that map
                            break;
                        default:
                            hs.Flags |= F_ERROR | F_ERROR_OPCODE;
                            break;
                    }
                }
                extPath = true;
                x = 0;
                goto modrm;
            }

            // REX2: D5, a payload byte, then the opcode. The payload names the
            // opcode map in its top bit, so a 0F opcode is reached without the
            // 0F byte, and carries the register extensions, with W where REX
            // keeps it. Only legacy instructions are promoted this way, so
            // the tables give the right shape once the map is known.
            if (c == 0xd5)
            {
                if (limit - p < 2) goto errorLength;
                byte rex2 = code[p++];
                haveRex2 = true;
                c = code[p++];
                hs.Flags |= F_PREFIX_REX2;
                if (rex != 0)           // REX2 replaces a REX, it cannot follow one
                    hs.Flags |= F_ERROR | F_ERROR_OPCODE;
                hs.RexW = (byte)((rex2 & 8) >> 3);
                hs.RexR = (byte)((rex2 & 4) >> 2);
                hs.RexX = (byte)((rex2 & 2) >> 1);
                hs.RexB = (byte)(rex2 & 1);
                if ((rex2 & 0x80) != 0)
                {
                    hs.Opcode = 0xd5;
                    hs.Opcode2 = c;
                    map0f = 1;
                    ht += DELTA_OPCODES;
                    goto opcodeReady;
                }
                // Map 0 is the one-byte map, and REX2 has to be the last byte
                // before the opcode: neither the 0F escape nor a further
                // prefix can follow it. 8F is deliberately absent: it is POP
                // here, not an XOP escape.
                if (c == 0x0f || (c & 0xf0) == 0x40 ||
                    c == 0x26 || c == 0x2e || c == 0x36 || c == 0x3e ||
                    c == 0x64 || c == 0x65 || c == 0x66 || c == 0x67 ||
                    c == 0xf0 || c == 0xf2 || c == 0xf3)
                    hs.Flags |= F_ERROR | F_ERROR_OPCODE;
                if (hs.RexW != 0 && (c & 0xf8) == 0xb8)
                    op64++;             // B8+r, map 0's mov r64, imm64
            }

            hs.Opcode = c;
            if (!haveRex2 && c == 0x0f)
            {
                if (limit - p < 1) goto errorLength;
                hs.Opcode2 = c = code[p++];
                map0f = 1;
                if (c == 0x38 || c == 0x3a)
                {
                    // Three-byte maps: the opcode follows and always has a
                    // ModR/M byte. Every 0F 3A opcode takes an imm8, no 0F 38
                    // one does, and none of them is lockable.
                    if (limit - p < 2) goto errorLength;
                    opcode = code[p++];
                    hs.Opcode3 = opcode;
                    cflags = (byte)((c == 0x3a) ? (C_MODRM | C_IMM8) : C_MODRM);
                    if ((pref & PRE_LOCK) != 0)
                        hs.Flags |= F_ERROR | F_ERROR_LOCK;
                    extPath = true;
                    x = 0;
                    goto modrm;
                }
                ht += DELTA_OPCODES;
            }
            else if (c >= 0xa0 && c <= 0xa3)
            {
                // moffs: the absolute address is as wide as the address size,
                // so eight bytes unless 67 selects 32-bit addressing.
                if ((pref & PRE_67) == 0) op64++;
                pref &= 0xf7;               // pref &= ~PRE_66
            }

        opcodeReady:
            opcode = c;
            cflags = (byte)T[ht + T[ht + opcode / 4] + (opcode % 4)];

            if (cflags == C_ERROR)
            {
                // The table carries no entry for the opcode. Some of these
                // are real instructions whose shape is known; the rest keep
                // F_ERROR, because the opcode is not one this engine can
                // claim to know.
                cflags = C_NONE;
                if (map0f != 0 && (opcode == 0x0b ||
                                   (opcode == 0x37 && mand == PRE_NONE)))
                {
                    ;                       // ud2 and getsec take no operand
                }
                else if (map0f != 0 && (opcode == 0xa6 || opcode == 0xa7 ||
                                        opcode == 0xb9 || opcode == 0xff))
                {
                    cflags = C_MODRM;       // PadLock, ud1 and ud0
                }
                else if (map0f == 0 && (opcode == 0x9e || opcode == 0x9f))
                {
                    ;                       // sahf and lahf, back since 2006
                }
                else
                {
                    hs.Flags |= F_ERROR | F_ERROR_OPCODE;
                    if (map0f != 0 && (opcode & 0xfd) == 0x24)
                        cflags = C_MODRM;   // the test registers: shape only
                }
            }

            x = 0;
            if ((cflags & C_GROUP) != 0)
            {
                int g = ht + (cflags & 0x7f);
                int t = T[g] | (T[g + 1] << 8);
                cflags = (byte)t;
                x = (byte)(t >> 8);
            }

            if (map0f != 0)
            {
                // movntsd and movntss are F2 0F 2B and F3 0F 2B. The row 0F 2B
                // read here rejects both, and it is shared with a neighbour
                // that has no such form, so the exception lives here rather
                // than in the table.
                if ((T[DELTA_PREFIXES + T[DELTA_PREFIXES + opcode / 4] +
                       (opcode % 4)] & mand) != 0 &&
                    !(opcode == 0x2b && (mand & (PRE_F2 | PRE_F3)) != 0))
                    hs.Flags |= F_ERROR | F_ERROR_OPCODE;
                // vmread, vmwrite and popcnt take a ModR/M byte that the
                // table cannot give them: their entries share a row with
                // opcodes that take none.
                if (opcode == 0x78 || opcode == 0x79 || opcode == 0xb8)
                    cflags |= C_MODRM;
            }

        modrm:
            if ((cflags & C_MODRM) != 0)
            {
                hs.Flags |= F_MODRM;
                if (limit - p < 1) goto errorLength;
                hs.Modrm = c = code[p++];
                hs.ModrmMod = (byte)(m_mod = c >> 6);
                hs.ModrmRm = (byte)(m_rm = c & 7);
                hs.ModrmReg = (byte)(m_reg = (c & 0x3f) >> 3);

                if (x != 0 && ((x << m_reg) & 0x80) != 0)
                    hs.Flags |= F_ERROR | F_ERROR_OPCODE;

                if (extPath) goto noErrorOperand;   // no legacy operand rule applies

                if (map0f == 0 && opcode >= 0xd9 && opcode <= 0xdf)
                {
                    int t = opcode - 0xd9;
                    if (m_mod == 3)
                    {
                        t = T[DELTA_FPU_MODRM + t * 8 + m_reg] << m_rm;
                    }
                    else
                    {
                        t = T[DELTA_FPU_REG + t] << m_reg;
                    }
                    if ((t & 0x80) != 0)
                        hs.Flags |= F_ERROR | F_ERROR_OPCODE;
                }

                if ((pref & PRE_LOCK) != 0)
                {
                    if (m_mod == 3)
                    {
                        hs.Flags |= F_ERROR | F_ERROR_LOCK;
                    }
                    else
                    {
                        int pht, tableEnd, op = opcode;
                        if (map0f != 0)
                        {
                            pht = DELTA_OP2_LOCK_OK;
                            tableEnd = DELTA_OP_ONLY_MEM;
                        }
                        else
                        {
                            pht = DELTA_OP_LOCK_OK;
                            tableEnd = DELTA_OP2_LOCK_OK;
                            op &= 0xfe;     // op &= -2
                        }
                        bool noLockError = false;
                        while (pht != tableEnd)
                        {
                            if (T[pht] == op)
                            {
                                if (((T[pht + 1] << m_reg) & 0x80) == 0)
                                    noLockError = true;
                                break;
                            }
                            pht += 2;
                        }
                        if (!noLockError)
                            hs.Flags |= F_ERROR | F_ERROR_LOCK;
                    }
                }

                if (map0f != 0)
                {
                    switch (opcode)
                    {
                        case 0x20:
                        case 0x22:
                            m_mod = 3;
                            if (m_reg > 4 || m_reg == 1) goto errorOperand;
                            goto noErrorOperand;
                        case 0x21:
                        case 0x23:
                            m_mod = 3;
                            // dr4 and dr5 alias dr6 and dr7 unless CR4.DE is
                            // set, so they decode rather than fault.
                            goto noErrorOperand;
                    }
                }
                else
                {
                    switch (opcode)
                    {
                        case 0x8c:
                            if (m_reg > 5) goto errorOperand;
                            goto noErrorOperand;
                        case 0x8e:
                            if (m_reg == 1 || m_reg > 5) goto errorOperand;
                            goto noErrorOperand;
                    }
                }

                if (m_mod == 3)
                {
                    int pht, tableEnd;
                    if (map0f != 0)
                    {
                        pht = DELTA_OP2_ONLY_MEM;
                        tableEnd = T.Length;
                    }
                    else
                    {
                        pht = DELTA_OP_ONLY_MEM;
                        tableEnd = DELTA_OP2_ONLY_MEM;
                    }
                    while (pht != tableEnd)
                    {
                        if (T[pht] == opcode)
                        {
                            // 3-byte entries: opcode, mandatory-prefix mask,
                            // register bits. The C's for(*ht++)+ht+=2 step is
                            // 3 on a non-match.
                            if ((T[pht + 1] & mand) != 0 &&
                                ((T[pht + 2] << m_reg) & 0x80) == 0)
                                goto errorOperand;
                            break;
                        }
                        pht += 3;
                    }
                    goto noErrorOperand;
                }
                else if (map0f != 0)
                {
                    switch (opcode)
                    {
                        case 0x50:
                        case 0xd7:
                        case 0xf7:
                            if ((mand & (PRE_NONE | PRE_66)) != 0) goto errorOperand;
                            break;
                        case 0xd6:
                            if ((mand & (PRE_F2 | PRE_F3)) != 0) goto errorOperand;
                            break;
                        case 0xc5:
                            goto errorOperand;
                    }
                    goto noErrorOperand;
                }
                else
                {
                    goto noErrorOperand;
                }

            errorOperand:
                hs.Flags |= F_ERROR | F_ERROR_OPERAND;
            noErrorOperand:

                // Group 3: F6 /0 and /1 take an imm8, F7 /0 and /1 an imm32 or
                // imm16. The rule belongs to the one-byte map; 0F F6 and 0F F7
                // are psadbw and maskmovq, which take neither.
                if (!extPath && map0f == 0 && m_reg <= 1)
                {
                    if (opcode == 0xf6) cflags |= C_IMM8;
                    else if (opcode == 0xf7) cflags |= C_IMM_P66;
                }
                // C7 /7 is xbegin, whose immediate is a displacement.
                if (!extPath && map0f == 0 && opcode == 0xc7 && m_reg == 7)
                    hs.Flags |= F_RELATIVE;
                // extrq and insertq take two imm8 operands where vmread takes
                // none.
                if (!extPath && map0f != 0 && opcode == 0x78 &&
                    (mand & (PRE_66 | PRE_F2)) != 0)
                    cflags |= C_IMM16;

                switch (m_mod)
                {
                    case 0:
                        if (m_rm == 5) dispSize = 4;
                        break;
                    case 1:
                        dispSize = 1;
                        break;
                    case 2:
                        dispSize = 4;
                        break;
                }

                if (m_mod != 3 && m_rm == 4)
                {
                    hs.Flags |= F_SIB;
                    if (limit - p < 1) goto errorLength;
                    hs.Sib = c = code[p++];
                    hs.SibScale = (byte)(c >> 6);
                    hs.SibIndex = (byte)((c & 0x3f) >> 3);
                    hs.SibBase = (byte)(c & 7);
                    if (hs.SibBase == 5 && (m_mod & 1) == 0)
                        dispSize = 4;
                }

                if (dispSize != 0)
                {
                    if (limit - p < dispSize) goto errorLength;
                    if (dispSize == 1)
                    {
                        hs.Flags |= F_DISP8;
                        hs.Disp = code[p];
                    }
                    else
                    {
                        hs.Flags |= F_DISP32;
                        hs.Disp = (uint)(code[p] | (code[p + 1] << 8) |
                                         (code[p + 2] << 16) | (code[p + 3] << 24));
                    }
                    p += dispSize;
                }
            }
            else if ((pref & PRE_LOCK) != 0)
            {
                hs.Flags |= F_ERROR | F_ERROR_LOCK;
            }

            // An operand-size dependent immediate is 32 bits wide, 16 under a
            // 66 prefix, and 32 again when a REX.W overrides that prefix.
            bool done = false;
            bool rel32Pending = false;  // C's "goto rel32_ok" from the P66 block
            if ((cflags & C_IMM_P66) != 0)
            {
                if ((cflags & C_REL32) != 0)
                {
                    if ((pref & PRE_66) != 0 && hs.RexW == 0)
                    {
                        if (limit - p < 2) goto errorLength;
                        hs.Flags |= F_IMM16 | F_RELATIVE;
                        hs.Imm = (ulong)(ushort)(code[p] | (code[p + 1] << 8));
                        p += 2;
                        done = true;
                    }
                    else
                    {
                        rel32Pending = true;
                    }
                }
                else if (op64 != 0)
                {
                    if (limit - p < 8) goto errorLength;
                    hs.Flags |= F_IMM64;
                    ulong v = 0;
                    for (int i = 7; i >= 0; i--) v = (v << 8) | code[p + i];
                    hs.Imm = v;
                    p += 8;
                }
                else if ((pref & PRE_66) == 0 || hs.RexW != 0)
                {
                    if (limit - p < 4) goto errorLength;
                    hs.Flags |= F_IMM32;
                    hs.Imm = (ulong)(uint)(code[p] | (code[p + 1] << 8) |
                                           (code[p + 2] << 16) | (code[p + 3] << 24));
                    p += 4;
                }
                else
                {
                    if (limit - p < 2) goto errorLength;
                    hs.Flags |= F_IMM16;
                    hs.Imm = (ulong)(ushort)(code[p] | (code[p + 1] << 8));
                    p += 2;
                }
            }

            if (!done && (cflags & C_IMM16) != 0 && (hs.Flags & F_IMM16) == 0)
            {
                if (limit - p < 2) goto errorLength;
                hs.Flags |= F_IMM16;
                hs.Imm = (ulong)(ushort)(code[p] | (code[p + 1] << 8));
                p += 2;
            }
            if (!done && (cflags & C_IMM8) != 0)
            {
                if (limit - p < 1) goto errorLength;
                hs.Flags |= F_IMM8;
                if ((hs.Flags & F_IMM16) != 0)
                    hs.Disp = code[p++];    // enter: the union holds the imm16
                else
                    hs.Imm = (hs.Imm & ~0xFFUL) | code[p++];
            }

            if (!done)
            {
                if ((cflags & C_REL32) != 0 || rel32Pending)
                {
                    if (limit - p < 4) goto errorLength;
                    hs.Flags |= F_IMM32 | F_RELATIVE;
                    hs.Imm = (ulong)(uint)(code[p] | (code[p + 1] << 8) |
                                           (code[p + 2] << 16) | (code[p + 3] << 24));
                    p += 4;
                }
                else if ((cflags & C_REL8) != 0)
                {
                    if (limit - p < 1) goto errorLength;
                    hs.Flags |= F_IMM8 | F_RELATIVE;
                    hs.Imm = code[p++];
                }
            }

            // C's disasm_done: every path falls through to here.

            hs.Len = (byte)(p - pos);
            hs.Map0f = map0f != 0;
            hsOut = hs;
            return hs.Len;

        errorLength:

            hs.Flags |= F_ERROR | F_ERROR_LENGTH;
            hs.Len = 15;
            hsOut = hs;
            return 15;
        }
    }
}
