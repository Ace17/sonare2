// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

import std.format;

import arch;
import document;

alias uint8 = ubyte;
alias uint16 = ushort;
alias uint32 = uint;

static this()
{
  g_Architectures.register("nes", new NesArchitecture);
}

// 6502 variant for the NES
class NesArchitecture : Architecture
{
  Instruction disassemble(const(ubyte)[] code, ulong pc)
  {
    auto ctx = Context(code, cast(uint)pc);
    return ctx.disassemble();
  }
}

struct Context
{
  const(ubyte)[] code;
  uint PC;
  int size;

  Instruction disassemble()
  {
    Instruction r;
    r.type = Type.Op;
    r.address = PC;
    size += 1;

    // See: http://nparker.llx.com/a2/opcodes.html
    const aaa = (code[0] & 0b111_000_00) >> 5;
    const bbb = (code[0] & 0b000_111_00) >> 2;
    const cc = (code[0] & 0b000_000_11) >> 0;

    string op;
    int type;
    switch(code[0])
    {
    case 0x00: op = "brk";
      type = _imp;
      break;
    case 0x01: op = "ora";
      type = _ind_x;
      break;
    case 0x02: op = "jam";
      type = _imp;
      break;
    case 0x03: op = "slo";
      type = _ind_x;
      break;
    case 0x04: op = "nop";
      type = _zero;
      break;
    case 0x05: op = "ora";
      type = _zero;
      break;
    case 0x06: op = "asl";
      type = _zero;
      break;
    case 0x07: op = "slo";
      type = _zero;
      break;
    case 0x08: op = "php";
      type = _imp;
      break;
    case 0x09: op = "ora";
      type = _imm;
      break;
    case 0x0a: op = "asl";
      type = _acc;
      break;
    case 0x0b: op = "anc";
      type = _imm;
      break;
    case 0x0c: op = "nop";
      type = _abs;
      break;
    case 0x0d: op = "ora";
      type = _abs;
      break;
    case 0x0e: op = "asl";
      type = _abs;
      break;
    case 0x0f: op = "slo";
      type = _abs;
      break;
    case 0x10: op = "bpl";
      type = _rel;
      break;
    case 0x11: op = "ora";
      type = _ind_y;
      break;
    case 0x12: op = "jam";
      type = _imp;
      break;
    case 0x13: op = "slo";
      type = _ind_y;
      break;
    case 0x14: op = "nop";
      type = _zero_x;
      break;
    case 0x15: op = "ora";
      type = _zero_x;
      break;
    case 0x16: op = "asl";
      type = _zero_x;
      break;
    case 0x17: op = "slo";
      type = _zero_x;
      break;
    case 0x18: op = "clc";
      type = _imp;
      break;
    case 0x19: op = "ora";
      type = _abs_y;
      break;
    case 0x1a: op = "nop";
      type = _imp;
      break;
    case 0x1b: op = "slo";
      type = _abs_y;
      break;
    case 0x1c: op = "nop";
      type = _abs_x;
      break;
    case 0x1d: op = "ora";
      type = _abs_x;
      break;
    case 0x1e: op = "asl";
      type = _abs_x;
      break;
    case 0x1f: op = "slo";
      type = _abs_x;
      break;
    case 0x20: op = "jsr";
      type = _abs;
      break;
    case 0x21: op = "and";
      type = _ind_x;
      break;
    case 0x22: op = "jam";
      type = _imp;
      break;
    case 0x23: op = "rla";
      type = _ind_x;
      break;
    case 0x24: op = "bit";
      type = _zero;
      break;
    case 0x25: op = "and";
      type = _zero;
      break;
    case 0x26: op = "rol";
      type = _zero;
      break;
    case 0x27: op = "rla";
      type = _zero;
      break;
    case 0x28: op = "plp";
      type = _imp;
      break;
    case 0x29: op = "and";
      type = _imm;
      break;
    case 0x2a: op = "rol";
      type = _acc;
      break;
    case 0x2b: op = "anc";
      type = _imm;
      break;
    case 0x2c: op = "bit";
      type = _abs;
      break;
    case 0x2d: op = "and";
      type = _abs;
      break;
    case 0x2e: op = "rol";
      type = _abs;
      break;
    case 0x2f: op = "rla";
      type = _abs;
      break;
    case 0x30: op = "bmi";
      type = _rel;
      break;
    case 0x31: op = "and";
      type = _ind_y;
      break;
    case 0x32: op = "jam";
      type = _imp;
      break;
    case 0x33: op = "rla";
      type = _ind_y;
      break;
    case 0x34: op = "nop";
      type = _imp;
      break;
    case 0x35: op = "and";
      type = _zero_x;
      break;
    case 0x36: op = "rol";
      type = _zero_x;
      break;
    case 0x37: op = "rla";
      type = _zero_x;
      break;
    case 0x38: op = "sec";
      type = _imp;
      break;
    case 0x39: op = "and";
      type = _abs_y;
      break;
    case 0x3a: op = "nop";
      type = _imp;
      break;
    case 0x3b: op = "rla";
      type = _abs_y;
      break;
    case 0x3c: op = "nop";
      type = _abs_x;
      break;
    case 0x3d: op = "and";
      type = _abs_x;
      break;
    case 0x3e: op = "rol";
      type = _abs_x;
      break;
    case 0x3f: op = "rla";
      type = _abs_x;
      break;
    case 0x40: op = "rti";
      type = _imp;
      break;
    case 0x41: op = "eor";
      type = _ind_x;
      break;
    case 0x42: op = "jam";
      type = _imp;
      break;
    case 0x43: op = "sre";
      type = _ind_x;
      break;
    case 0x44: op = "nop";
      type = _zero;
      break;
    case 0x45: op = "eor";
      type = _zero;
      break;
    case 0x46: op = "lsr";
      type = _zero;
      break;
    case 0x47: op = "sre";
      type = _zero;
      break;
    case 0x48: op = "pha";
      type = _imp;
      break;
    case 0x49: op = "eor";
      type = _imm;
      break;
    case 0x4a: op = "lsr";
      type = _acc;
      break;
    case 0x4b: op = "asr";
      type = _imm;
      break;
    case 0x4c: op = "jmp";
      type = _abs;
      break;
    case 0x4d: op = "eor";
      type = _abs;
      break;
    case 0x4e: op = "lsr";
      type = _abs;
      break;
    case 0x4f: op = "sre";
      type = _abs;
      break;
    case 0x50: op = "bvc";
      type = _rel;
      break;
    case 0x51: op = "eor";
      type = _ind_y;
      break;
    case 0x52: op = "jam";
      type = _imp;
      break;
    case 0x53: op = "sre";
      type = _ind_y;
      break;
    case 0x54: op = "nop";
      type = _zero_x;
      break;
    case 0x55: op = "eor";
      type = _zero_x;
      break;
    case 0x56: op = "lsr";
      type = _zero_x;
      break;
    case 0x57: op = "sre";
      type = _zero_x;
      break;
    case 0x58: op = "cli";
      type = _imp;
      break;
    case 0x59: op = "eor";
      type = _abs_y;
      break;
    case 0x5a: op = "nop";
      type = _imp;
      break;
    case 0x5b: op = "sre";
      type = _abs_y;
      break;
    case 0x5c: op = "nop";
      type = _abs_x;
      break;
    case 0x5d: op = "eor";
      type = _abs_x;
      break;
    case 0x5e: op = "lsr";
      type = _abs_x;
      break;
    case 0x5f: op = "sre";
      type = _abs_x;
      break;
    case 0x60: op = "rts";
      type = _imp;
      break;
    case 0x61: op = "adc";
      type = _ind_x;
      break;
    case 0x62: op = "jam";
      type = _imp;
      break;
    case 0x63: op = "rra";
      type = _ind_x;
      break;
    case 0x64: op = "nop";
      type = _zero;
      break;
    case 0x65: op = "adc";
      type = _zero;
      break;
    case 0x66: op = "ror";
      type = _zero;
      break;
    case 0x67: op = "rra";
      type = _zero;
      break;
    case 0x68: op = "pla";
      type = _imp;
      break;
    case 0x69: op = "adc";
      type = _imm;
      break;
    case 0x6a: op = "ror";
      type = _acc;
      break;
    case 0x6b: op = "arr";
      type = _imm;
      break;
    case 0x6c: op = "jmp";
      type = _ind;
      break;
    case 0x6d: op = "adc";
      type = _abs;
      break;
    case 0x6e: op = "ror";
      type = _abs;
      break;
    case 0x6f: op = "rra";
      type = _abs;
      break;
    case 0x70: op = "bvs";
      type = _rel;
      break;
    case 0x71: op = "adc";
      type = _ind_y;
      break;
    case 0x72: op = "jam";
      type = _imp;
      break;
    case 0x73: op = "rra";
      type = _ind_y;
      break;
    case 0x74: op = "nop";
      type = _zero_x;
      break;
    case 0x75: op = "adc";
      type = _zero_x;
      break;
    case 0x76: op = "ror";
      type = _zero_x;
      break;
    case 0x77: op = "rra";
      type = _zero_x;
      break;
    case 0x78: op = "sei";
      type = _imp;
      break;
    case 0x79: op = "adc";
      type = _abs_y;
      break;
    case 0x7a: op = "nop";
      type = _imp;
      break;
    case 0x7b: op = "rra";
      type = _abs_y;
      break;
    case 0x7c: op = "nop";
      type = _abs_x;
      break;
    case 0x7d: op = "adc";
      type = _abs_x;
      break;
    case 0x7e: op = "ror";
      type = _abs_x;
      break;
    case 0x7f: op = "rra";
      type = _abs_x;
      break;
    case 0x80: op = "nop";
      type = _imm;
      break;
    case 0x81: op = "sta";
      type = _ind_x;
      break;
    case 0x82: op = "nop";
      type = _imm;
      break;
    case 0x83: op = "sax";
      type = _ind_x;
      break;
    case 0x84: op = "sty";
      type = _zero;
      break;
    case 0x85: op = "sta";
      type = _zero;
      break;
    case 0x86: op = "stx";
      type = _zero;
      break;
    case 0x87: op = "sax";
      type = _zero;
      break;
    case 0x88: op = "dey";
      type = _imp;
      break;
    case 0x89: op = "nop";
      type = _imm;
      break;
    case 0x8a: op = "txa";
      type = _imp;
      break;
    case 0x8b: op = "ane";
      type = _imm;
      break;
    case 0x8c: op = "sty";
      type = _abs;
      break;
    case 0x8d: op = "sta";
      type = _abs;
      break;
    case 0x8e: op = "stx";
      type = _abs;
      break;
    case 0x8f: op = "sax";
      type = _abs;
      break;
    case 0x90: op = "bcc";
      type = _rel;
      break;
    case 0x91: op = "sta";
      type = _ind_y;
      break;
    case 0x92: op = "jam";
      type = _imp;
      break;
    case 0x93: op = "sha";
      type = _ind_y;
      break;
    case 0x94: op = "sty";
      type = _zero_x;
      break;
    case 0x95: op = "sta";
      type = _zero_x;
      break;
    case 0x96: op = "stx";
      type = _zero_y;
      break;
    case 0x97: op = "sax";
      type = _zero_y;
      break;
    case 0x98: op = "tya";
      type = _imp;
      break;
    case 0x99: op = "sta";
      type = _abs_y;
      break;
    case 0x9a: op = "txs";
      type = _imp;
      break;
    case 0x9b: op = "shs";
      type = _abs_y;
      break;
    case 0x9c: op = "shy";
      type = _abs_x;
      break;
    case 0x9d: op = "sta";
      type = _abs_x;
      break;
    case 0x9e: op = "shx";
      type = _abs_y;
      break;
    case 0x9f: op = "sha";
      type = _abs_y;
      break;
    case 0xa0: op = "ldy";
      type = _imm;
      break;
    case 0xa1: op = "lda";
      type = _ind_x;
      break;
    case 0xa2: op = "ldx";
      type = _imm;
      break;
    case 0xa3: op = "lax";
      type = _ind_x;
      break;
    case 0xa4: op = "ldy";
      type = _zero;
      break;
    case 0xa5: op = "lda";
      type = _zero;
      break;
    case 0xa6: op = "ldx";
      type = _zero;
      break;
    case 0xa7: op = "lax";
      type = _zero;
      break;
    case 0xa8: op = "tay";
      type = _imp;
      break;
    case 0xa9: op = "lda";
      type = _imm;
      break;
    case 0xaa: op = "tax";
      type = _imp;
      break;
    case 0xab: op = "lxa";
      type = _imm;
      break;
    case 0xac: op = "ldy";
      type = _abs;
      break;
    case 0xad: op = "lda";
      type = _abs;
      break;
    case 0xae: op = "ldx";
      type = _abs;
      break;
    case 0xaf: op = "lax";
      type = _abs;
      break;
    case 0xb0: op = "bcs";
      type = _rel;
      break;
    case 0xb1: op = "lda";
      type = _ind_y;
      break;
    case 0xb2: op = "jam";
      type = _imp;
      break;
    case 0xb3: op = "lax";
      type = _ind_y;
      break;
    case 0xb4: op = "ldy";
      type = _zero_x;
      break;
    case 0xb5: op = "lda";
      type = _zero_x;
      break;
    case 0xb6: op = "ldx";
      type = _zero_y;
      break;
    case 0xb7: op = "lax";
      type = _zero_y;
      break;
    case 0xb8: op = "clv";
      type = _imp;
      break;
    case 0xb9: op = "lda";
      type = _abs_y;
      break;
    case 0xba: op = "tsx";
      type = _imp;
      break;
    case 0xbb: op = "las";
      type = _abs_y;
      break;
    case 0xbc: op = "ldy";
      type = _abs_x;
      break;
    case 0xbd: op = "lda";
      type = _abs_x;
      break;
    case 0xbe: op = "ldx";
      type = _abs_y;
      break;
    case 0xbf: op = "lax";
      type = _abs_y;
      break;
    case 0xc0: op = "cpy";
      type = _imm;
      break;
    case 0xc1: op = "cmp";
      type = _ind_x;
      break;
    case 0xc2: op = "nop";
      type = _imm;
      break;
    case 0xc3: op = "dcp";
      type = _ind_x;
      break;
    case 0xc4: op = "cpy";
      type = _zero;
      break;
    case 0xc5: op = "cmp";
      type = _zero;
      break;
    case 0xc6: op = "dec";
      type = _zero;
      break;
    case 0xc7: op = "dcp";
      type = _zero;
      break;
    case 0xc8: op = "iny";
      type = _imp;
      break;
    case 0xc9: op = "cmp";
      type = _imm;
      break;
    case 0xca: op = "dex";
      type = _imp;
      break;
    case 0xcb: op = "sbx";
      type = _imm;
      break;
    case 0xcc: op = "cpy";
      type = _abs;
      break;
    case 0xcd: op = "cmp";
      type = _abs;
      break;
    case 0xce: op = "dec";
      type = _abs;
      break;
    case 0xcf: op = "dcp";
      type = _abs;
      break;
    case 0xd0: op = "bne";
      type = _rel;
      break;
    case 0xd1: op = "cmp";
      type = _ind_y;
      break;
    case 0xd2: op = "jam";
      type = _imp;
      break;
    case 0xd3: op = "dcp";
      type = _ind_y;
      break;
    case 0xd4: op = "nop";
      type = _zero_x;
      break;
    case 0xd5: op = "cmp";
      type = _zero_x;
      break;
    case 0xd6: op = "dec";
      type = _zero_x;
      break;
    case 0xd7: op = "dcp";
      type = _zero_x;
      break;
    case 0xd8: op = "cld";
      type = _imp;
      break;
    case 0xd9: op = "cmp";
      type = _abs_y;
      break;
    case 0xda: op = "nop";
      type = _imp;
      break;
    case 0xdb: op = "dcp";
      type = _abs_y;
      break;
    case 0xdc: op = "nop";
      type = _abs_x;
      break;
    case 0xdd: op = "cmp";
      type = _abs_x;
      break;
    case 0xde: op = "dec";
      type = _abs_x;
      break;
    case 0xdf: op = "dcp";
      type = _abs_x;
      break;
    case 0xe0: op = "cpx";
      type = _imm;
      break;
    case 0xe1: op = "sbc";
      type = _ind_x;
      break;
    case 0xe2: op = "nop";
      type = _imm;
      break;
    case 0xe3: op = "isb";
      type = _ind_x;
      break;
    case 0xe4: op = "cpx";
      type = _zero;
      break;
    case 0xe5: op = "sbc";
      type = _zero;
      break;
    case 0xe6: op = "inc";
      type = _zero;
      break;
    case 0xe7: op = "isb";
      type = _zero;
      break;
    case 0xe8: op = "inx";
      type = _imp;
      break;
    case 0xe9: op = "sbc";
      type = _imm;
      break;
    case 0xea: op = "nop";
      type = _imp;
      break;
    case 0xeb: op = "sbc";
      type = _imm;
      break;
    case 0xec: op = "cpx";
      type = _abs;
      break;
    case 0xed: op = "sbc";
      type = _abs;
      break;
    case 0xee: op = "inc";
      type = _abs;
      break;
    case 0xef: op = "isb";
      type = _abs;
      break;
    case 0xf0: op = "beq";
      type = _rel;
      break;
    case 0xf1: op = "sbc";
      type = _ind_y;
      break;
    case 0xf2: op = "jam";
      type = _imp;
      break;
    case 0xf3: op = "isb";
      type = _ind_y;
      break;
    case 0xf4: op = "nop";
      type = _zero_x;
      break;
    case 0xf5: op = "sbc";
      type = _zero_x;
      break;
    case 0xf6: op = "inc";
      type = _zero_x;
      break;
    case 0xf7: op = "isb";
      type = _zero_x;
      break;
    case 0xf8: op = "sed";
      type = _imp;
      break;
    case 0xf9: op = "sbc";
      type = _abs_y;
      break;
    case 0xfa: op = "nop";
      type = _imp;
      break;
    case 0xfb: op = "isb";
      type = _abs_y;
      break;
    case 0xfc: op = "nop";
      type = _abs_x;
      break;
    case 0xfd: op = "sbc";
      type = _abs_x;
      break;
    case 0xfe: op = "inc";
      type = _abs_x;
      break;
    case 0xff: op = "isb";
      type = _abs_x;
      break;
    default:
      assert(0);
    }

    r.operands = parseOperand(type);

    r.bytes = code[0 .. size];
    r.mnemonic = op;
    return r;
  }

  // addressing modes
  enum
  {
    _imp,
    _acc,
    _rel,
    _imm,
    _abs,
    _abs_x,
    _abs_y,
    _zero,
    _zero_x,
    _zero_y,
    _ind,
    _ind_x,
    _ind_y
  };

  uint8 dis_op8()
  {
    size += 1;
    return code[1];
  }

  uint16 dis_op16()
  {
    size += 2;
    return code[1] + (code[2] << 8);
  }

  Expr[] dis_show_ind()
  {
    auto deref = new DerefExpr();
    deref.sub = val(dis_op16());
    return [deref];
  }

  Expr[] dis_show_ind_x()
  {
    auto deref = new DerefExpr();
    deref.sub = val(dis_op8());
    return [deref, id("x")];
  }

  Expr[] dis_show_ind_y()
  {
    auto deref = new DerefExpr();
    deref.sub = val(dis_op8());
    return [deref, id("y")];
  }

  Expr parseRelative()
  {
    const target = PC + 2 + dis_op8();
    return val(target);
  }

  Expr[] parseOperand(int optype)
  {
    switch(optype)
    {
    case _imp:     return [];
    case _acc:     return [id("a")];
    case _rel:     return [parseRelative()];
    case _imm:     return [val(dis_op8())];
    case _abs:     return [val(dis_op16())];
    case _abs_x:   return [val(dis_op16()), id("x")];
    case _abs_y:   return [val(dis_op16()), id("y")];
    case _zero:    return [val(0)];
    case _zero_x:  return [val(dis_op8()), id("x")];
    case _zero_y:  return [val(dis_op8()), id("y")];
    case _ind:     return dis_show_ind();
    case _ind_x:   return dis_show_ind_x();
    case _ind_y:   return dis_show_ind_y();
    default:
      assert(0);
    }
  }

  Expr val(int value)
  {
    auto r = new NumberExpr;
    r.value = value;
    return r;
  }

  Expr id(string name)
  {
    auto r = new IdentifierExpr;
    r.name = name;
    return r;
  }
}

