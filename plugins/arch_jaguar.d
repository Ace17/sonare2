// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

import arch;
import document;

static this()
{
  g_Architectures.register("jaguar-gpu", new JaguarArchitecture!true);
  g_Architectures.register("jaguar-dsp", new JaguarArchitecture!false);
}

class JaguarArchitecture(bool isGpu) : Architecture
{
  void disassemble(Document doc)
  {
    int pc = cast(int)doc.address;
    int i = 0;

    while(i < cast(int)doc.data.length)
    {
      auto instruction = dasmInstruction(isGpu, pc, doc.data[i .. $]);
      const size = instruction.bytes.length;

      if(!size)
        break;

      doc.instructions ~= instruction;

      i += size;
      pc += size;
    }
  }
}

int notZero(int input)
{
  return input ? input : 32;
}

immutable condition =
[
  /* 00 */ "",
  /* 01 */ "nz",
  /* 02 */ "z",
  /* 03 */ "?",
  /* 04 */ "nc",
  /* 05 */ "nc/nz",
  /* 06 */ "nc/z",
  /* 07 */ "?",
  /* 08 */ "c",
  /* 09 */ "c/nz",
  /* 10 */ "c/z",
  /* 11 */ "?",
  /* 12 */ "?",
  /* 13 */ "?",
  /* 14 */ "?",
  /* 15 */ "?",
  /* 16 */ "?",
  /* 17 */ "?",
  /* 18 */ "?",
  /* 19 */ "?",
  /* 20 */ "nn",
  /* 21 */ "nn/nz",
  /* 22 */ "nn/z",
  /* 23 */ "?",
  /* 24 */ "n",
  /* 25 */ "n/nz",
  /* 26 */ "n/z",
  /* 27 */ "?",
  /* 28 */ "?",
  /* 29 */ "?",
  /* 30 */ "?",
  /* 31 */ "never"
];

immutable RegisterNames =
[
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "r16",
  "r17",
  "r18",
  "r19",
  "r20",
  "r21",
  "r22",
  "r23",
  "r24",
  "r25",
  "r26",
  "r27",
  "r28",
  "r29",
  "r30",
  "r31",
];

static Instruction dasmInstruction(bool isGpu, uint pc, const ubyte[] code)
{
  Instruction r;
  r.address = pc;
  r.type = Type.Unknown;
  auto p = code.ptr;

  uint read16_BE()
  {
    auto val = (p[0] << 8) | (p[1] << 0);
    p += 2;
    return val;
  };

  auto const op = read16_BE();
  auto const opCode = (op >> 10) & 0b111111;
  auto const reg1 = (op >> 5) & 0b11111;
  auto const reg2 = (op >> 0) & 0b11111;

  Expr R(int id)
  {
    auto r = new IdentifierExpr;
    r.name = RegisterNames[id];
    return r;
  }

  Expr deref(Expr e)
  {
    auto r = new DerefExpr;
    r.sub = e;
    return r;
  }

  Expr val(int value)
  {
    auto r = new NumberExpr;
    r.value = value;
    return r;
  }

  Expr add(Expr a, Expr b)
  {
    auto r = new AddExpr;
    r.a = a;
    r.b = b;
    return r;
  }

  pc += 2;
  switch(opCode)
  {
  case 0:
    r.mnemonic = "add";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 1:
    r.mnemonic = "addc";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 2:
    r.mnemonic = "addq";
    r.operands = [val(notZero(reg1)), R(reg2)];
    r.type = Type.Op;
    break;
  case 3:
    r.mnemonic = "addqt";
    r.operands = [val(notZero(reg1)), R(reg2)];
    r.type = Type.Op;
    break;
  case 4:
    r.mnemonic = "sub";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 5:
    r.mnemonic = "subc";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 6:
    r.mnemonic = "subq";
    r.operands = [val(notZero(reg1)), R(reg2)];
    r.type = Type.Op;
    break;
  case 7:
    r.mnemonic = "subqt";
    r.operands = [val(notZero(reg1)), R(reg2)];
    r.type = Type.Op;
    break;
  case 8:
    r.mnemonic = "neg";
    r.operands = [R(reg2)];
    r.type = Type.Op;
    break;
  case 9:
    r.mnemonic = "and";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 10:
    r.mnemonic = "or";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 11:
    r.mnemonic = "xor";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 12:
    r.mnemonic = "not";
    r.operands = [R(reg2)];
    r.type = Type.Op;
    break;
  case 13:
    r.mnemonic = "btst";
    r.operands = [val(reg1), R(reg2)];
    break;
  case 14:
    r.mnemonic = "bset";
    r.operands = [val(reg1), R(reg2)];
    break;
  case 15:
    r.mnemonic = "bclr";
    r.operands = [val(reg1), R(reg2)];
    break;
  case 16:
    r.mnemonic = "mult";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 17:
    r.mnemonic = "imult";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 18:
    r.mnemonic = "imultn";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 19:
    r.mnemonic = "resmac";
    r.operands = [R(reg2)];
    break;
  case 20:
    r.mnemonic = "imacn";
    r.operands = [R(reg1), R(reg2)];
    break;
  case 21:
    r.mnemonic = "div";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 22:
    r.mnemonic = "abs";
    r.operands = [R(reg2)];
    r.type = Type.Op;
    break;
  case 23:
    r.mnemonic = "sh";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 24:
    r.mnemonic = "shlq";
    r.operands = [val(32 - notZero(reg1)), R(reg2)];
    r.type = Type.Op;
    break;
  case 25:
    r.mnemonic = "shrq";
    r.operands = [val(notZero(reg1)), R(reg2)];
    r.type = Type.Op;
    break;
  case 26:
    r.mnemonic = "sha";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 27:
    r.mnemonic = "sharq";
    r.operands = [val(notZero(reg1)), R(reg2)];
    r.type = Type.Op;
    break;
  case 28:
    r.mnemonic = "ror";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 29:
    r.mnemonic = "rorq";
    r.operands = [val(notZero(reg1)), R(reg2)];
    r.type = Type.Op;
    break;
  case 30:
    r.mnemonic = "cmp";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Op;
    break;
  case 31:
    r.mnemonic = "cmpq";
    r.operands = [val(cast(short)(reg1 << 11) >> 11), R(reg2)];
    r.type = Type.Op;
    break;
  case 32:

    if(isGpu)
    {
      r.mnemonic = "sat8";
      r.operands = [R(reg2)];
    }
    else
    {
      r.mnemonic = "subqmod";
      r.operands = [val(notZero(reg1)), R(reg2)];
    }

    break;
  case 33:

    if(isGpu)
    {
      r.mnemonic = "sat16";
      r.operands = [R(reg2)];
    }
    else
    {
      r.mnemonic = "sat16s";
      r.operands = [R(reg2)];
    }

    break;
  case 34:
    r.mnemonic = "move";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Assign;
    break;
  case 35:
    r.mnemonic = "moveq";
    r.operands = [val(reg1), R(reg2)];
    r.type = Type.Assign;
    break;
  case 36:
    r.mnemonic = "moveta";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Assign;
    break;
  case 37:
    r.mnemonic = "movefa";
    r.operands = [R(reg1), R(reg2)];
    r.type = Type.Assign;
    break;
  case 38:
    {
      auto low = read16_BE() << 0;
      auto high = read16_BE() << 16;
      r.mnemonic = "movei";
      r.operands = [val(low | high), R(reg2)];
      r.type = Type.Assign;
      break;
    }
  case 39:
    r.mnemonic = "loadb";
    r.operands = [deref(R(reg1)), R(reg2)];
    r.type = Type.Assign;
    break;
  case 40:
    r.mnemonic = "loadw";
    r.operands = [deref(R(reg1)), R(reg2)];
    r.type = Type.Assign;
    break;
  case 41:
    r.mnemonic = "load";
    r.operands = [deref(R(reg1)), R(reg2)];
    r.type = Type.Assign;
    break;
  case 42:

    if(isGpu)
    {
      r.mnemonic = "loadp";
      r.operands = [deref(R(reg1)), R(reg2)];
    }
    else
    {
      r.mnemonic = "sat32s";
      r.operands = [R(reg2)];
    }

    r.type = Type.Assign;
    break;
  case 43:
    r.mnemonic = "load";
    r.operands = [deref(add(R(14), val(notZero(reg1) * 4))), R(reg2)];
    r.type = Type.Assign;
    break;
  case 44:
    r.mnemonic = "load";
    r.operands = [deref(add(R(15), val(notZero(reg1) * 4))), R(reg2)];
    r.type = Type.Assign;
    break;
  case 45:
    r.mnemonic = "storeb";
    r.operands = [(R(reg2)), deref(R(reg1))];
    r.type = Type.Assign;
    break;
  case 46:
    r.mnemonic = "storew";
    r.operands = [(R(reg2)), deref(R(reg1))];
    r.type = Type.Assign;
    break;
  case 47:
    r.mnemonic = "store";
    r.operands = [(R(reg2)), deref(R(reg1))];
    r.type = Type.Assign;
    break;
  case 48:

    if(isGpu)
    {
      r.mnemonic = "storep";
      r.operands = [(R(reg2)), deref(R(reg1))];
      r.type = Type.Assign;
    }
    else
    {
      r.mnemonic = "mirror";
      r.operands = [R(reg2)];
    }

    break;
  case 49:
    r.mnemonic = "store";
    r.operands = [R(reg2), deref(add(R(14), val(notZero(reg1) * 4)))];
    r.type = Type.Assign;
    break;
  case 50:
    r.mnemonic = "store";
    r.operands = [R(reg2), deref(add(R(15), val(notZero(reg1) * 4)))];
    r.type = Type.Assign;
    break;
  case 51:
    {
      auto pcReg = new IdentifierExpr;
      pcReg.name = "pc";
      r.mnemonic = "move";
      r.operands = [pcReg, R(reg2)];
      r.type = Type.Assign;
      break;
    }
  case 52:
    r.mnemonic = "jump" ~ condition[reg2];
    r.operands = [deref(R(reg1))];
    r.type = Type.Jump;
    break;
  case 53:
    {
      int offset = ((reg1 << 3) & 0xff);

      if(offset >= 128)
        offset -= 256;

      offset >>= 2;

      r.mnemonic = "jr" ~ condition[reg2];
      r.operands = [val(pc + offset)];
      r.type = Type.Jump;
      break;
    }
  case 54:
    r.mnemonic = "mmult";
    r.operands = [R(reg1), R(reg2)];
    break;
  case 55:
    r.mnemonic = "mtoi";
    r.operands = [R(reg1), R(reg2)];
    break;
  case 56:
    r.mnemonic = "normi";
    r.operands = [R(reg1), R(reg2)];
    break;
  case 57:
    r.mnemonic = "nop";
    r.operands = [];
    r.type = Type.Nop;
    break;
  case 58:
    r.mnemonic = "load";
    r.type = Type.Assign;
    r.operands = [deref(add(R(14), R(reg1))), R(reg2)];
    break;
  case 59:
    r.mnemonic = "load";
    r.operands = [deref(add(R(15), R(reg1))), R(reg2)];
    r.type = Type.Assign;
    break;
  case 60:
    r.mnemonic = "store";
    r.operands = [R(reg1), deref(add(R(14), R(reg2)))];
    r.type = Type.Assign;
    break;
  case 61:
    r.mnemonic = "store";
    r.operands = [R(reg1), deref(add(R(15), R(reg2)))];
    r.type = Type.Assign;
    break;
  case 62:
    {
      if(isGpu)
      {
        r.mnemonic = "sat24";
        r.operands = [R(reg2)];
      }
      else
      {
        // invalid
        r.type = Type.Unknown;
      }

      break;
    }
  case 63:

    r.type = Type.Op;

    if(isGpu)
    {
      if(reg1 == 0)
      {
        r.mnemonic = "pack";
        r.operands = [R(reg2)];
      }
      else if(reg1 == 1)
      {
        r.mnemonic = "unpack";
        r.operands = [R(reg2)];
      }
      else
        r.type = Type.Unknown;
    }
    else
    {
      r.mnemonic = "addqmod";
      r.operands = [val(notZero(reg1)), R(reg2)];
    }

    break;
  default:
    assert(0);
  }

  auto size = p - code.ptr;

  if(size > code.length)
    return Instruction();

  r.bytes = code[0 .. size];
  return r;
}

