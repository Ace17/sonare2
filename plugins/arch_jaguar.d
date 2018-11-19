// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

import std.format;

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
      string buffer;
      auto instruction = dasmInstruction(isGpu, buffer, pc, doc.data[i .. $]);
      auto size = instruction.bytes.length;

      if(!size)
        break;

      instruction.asm_ = buffer;

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
  "",
  "nz,",
  "z,",
  "?,",
  "nc,",
  "nc nz,",
  "nc z,",
  "?,",
  "c,",
  "c nz,",
  "c z,",
  "?,",
  "?,",
  "?,",
  "?,",
  "?,",
  "?,",
  "?,",
  "?,",
  "?,",
  "nn,",
  "nn nz,",
  "nn z,",
  "?,",
  "n,",
  "n nz,",
  "n z,",
  "?,",
  "?,",
  "?,",
  "?,",
  "never,"
];

string formatSigned16bit(int val)
{
  if(val < 0)
    return format("-$%x", -val);
  else
    return format("$%x", val);
}

static Instruction dasmInstruction(bool isGpu, out string text, uint pc, const ubyte[] code)
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

  pc += 2;
  switch(opCode)
  {
  case 0:
    text = format("add     r%d,r%d", reg1, reg2);
    r.type = Type.Op;
    break;
  case 1:
    text = format("addc    r%d,r%d", reg1, reg2);
    r.type = Type.Op;
    break;
  case 2:
    text = format("addq    $%x,r%d", notZero(reg1), reg2);
    r.type = Type.Op;
    break;
  case 3:
    text = format("addqt   $%x,r%d", notZero(reg1), reg2);
    r.type = Type.Op;
    break;
  case 4:
    text = format("sub     r%d,r%d", reg1, reg2);
    r.type = Type.Op;
    break;
  case 5:
    text = format("subc    r%d,r%d", reg1, reg2);
    r.type = Type.Op;
    break;
  case 6:
    text = format("subq    $%x,r%d", notZero(reg1), reg2);
    r.type = Type.Op;
    break;
  case 7:
    text = format("subqt   $%x,r%d", notZero(reg1), reg2);
    r.type = Type.Op;
    break;
  case 8:
    text = format("neg     r%d", reg2);
    r.type = Type.Op;
    break;
  case 9:
    text = format("and     r%d,r%d", reg1, reg2);
    r.type = Type.Op;
    break;
  case 10:
    text = format("or      r%d,r%d", reg1, reg2);
    r.type = Type.Op;
    break;
  case 11:
    text = format("xor     r%d,r%d", reg1, reg2);
    r.type = Type.Op;
    break;
  case 12:
    text = format("not     r%d", reg2);
    r.type = Type.Op;
    break;
  case 13:
    text = format("btst    $%x,r%d", reg1, reg2);
    break;
  case 14:
    text = format("bset    $%x,r%d", reg1, reg2);
    break;
  case 15:
    text = format("bclr    $%x,r%d", reg1, reg2);
    break;
  case 16:
    text = format("mult    r%d,r%d", reg1, reg2);
    r.type = Type.Op;
    break;
  case 17:
    text = format("imult   r%d,r%d", reg1, reg2);
    r.type = Type.Op;
    break;
  case 18:
    text = format("imultn  r%d,r%d", reg1, reg2);
    r.type = Type.Op;
    break;
  case 19:
    text = format("resmac  r%d", reg2);
    break;
  case 20:
    text = format("imacn   r%d,r%d", reg1, reg2);
    break;
  case 21:
    text = format("div     r%d,r%d", reg1, reg2);
    break;
  case 22:
    text = format("abs     r%d", reg2);
    break;
  case 23:
    text = format("sh      r%d,r%d", reg1, reg2);
    break;
  case 24:
    text = format("shlq    $%x,r%d", 32 - notZero(reg1), reg2);
    break;
  case 25:
    text = format("shrq    $%x,r%d", notZero(reg1), reg2);
    break;
  case 26:
    text = format("sha     r%d,r%d", reg1, reg2);
    break;
  case 27:
    text = format("sharq   $%x,r%d", notZero(reg1), reg2);
    break;
  case 28:
    text = format("ror     r%d,r%d", reg1, reg2);
    break;
  case 29:
    text = format("rorq    $%x,r%d", notZero(reg1), reg2);
    break;
  case 30:
    text = format("cmp     r%d,r%d", reg1, reg2);
    break;
  case 31:
    text = format("cmpq    %s,r%d", formatSigned16bit(cast(short)(reg1 << 11) >> 11), reg2);
    break;
  case 32:

    if(isGpu)
      text = format("sat8    r%d", reg2);
    else
      text = format("subqmod $%x,r%d", notZero(reg1), reg2);

    break;
  case 33:

    if(isGpu)
      text = format("sat16   r%d", reg2);
    else
      text = format("sat16s  r%d", reg2);

    break;
  case 34:
    text = format("move    r%d,r%d", reg1, reg2);
    r.type = Type.Assign;
    break;
  case 35:
    text = format("moveq   %d,r%d", reg1, reg2);
    r.type = Type.Assign;
    break;
  case 36:
    text = format("moveta  r%d,r%d", reg1, reg2);
    r.type = Type.Assign;
    break;
  case 37:
    text = format("movefa  r%d,r%d", reg1, reg2);
    r.type = Type.Assign;
    break;
  case 38:
    {
      auto low = read16_BE() << 0;
      auto high = read16_BE() << 16;
      text = format("movei   $%x,r%d", low | high, reg2);
      r.type = Type.Assign;
      break;
    }
  case 39:
    text = format("loadb   (r%d),r%d", reg1, reg2);
    r.type = Type.Assign;
    break;
  case 40:
    text = format("loadw   (r%d),r%d", reg1, reg2);
    r.type = Type.Assign;
    break;
  case 41:
    text = format("load    (r%d),r%d", reg1, reg2);
    r.type = Type.Assign;
    break;
  case 42:

    if(isGpu)
      text = format("loadp   (r%d),r%d", reg1, reg2);
    else
      text = format("sat32s  r%d", reg2);

    r.type = Type.Assign;
    break;
  case 43:
    text = format("load    (r14+$%x),r%d", notZero(reg1) * 4, reg2);
    r.type = Type.Assign;
    break;
  case 44:
    text = format("load    (r15+$%x),r%d", notZero(reg1) * 4, reg2);
    r.type = Type.Assign;
    break;
  case 45:
    text = format("storeb  r%d,(r%d)", reg2, reg1);
    r.type = Type.Assign;
    break;
  case 46:
    text = format("storew  r%d,(r%d)", reg2, reg1);
    r.type = Type.Assign;
    break;
  case 47:
    text = format("store   r%d,(r%d)", reg2, reg1);
    r.type = Type.Assign;
    break;
  case 48:

    if(isGpu)
    {
      text = format("storep  r%d,(r%d)", reg2, reg1);
      r.type = Type.Assign;
    }
    else
    {
      text = format("mirror  r%d", reg2);
    }

    break;
  case 49:
    text = format("store   r%d,(r14+$%x)", reg2, notZero(reg1) * 4);
    break;
  case 50:
    text = format("store   r%d,(r15+$%x)", reg2, notZero(reg1) * 4);
    break;
  case 51:
    text = format("move    pc,r%d", reg2);
    break;
  case 52:
    text = format("jump    %s(r%d)", condition[reg2], reg1);
    r.type = Type.Jump;
    break;
  case 53:
    {
      int offset = ((reg1 << 3) & 0xff);

      if(offset >= 128)
        offset -= 256;

      offset >>= 2;

      text = format("jr      %s%08X", condition[reg2], pc + offset);
      r.type = Type.Jump;
      break;
    }
  case 54:
    text = format("mmult   r%d,r%d", reg1, reg2);
    break;
  case 55:
    text = format("mtoi    r%d,r%d", reg1, reg2);
    break;
  case 56:
    text = format("normi   r%d,r%d", reg1, reg2);
    break;
  case 57:
    text = format("nop");
    r.type = Type.Unknown;
    break;
  case 58:
    text = format("load    (r14+r%d),r%d", reg1, reg2);
    r.type = Type.Assign;
    break;
  case 59:
    text = format("load    (r15+r%d),r%d", reg1, reg2);
    r.type = Type.Assign;
    break;
  case 60:
    text = format("store   r%d,(r14+r%d)", reg2, reg1);
    r.type = Type.Assign;
    break;
  case 61:
    text = format("store   r%d,(r15+r%d)", reg2, reg1);
    r.type = Type.Assign;
    break;
  case 62:
    {
      if(isGpu)
        text = format("sat24   r%d", reg2);
      else
        text = format("invalid");

      break;
    }
  case 63:

    r.type = Type.Op;

    if(isGpu)
    {
      if(reg1 == 0)
      {
        text = format("pack    r%d", reg2);
      }
      else if(reg1 == 1)
      {
        text = format("unpack    r%d", reg2);
      }
      else
      {
        text = format("invalid");
        r.type = Type.Unknown;
      }
    }
    else
    {
      text = format("addqmod $%x,r%d", notZero(reg1), reg2);
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

