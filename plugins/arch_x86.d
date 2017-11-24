/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import std.algorithm;
import std.array;
import std.stdio;
import std.string;

import capstone;
import capstone_x86;

import arch;
import document;

static this()
{
  g_Architectures.register("i386", new i386Architecture);
}

class i386Architecture : Architecture
{
  void disassemble(Document doc)
  {
    static cs_mode getMode(int bits)
    {
      switch(bits)
      {
      case 16: return cs_mode.CS_MODE_16;
      case 32: return cs_mode.CS_MODE_32;
      case 64: return cs_mode.CS_MODE_64;
      default: assert(0);
      }
    }

    const mode = getMode(doc.bits);

    csh handle;

    if(cs_open(cs_arch.CS_ARCH_X86, mode, &handle) != cs_err.CS_ERR_OK)
      throw new Exception("can't open capstone");

    scope(exit) cs_close(&handle);

    cs_insn* insn;

    const count = cs_disasm(handle, cast(ubyte*)doc.data.ptr, doc.data.length, doc.address, 0UL, &insn);

    if(count <= 0)
      throw new Exception("failed to disassemble");

    scope(exit) cs_free(insn, count);

    Instruction convert(ref cs_insn ins)
    {
      const offset = ins.address - doc.address;

      Instruction instruction;
      instruction.address = ins.address;
      instruction.bytes = doc.data[offset .. offset + ins.size];
      instruction.asm_ = format("%.5s %s",
                                fromStringz(ins.mnemonic),
                                fromStringz(ins.op_str));

      instruction.type = getInstructionType(cast(x86_insn)ins.id);

      return instruction;
    }

    doc.instructions = array(map!convert(insn[0 .. count]));
  }
}

Type getInstructionType(x86_insn id)
{
  switch(id)
  {
  case x86_insn.X86_INS_JMP:
    return Type.Jump;
  default:
    return Type.Unknown;
  }
}

char[] fromStringz(char[] s)
{
  import core.stdc.string;
  return s[0 .. strlen(s.ptr)];
}

