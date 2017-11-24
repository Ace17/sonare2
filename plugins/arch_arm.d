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

import arch;
import document;

static this()
{
  g_Architectures.register("arm", new ArmArchitecture);
}

class ArmArchitecture : Architecture
{
  void disassemble(Document doc)
  {
    csh handle;

    if(cs_open(cs_arch.CS_ARCH_ARM, cs_mode.CS_MODE_ARM, &handle) != cs_err.CS_ERR_OK)
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

      instruction.type = Type.Unknown;

      return instruction;
    }

    doc.instructions = array(map!convert(insn[0 .. count]));
  }
}

char[] fromStringz(char[] s)
{
  import core.stdc.string;
  return s[0 .. strlen(s.ptr)];
}

