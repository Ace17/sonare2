// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

import std.algorithm;
import std.array;
import std.stdio;
import std.string;

import capstone;

import arch;

static this()
{
  g_Architectures.register("arm_32", new ArmArchitecture);
}

class ArmArchitecture : Architecture
{
  csh handle;

  this()
  {
    if(cs_open(cs_arch.CS_ARCH_ARM, cs_mode.CS_MODE_ARM, &handle) != cs_err.CS_ERR_OK)
      throw new Exception("can't open capstone");
  }

  ~this()
  {
    cs_close(&handle);
  }

  Instruction disassemble(const(ubyte)[] code, ulong pc)
  {
    cs_insn* insn;

    const count = cs_disasm(handle, cast(ubyte*)code.ptr, code.length, pc, 1, &insn);

    if(count <= 0)
      throw new Exception("failed to disassemble");

    scope(exit) cs_free(insn, count);

    Instruction convert(ref cs_insn ins)
    {
      Instruction instruction;
      instruction.address = ins.address;
      instruction.bytes = code[0 .. ins.size];
      instruction.mnemonic = fromStringz(ins.mnemonic);

      // hack: put all operands into a single identifier expression
      auto id = new IdentifierExpr;
      id.name = fromStringz(ins.op_str);
      instruction.operands = [id];

      instruction.type = Type.Unknown;

      return instruction;
    }

    return convert(*insn);
  }
}

string fromStringz(char[] s)
{
  import core.stdc.string;
  return s[0 .. strlen(s.ptr)].idup;
}

