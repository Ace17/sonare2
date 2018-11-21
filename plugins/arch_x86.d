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
  g_Architectures.register("x86_16", new x86Architecture !16);
  g_Architectures.register("x86_32", new x86Architecture !32);
  g_Architectures.register("x86_64", new x86Architecture !64);
}

class x86Architecture(int bits) : Architecture
{
  csh handle;

  this()
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

    const mode = getMode(bits);

    if(cs_open(cs_arch.CS_ARCH_X86, mode, &handle) != cs_err.CS_ERR_OK)
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

      instruction.type = getInstructionType(cast(x86_insn)ins.id);

      return instruction;
    }

    return convert(*insn);
  }
}

Type getInstructionType(x86_insn id)
{
  switch(id)
  {
  case x86_insn.X86_INS_JAE:
  case x86_insn.X86_INS_JA:
  case x86_insn.X86_INS_JBE:
  case x86_insn.X86_INS_JB:
  case x86_insn.X86_INS_JCXZ:
  case x86_insn.X86_INS_JECXZ:
  case x86_insn.X86_INS_JE:
  case x86_insn.X86_INS_JGE:
  case x86_insn.X86_INS_JG:
  case x86_insn.X86_INS_JLE:
  case x86_insn.X86_INS_JL:
  case x86_insn.X86_INS_JMP:
  case x86_insn.X86_INS_JNE:
  case x86_insn.X86_INS_JNO:
  case x86_insn.X86_INS_JNP:
  case x86_insn.X86_INS_JNS:
  case x86_insn.X86_INS_JO:
  case x86_insn.X86_INS_JP:
  case x86_insn.X86_INS_JRCXZ:
  case x86_insn.X86_INS_JS:
    return Type.Jump;
  case x86_insn.X86_INS_MOV:
  case x86_insn.X86_INS_MOVABS:
  case x86_insn.X86_INS_MOVBE:
  case x86_insn.X86_INS_MOVDDUP:
  case x86_insn.X86_INS_MOVDQA:
  case x86_insn.X86_INS_MOVDQU:
  case x86_insn.X86_INS_MOVHLPS:
  case x86_insn.X86_INS_MOVHPD:
  case x86_insn.X86_INS_MOVHPS:
  case x86_insn.X86_INS_MOVLHPS:
  case x86_insn.X86_INS_MOVLPD:
  case x86_insn.X86_INS_MOVLPS:
  case x86_insn.X86_INS_MOVMSKPD:
  case x86_insn.X86_INS_MOVMSKPS:
  case x86_insn.X86_INS_MOVNTDQA:
  case x86_insn.X86_INS_MOVNTDQ:
  case x86_insn.X86_INS_MOVNTI:
  case x86_insn.X86_INS_MOVNTPD:
  case x86_insn.X86_INS_MOVNTPS:
  case x86_insn.X86_INS_MOVNTSD:
  case x86_insn.X86_INS_MOVNTSS:
  case x86_insn.X86_INS_MOVSB:
  case x86_insn.X86_INS_MOVSD:
  case x86_insn.X86_INS_MOVSHDUP:
  case x86_insn.X86_INS_MOVSLDUP:
  case x86_insn.X86_INS_MOVSQ:
  case x86_insn.X86_INS_MOVSS:
  case x86_insn.X86_INS_MOVSW:
  case x86_insn.X86_INS_MOVSX:
  case x86_insn.X86_INS_MOVSXD:
  case x86_insn.X86_INS_MOVUPD:
  case x86_insn.X86_INS_MOVUPS:
  case x86_insn.X86_INS_MOVZX:
    return Type.Assign;
  case x86_insn.X86_INS_RET:
    return Type.Ret;
  default:
    return Type.Unknown;
  }
}

string fromStringz(char[] s)
{
  import core.stdc.string;
  return s[0 .. strlen(s.ptr)].idup;
}

