// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

import arch;
import document;
import instruction;

import std.algorithm: map;
import std.array: join;
import std.format;

void cmd_disassemble(Document doc)
{
  auto arch = g_Architectures.get(doc.arch);

  foreach(ref reg; doc.regions)
  {
    auto pc = reg.address;
    int i = 0;

    while(i < cast(int)reg.data.length)
    {
      auto instruction = arch.disassemble(reg.data[i .. $], pc);
      const size = instruction.bytes.length;

      if(!size)
        break;

      reg.instructions ~= instruction;

      i += size;
      pc += size;
    }
  }

  doc.symbols[doc.entryPoint] = "entry0";

  int labelCount;

  // basic code xrefs
  foreach(ref reg; doc.regions)
    foreach(instruction; reg.instructions)
    {
      if(instruction.type == Type.Jump || instruction.type == Type.Call)
      {
        foreach(c; join(map!allConstants(instruction.operands)))
          doc.symbols[c] = format("_%s", labelCount++);
      }
    }
}

ulong[] allConstants(Expr e)
{
  if(auto n = cast(NumberExpr)e)
  {
    return [n.value];
  }
  else if(auto i = cast(IdentifierExpr)e)
  {
    return [];
  }
  else if(auto d = cast(DerefExpr)e)
  {
    return allConstants(d.sub);
  }
  else
  {
    return [];
  }
}

