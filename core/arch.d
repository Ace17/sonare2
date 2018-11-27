// Copyright (C) 2017 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

public import instruction;

interface Architecture
{
  // disassemble one instruction, starting at code[0]
  Instruction disassemble(const(ubyte)[] code, ulong pc);
}

///////////////////////////////////////////////////////////////////////////////
import registry;
Registry!Architecture g_Architectures;

