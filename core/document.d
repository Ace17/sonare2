// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// The binary blob being analyzed.
// This never should be accessed by the view.

import instruction;

struct Region
{
  ulong address;
  ulong size;
  ubyte[] data;

  // disassembler output
  Instruction[] instructions;
}

class Document
{
  string format;
  string arch;

  Region[] regions;

  ulong entryPoint;

  string[ulong] symbols;

  string[] result;
}

