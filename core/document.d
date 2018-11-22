// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// The binary blob being analyzed.
// This never should be accessed by the view.

import instruction;

class Document
{
  string format;
  string arch;

  ulong address;
  ubyte[] data;

  ulong entryPoint;
  Instruction[] instructions;

  string[ulong] symbols;

  string[] result;
}

