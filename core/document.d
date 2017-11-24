/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// The binary blob being analyzed.
// This never should be accessed by the view.

class Document
{
  int bits; // 16, 32, 64
  string format;
  string arch;

  ulong address;
  ubyte[] data;

  ulong entryPoint;
  Instruction[] instructions;
}

struct Instruction
{
  ulong address;
  string asm_;
  const(ubyte)[] bytes;
  Type type;
}

enum Type
{
  Unknown,
  Jump,
  Call,
  Ret,
  Assign,
  Op,
}

