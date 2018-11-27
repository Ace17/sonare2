// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// Loader for x86 16-bit real-mode bootsector

import document;
import loader;

static this()
{
  g_Loaders.register("bootsector", new BootSectorLoader);
}

class BootSectorLoader : Loader
{
  bool probe(string path)
  {
    const data = cast(ubyte[])std.file.read(path);

    if(data.length != 512)
      return false;

    if(data[510 .. 512] !=[0x55, 0xAA])
      return false;

    return true;
  }

  void load(Document doc, string path, ulong baseAddress)
  {
    doc.arch = "x86_16";
    doc.address = baseAddress != ulong.max ? baseAddress : 0x7c00;
    doc.data = cast(ubyte[])std.file.read(path);
  }
}

