// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// Loader for binary blobs

import document;
import loader;

static this()
{
  g_Loaders.register("raw", new RawLoader);
}

class RawLoader : Loader
{
  bool probe(string path)
  {
    return false; // don't default to raw
  }

  void load(Document doc, string path)
  {
    doc.arch = "i386";
    doc.bits = 64;
    doc.address = 0;
    doc.data = cast(ubyte[])std.file.read(path);
  }
}

