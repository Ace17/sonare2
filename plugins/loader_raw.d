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

  void load(Document doc, string path, ulong baseAddress)
  {
    if(doc.arch == "")
      doc.arch = "x86_64";

    doc.address = baseAddress != ulong.max ? baseAddress : 0;
    doc.entryPoint = doc.address;
    doc.data = cast(ubyte[])std.file.read(path);
  }
}

