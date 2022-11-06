// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// Load binary use case

import std.file;
import std.stdio;

import document;

void cmd_load(Document doc, string path, ulong address = ulong.max)
{
  auto name = doc.format;

  if(name == "")
  {
    name = guessFormat(path);
    writefln("Using format: '%s'", name);
  }

  auto loader = g_Loaders.get(name);
  loader.load(doc, path, address);
}

void cmd_symbols(Document doc)
{
  import std.string;
  doc.result = [];

  foreach(addr, name; doc.symbols)
    doc.result ~= format("0x%08X  :  %s", addr, name);
}

string guessFormat(string path)
{
  foreach(name; g_Loaders.keys)
    if(g_Loaders.get(name).probe(path))
      return name;

  return "raw";
}

interface Loader
{
  // return true if this loader can load the file at 'path'
  bool probe(string path);

  // load the binary from 'path' into 'doc'
  void load(Document doc, string path, ulong baseAddress);
}

///////////////////////////////////////////////////////////////////////////////
import registry;
Registry!Loader g_Loaders;

