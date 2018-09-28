/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// Load binary use case

import std.file;
import std.stdio;

import document;
import registry;

void cmd_load(Document doc, string path)
{
  auto name = doc.format;

  if(name == "")
  {
    name = guessFormat(path);
    writefln("Using format: '%s'", name);
  }

  auto loader = g_Loaders.get(name);
  loader.load(doc, path);
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

  return g_Loaders.keys[0];
}

interface Loader
{
  bool probe(string path);
  void load(Document doc, string path);
}

Registry!Loader g_Loaders;

