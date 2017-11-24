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

import document;
import registry;

void cmd_load(Document doc, string path)
{
  auto name = doc.format;

  if(name == "")
    name = guessFormat(path);

  auto loader = g_Loaders.get(name);
  loader.load(doc, path);
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

