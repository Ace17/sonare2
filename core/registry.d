// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// Helper for pluggable factories

struct Registry (T)
{
void register(string name, T a)
{
  if(name in m_entries)
    throw new Exception("A " ~ T.stringof ~ " named '" ~ name ~ "' already exists");

  m_entries[name] = a;
}

T get(string name)
{
  if(name !in m_entries)
    throw new Exception("No such " ~ T.stringof ~ ": '" ~ name ~ "'");

  return m_entries[name];
}

string[] keys()
{
  return m_entries.keys;
}

T[string] m_entries;
}

