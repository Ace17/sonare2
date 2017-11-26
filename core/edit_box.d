/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// stores the state of the interactive command line

import std.typecons;

import assertion;

unittest
{
  auto b = new EditBox;
  b.onChar('H');
  b.onChar('E');
  b.onChar('L');
  b.onChar('L');
  b.onChar('O');
  assertEquals("HELLO", b.text);
}

unittest
{
  auto b = new EditBox;
  b.onChar('H');
  b.onChar('E');
  b.onChar('L');
  b.onChar('L');
  b.onChar('O');
  b.onChar('\x08'); // backspace
  assertEquals("HELL", b.text);
}

unittest
{
  auto b = new EditBox;
  b.onChar('l');
  b.onChar('s');
  b.onChar('\x15'); // Ctrl-U
  assertEquals("", b.text);
}

unittest
{
  auto b = new EditBox;
  b.onChar('r');
  b.onChar('u');
  b.onChar('n');
  b.onChar('\x0D'); // 'Enter' key
  assertEquals("", b.text);
}

class EditBox
{
  interface Sink
  {
    void eof();
    void escape();
    string complete(string cmd);
    void sendCommand(string cmd);
  }

  this()
  {
    sink = new BlackHole!Sink;
  }

  void onChar(char c)
  {
    switch(c)
    {
    case '\x0D': // 'Enter' key
      const cmd = text;
      text = "";
      sink.sendCommand(cmd);
      break;

    case '\033': // Escape
      sink.escape();
      text = "";
      break;

    case '\t':
      text = sink.complete(text);
      break;

    case '\x08': // Ctrl-H

      if(text.length > 0)
        text.length--;

      break;

    case '\x15': // Ctrl-U
      text = "";
      break;

    case '\x04': // Ctrl-D
      sink.eof();
      break;

    default:
      text ~= c;
      break;
    }
  }

  string text;
  Sink sink;
}

