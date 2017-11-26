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

