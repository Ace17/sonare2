/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// Representation of the screen state, in an I/O agnostic way.
// Should be "ready-to-render" by an (almost) passive view.
// with almost no logic required.

import input_sink;

struct ViewModel
{
  bool quit;
  Line[] lines;
  bool commandMode;
  string command;
}

struct Line
{
  string text;
  Color color;
}

enum Color
{
  White,
  Green,
  Yellow,
  Blue,
  Red,
}

interface IView
{
  // called by Main only. Ideally, shouldn't be seen by the presenter
  void run();

  // called by the presenter to 'sink' messages to the view
  int getLineCount();
  void refresh(in ViewModel vm);
}

///////////////////////////////////////////////////////////////////////////////
// pluggable factory for view types

void registerView(T)(string name)
{
  static IView instanciateView(InputSink s)
  {
    return new T(s);
  }

  g_Views[name] = &instanciateView;
}

IView instanciateView(string type, InputSink sink)
{
  if(type !in g_Views)
    throw new Exception("No such view: '" ~ type ~ "'");

  return g_Views[type] (sink);
}

private:
ViewCreationFunc[string] g_Views;
alias ViewCreationFunc = IView function(InputSink);

