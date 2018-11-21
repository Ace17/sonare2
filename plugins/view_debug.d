// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// ANSI-terminal view implementation.
// - Takes a ViewModel and renders it.
// - Receives user events, and forward them to the presenter (through an InputSink)

import std.algorithm;
import std.string;

import input_sink;
import view;

import core.stdc.stdio;

static this()
{
  registerView!DebugView("debug");
}

class DebugView : IView
{
  this(InputSink s)
  {
  }

  void run()
  {
  }

  int getLineCount()
  {
    return 10;
  }

  void refresh(in ViewModel model)
  {
  }

  ViewModel m_viewModel;
  InputSink m_sink;
}

