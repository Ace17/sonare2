/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// Entry point and main loop.
// Ideally, shouldn't know about any concrete view or machine architecture.

import std.getopt;
import std.stdio;

import debugger;
import disassemble;
import document;
import loader;
import presenter;
import shell;
import view;

int main(string[] args)
{
  try
  {
    safeMain(args);
    return 0;
  }
  catch(Exception e)
  {
    stderr.writefln("Fatal: %s", e.msg);
    return 1;
  }
}

void safeMain(string[] args)
{
  string script;
  string uiType = "console";

  auto helpInfo = getopt(args,
                         "u|ui", "UI to use (console, sdl)", &uiType,
                         "i|script", "script file to run", &script);

  if(helpInfo.helpWanted)
  {
    writefln("Usage: %s [options] [executable]", args[0]);
    defaultGetoptPrinter("Options:", helpInfo.options);
    return;
  }

  auto shell = new Shell;
  scope(exit) destroy(shell);

  auto doc = new Document;

  void addAction(T...)(string name, void function(Document, T) func, string desc)
  {
    void action(T args)
    {
      func(doc, args);
    }

    shell.addAction(name, &action, desc);
  }

  addAction("load", &cmd_load, "loads an executable binary");
  addAction("arch", &cmd_setArch, "sets the architecture");
  addAction("ii", &cmd_symbols, "list symbols");
  addAction("run", &run, "run an executable binary");
  addAction("disassemble", &cmd_disassemble, "disassemble");

  auto presenter = new Presenter(doc);
  scope(exit) destroy(presenter);
  shell.addAction("quit", &presenter.quit, "quit the program");

  auto view = instanciateView(uiType, presenter);
  scope(exit) destroy(view);

  presenter.setView(view);
  presenter.shell = shell;

  if(args.length > 1)
    cmd_load(doc, args[1]);

  if(script)
  {
    foreach(line; File(script).byLineCopy)
      shell.processOneLine(line);
  }

  view.run();
}

void cmd_setArch(Document doc, string archName)
{
  arch.g_Architectures.get(archName);
  doc.arch = archName;
}

