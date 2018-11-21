// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

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
  string binFmt;
  string binArch;
  uint baseAddress;

  auto helpInfo = getopt(args,
                         "f|format", "input format (raw, elf, etc.)", &binFmt,
                         "a|arch", "input architecture (arm, x86, etc.)", &binArch,
                         "m|base-address", "base address", &baseAddress,
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

  void addAction(T...)(string name, void function(Document, T) func, MetaInfo meta, string desc)
  {
    void action(T args)
    {
      func(doc, args);
    }

    meta.defaults = meta.defaults[1 .. $];
    shell.addAction(name, &action, meta, desc);
  }

  addAction("load", &cmd_load, Meta!cmd_load, "loads an executable binary");
  addAction("arch", &cmd_setArch, Meta!cmd_setArch, "sets the architecture");
  addAction("ii", &cmd_symbols, Meta!cmd_symbols, "list symbols");
  addAction("run", &run, Meta!run, "run an executable binary");
  addAction("disassemble", &cmd_disassemble, Meta!cmd_disassemble, "disassemble");

  auto presenter = new Presenter(doc);
  scope(exit) destroy(presenter);

  shell.addAction("quit", &presenter.quit, Meta!(presenter.quit), "quit the program");

  auto view = instanciateView(uiType, presenter);
  scope(exit) destroy(view);

  presenter.setView(view);
  presenter.m_shell = shell;

  if(args.length > 1)
  {
    doc.format = binFmt;
    doc.arch = binArch;
    doc.address = baseAddress;
    cmd_load(doc, args[1]);
    cmd_disassemble(doc);
  }

  if(script)
  {
    foreach(line; File(script).byLineCopy)
      shell.processOneLine(line);
  }

  // HACK: trigger a refresh
  presenter.onChar('\b');

  view.run();
}

void cmd_setArch(Document doc, string archName = "")
{
  if(archName == "")
  {
    import std.string;
    doc.result = [format("Current arch is '%s'", doc.arch)];
    return;
  }

  arch.g_Architectures.get(archName);
  doc.arch = archName;
}

