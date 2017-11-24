/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// command line parsing and completion

import std.algorithm;
import std.stdio;
import std.string;
import std.traits;

import assertion;

unittest
{
  auto s = new Shell;
  void nop() {}

  s.addAction("save", &nop, "desc");
  s.addAction("load", &nop, "desc");
  s.addAction("loop", &nop, "desc");

  assertEquals("save", s.complete("sav"));
  assertEquals("savi", s.complete("savi"));

  assertEquals("loop", s.complete("loo"));
  assertEquals("lo", s.complete("lo"));

  // 'lo' is the longest common prefix
  assertEquals("lo", s.complete("l"));
}

class Shell
{
public:
  this()
  {
    m_actions["help"] = Action(&help, "shows this help");
  }

  void addAction(F)(string name, F f, string desc)
  {
    void execute(string[] dynamicArgs)
    {
      alias ParamTypes = ParameterTypeTuple!F;

      const N = ParamTypes.length;

      if(dynamicArgs.length != N)
      {
        const msg = format("Command '%s' takes %s arguments, got %s", name, N, dynamicArgs.length);
        throw new Exception(msg);
      }

      ParamTypes argValues;

      foreach(i, t; ParamTypes)
        argValues[i] = dynamicArgs[i];

      f(argValues);
    }

    m_actions[name] = Action(&execute, desc);
  }

  void processOneLine(string line)
  {
    processOneCommand(line);
  }

  string complete(string prefix)
  {
    bool isPrefix(string a)
    {
      return startsWith(a, prefix);
    }

    auto matches = filter!isPrefix(m_actions.keys);

    if(matches.empty())
      return prefix;

    return reduce!commonPrefix(matches);
  }

private:
  struct Action
  {
    void delegate(string[]) func;
    string desc;
  }

  Action[string] m_actions;

  void processOneCommand(string line)
  {
    const cmdLine = strip(line);

    if(cmdLine == "")
      return;

    string[] argv;

    foreach(arg; splitter(cmdLine))
      argv ~= arg;

    auto action = getAction(argv[0]);

    action.func(argv[1 .. $]);
  }

  // actions

  void help(string[] args)
  {
    if(args.length == 1)
    {
      const name = args[0];
      auto action = getAction(name);
      writefln("%s: %s", name, action.desc);
    }
    else
    {
      writefln("Available commands:");

      foreach(name; m_actions.keys.sort)
        writefln("  %20s : %s", name, m_actions[name].desc);
    }
  }

  const(Action)* getAction(string name)
  {
    auto action = name in m_actions;

    if(!action)
      throw new Exception("Unknown command '" ~ name ~ "'");

    return action;
  }
}

