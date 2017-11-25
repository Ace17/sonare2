/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// Derives a ViewModel from a Document,
// and receives keystrokes from the view.
// Stores the state of the command line.

import std.algorithm;
import std.array;
import std.string;

import document;
import input_sink;
import shell;
import view;

class Presenter : InputSink
{
  this(Document doc)
  {
    m_doc = doc;
    vm.commandMode = true;
  }

  void updateViewModel()
  {
    const N = m_sink.getLineCount();

    auto getInstruction(int index)
    {
      if(index < 0 || index >= m_doc.instructions.length)
        return Instruction(ulong.max);

      return m_doc.instructions[index];
    }

    static Color getColor(Type insType)
    {
      final switch(insType)
      {
      case Type.Jump: return Color.Green;
      case Type.Call: return Color.Red;
      case Type.Ret: return Color.Red;
      case Type.Assign: return Color.Blue;
      case Type.Op: return Color.Blue;
      case Type.Unknown: return Color.White;
      }
    }

    Line[] getLines(int offset)
    {
      Line[] r;

      foreach(k; 0 .. N)
      {
        const ins = getInstruction(m_scrolling + k);

        if(ins.address == ulong.max)
        {
          r ~= Line("~");
          continue;
        }

        Line line;

        line.color = getColor(ins.type);
        line.text = format("0x%.4X:    %-24s %s",
                           ins.address,
                           toHex(ins.bytes),
                           ins.asm_);
        r ~= line;
      }

      return r;
    }

    vm.lines = getLines(m_scrolling);
  }

  void quit()
  {
    vm.quit = true;
  }

  void onChar(char c)
  {
    try
    {
      onCharSafe(c);
    }
    catch(Exception e)
    {
      vm.lines = [Line(e.msg)];
    }
    m_sink.refresh(vm);
  }

  void onCharSafe(char c)
  {
    if(vm.commandMode)
    {
      switch(c)
      {
      case '\x0D':
        const cmd = vm.command;
        vm.command = "";
        onCommand(cmd);
        break;

      case '\033':
        vm.commandMode = false;
        vm.command = "";
        break;

      case '\t':
        tryCompleteCommand();
        break;

      case '\x08': // Ctrl-H

        if(vm.command.length > 0)
          vm.command.length--;

        break;

      case '\x15': // Ctrl-U
        vm.command = "";
        break;

      case '\x04': // Ctrl-D
        vm.quit = true;
        break;

      default:
        vm.command ~= c;
        break;
      }
    }
    else
    {
      switch(c)
      {
      case ':':
        vm.commandMode = true;
        break;

      case 'j':
        m_scrolling++;
        break;

      case 'k':
        m_scrolling--;
        break;
      default:
        break;
      }
    }

    if(!empty(m_doc.result))
    {
      vm.lines = array(map!Line(m_doc.result));
      m_doc.result = [];
    }
    else
      updateViewModel();
  }

  void tryCompleteCommand()
  {
    vm.command = shell.complete(vm.command);
  }

  void setView(IView sink)
  {
    m_sink = sink;
    m_sink.refresh(vm);
  }

  Shell shell;
  ViewModel vm;
  IView m_sink;
  Document m_doc;

private:
  int m_scrolling;

  void onCommand(string command)
  {
    shell.processOneLine(command);
  }
}

string toHex(in ubyte[] b)
{
  string hex(ubyte b)
  {
    return format("%.2x", b);
  }

  return join(map!hex(b), " ");
}

