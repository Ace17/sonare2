/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// Computes a ViewModel from a Document.
// Receives keystrokes from the view,
// and triggers appropriate actions.

import std.algorithm;
import std.array;
import std.string;

import document;
import edit_box;
import input_sink;
import shell;
import view;

class Presenter : InputSink, EditBox.Sink
{
  this(Document doc)
  {
    m_doc = doc;
    vm.commandMode = true;

    m_cmd = new EditBox;
    m_cmd.sink = this;
  }

  void updateViewModel()
  {
    vm.command = m_cmd.text;
    const N = m_sink.getLineCount();

    auto getInstruction(int index)
    {
      if(index < 0 || index >= m_doc.instructions.length)
        return Instruction(ulong.max);

      return m_doc.instructions[index];
    }

    Line[] getLines(int offset)
    {
      Line[] r;
      bool hasLabel;

      int srcK = 0;

      foreach(dstK; 0 .. N)
      {
        const ins = getInstruction(m_scrolling + srcK);

        // unmapped memory
        if(ins.address == ulong.max)
        {
          r ~= Line("~");
          srcK++;
          continue;
        }

        // label needed
        if(ins.address in m_doc.symbols && !hasLabel)
        {
          r ~= Line(m_doc.symbols[ins.address] ~ ":", Color.Green);
          hasLabel = true;
          continue;
        }

        srcK++;
        hasLabel = false;

        Line line;
        auto operandText = join(map!formatExpression(ins.operands), ", ");

        line.color = getColor(ins.type);
        line.text = format("0x%.4X:    %-24s %-8s %s",
                           ins.address,
                           toHex(ins.bytes),
                           ins.mnemonic,
                           operandText);

        r ~= line;
      }

      return r;
    }

    vm.lines = getLines(m_scrolling);
  }

  /////////////////////////////////////////////////////////////////////////////
  // Notifications from EditBox.Sink
  void eof()
  {
    quit();
  }

  void escape()
  {
    vm.commandMode = false;
  }

  string complete(string cmd)
  {
    return m_shell.complete(cmd);
  }

  void sendCommand(string cmd)
  {
    m_shell.processOneLine(cmd);
  }

  /////////////////////////////////////////////////////////////////////////////

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
      m_cmd.onChar(c);
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

  void setView(IView sink)
  {
    m_sink = sink;
  }

  Shell m_shell;
  ViewModel vm;
  IView m_sink;
  Document m_doc;
  EditBox m_cmd;

private:
  int m_scrolling;
}

string toHex(in ubyte[] b)
{
  string hex(ubyte b)
  {
    return format("%.2x", b);
  }

  return join(map!hex(b), " ");
}

string formatExpression(in Expr e)
{
  if(auto n = cast(NumberExpr)e)
  {
    return format("0x%X", n.value);
  }
  else if(auto i = cast(IdentifierExpr)e)
  {
    return i.name;
  }
  else if(auto d = cast(DerefExpr)e)
  {
    return "[" ~ formatExpression(d.sub) ~ "]";
  }
  else
  {
    return typeid(e).name;
  }
}

Color getColor(Type insType)
{
  final switch(insType)
  {
  case Type.Jump: return Color.Green;
  case Type.Call: return Color.Green;
  case Type.Ret: return Color.Green;
  case Type.Assign: return Color.White;
  case Type.Op: return Color.Blue;
  case Type.Nop: return Color.Blue;
  case Type.Unknown: return Color.Red;
  }
}

