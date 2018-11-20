/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// ANSI-terminal view implementation.
// - Takes a ViewModel and renders it.
// - Receives user events, and forward them to the presenter (through an InputSink)

import std.algorithm;
import std.string;

import input_sink;
import ncurses;
import view;

import core.stdc.stdio;

static this()
{
  registerView!ConsoleView("console");
}

class ConsoleView : IView
{
  this(InputSink s)
  {
    m_sink = s;
    init_ncurses();
  }

  ~this()
  {
    deinit_ncurses();
  }

  void run()
  {
    while(!should_exit)
    {
      // Using getch() here instead would refresh stdscr, overwriting the
      // initial contents of the other windows on startup
      int c = wgetch(m_cmdWindow);
      switch(c)
      {
      case KEY_RESIZE:
        resize();
        break;

      // Ctrl-L -- redraw screen
      case '\f':
        // Makes the next refresh repaint the screen from scratch
        CHECK!clearok(curscr, true);
        // Resize and reposition windows in case that got messed up somehow
        resize();
        break;

      default:
        m_sink.onChar(cast(char)c);
      }
    }
  }

  void resize()
  {
    if(LINES >= 3)
    {
      CHECK!wresize(m_txtWindow, LINES - 2, COLS);
      CHECK!wresize(m_separator, 1, COLS);
      CHECK!wresize(m_cmdWindow, 1, COLS);

      CHECK!mvwin(m_separator, LINES - 2, 0);
      CHECK!mvwin(m_cmdWindow, LINES - 1, 0);
    }

    // Batch refreshes and commit them with doupdate()
    redraw();
    CHECK!wnoutrefresh(m_txtWindow);
    CHECK!wnoutrefresh(m_separator);
    CHECK!wnoutrefresh(m_cmdWindow);
    CHECK!doupdate();
  }

  void refresh(in ViewModel model)
  {
    should_exit = model.quit;
    m_viewModel = cast(ViewModel)model;

    redraw();

    CHECK!wrefresh(m_txtWindow);
  }

  int getLineCount()
  {
    return LINES - 3;
  }

  void redraw()
  {
    CHECK!werase(m_txtWindow);

    Line getLine(int i)
    {
      if(i < 0 || i >= m_viewModel.lines.length)
        return Line();

      return m_viewModel.lines[i];
    }

    foreach(k; 0 .. LINES - 3)
    {
      auto line = getLine(k);

      ulong attr = ulong.max;

      foreach(int i, c; line.text)
      {
        int pair;
        final switch(c.color)
        {
        case Color.White: pair = 0;
          break;
        case Color.Yellow: pair = 2;
          break;
        case Color.Green: pair = 3;
          break;
        case Color.Blue: pair = 4;
          break;
        case Color.Red: pair = 5;
          break;
        }

        if(k == LINES / 2)
          pair = 2;

        attr = COLOR_PAIR(pair);

        wattron(m_txtWindow, attr);
        CHECK!mvwaddch(m_txtWindow, 1 + k, 1 + i, c.value);
        wattroff(m_txtWindow, attr);
      }
    }

    if(m_viewModel.commandMode)
    {
      wclear(m_cmdWindow);
      mvwaddstr(m_cmdWindow, 0, 0, toStringz(":" ~ m_viewModel.command));
      curs_set(2);
    }
    else
    {
      wclear(m_cmdWindow);
      mvwaddstr(m_cmdWindow, 0, 0, toStringz(" " ~ m_viewModel.command));
      curs_set(0);
    }
  }

  void init_ncurses()
  {
    if(!initscr())
      throw new Exception("Failed to initialize ncurses");

    if(has_colors())
    {
      CHECK!start_color();
      CHECK!use_default_colors();
    }

    CHECK!cbreak();
    CHECK!noecho();
    CHECK!nonl();
    CHECK!intrflush(null, false);
    // Do not enable keypad() since we want to pass unadulterated input to
    // readline

    // Explicitly specify a "very visible" cursor to make sure it's at least
    // consistent when we turn the cursor on and off (maybe it would make sense
    // to query it and use the value we get back too). "normal" vs. "very
    // visible" makes no difference in gnome-terminal or xterm. Let this fail
    // for terminals that do not support cursor visibility adjustments.
    curs_set(2);

    if(LINES >= 3)
    {
      m_txtWindow = newwin(LINES - 2, COLS, 0, 0);
      m_separator = newwin(1, COLS, LINES - 2, 0);
      m_cmdWindow = newwin(1, COLS, LINES - 1, 0);
    }
    else
    {
      // Degenerate case. Give the windows the minimum workable size to
      // prevent errors from e.g. wmove().
      m_txtWindow = newwin(1, COLS, 0, 0);
      m_separator = newwin(1, COLS, 0, 0);
      m_cmdWindow = newwin(1, COLS, 0, 0);
    }

    if(!m_txtWindow || !m_separator || !m_cmdWindow)
      throw new Exception("Failed to allocate windows");

    // Allow strings longer than the message window and show only the last part
    // if the string doesn't fit
    CHECK!scrollok(m_txtWindow, true);

    if(has_colors())
    {
      init_pair(1, COLOR_WHITE, COLOR_BLUE);
      init_pair(2, COLOR_BLACK, COLOR_WHITE);
      init_pair(3, COLOR_GREEN, COLOR_BLACK);
      init_pair(4, COLOR_BLUE, COLOR_BLACK);
      init_pair(5, COLOR_RED, COLOR_BLACK);

      CHECK!wbkgd(m_separator, COLOR_PAIR(1));
    }
    else
      // ...or the "best highlighting mode of the terminal" if it doesn't
      // support colors
      CHECK!wbkgd(m_separator, A_STANDOUT);

    CHECK!wrefresh(m_separator);
  }

  void deinit_ncurses()
  {
    CHECK!delwin(m_txtWindow);
    CHECK!delwin(m_separator);
    CHECK!delwin(m_cmdWindow);
    CHECK!endwin();
  }

  ViewModel m_viewModel;
  InputSink m_sink;

  WINDOW* m_txtWindow;
  WINDOW* m_separator;
  WINDOW* m_cmdWindow;
  bool should_exit = false;
}

// Checks errors for (most) ncurses functions. CHECK(fn, x, y, z) is a checked
// version of fn(x, y, z).
void CHECK(alias fn, int line = __LINE__, T...)(T args)
{
  import std.string;
  const res = fn(args);

  if(res == ERR)
    throw new Exception(format("Failure at line %d", line));
}

