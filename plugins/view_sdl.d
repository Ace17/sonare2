/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// SDL2 view implementation.
// - Takes a ViewModel and renders it.
// - Receives user events, and forward them to the presenter (through an InputSink)

import SDL;
import input_sink;
import view;

static this()
{
  registerView!SdlView("sdl");
}

class SdlView : IView
{
  this(InputSink sink)
  {
    m_sink = sink;
    SDL_Init(SDL_INIT_VIDEO);
    SDL_Window* displayWindow;
    SDL_CreateWindowAndRenderer(1024, 1024, SDL_WINDOW_OPENGL, &displayWindow, &m_renderer);
    SDL_StartTextInput();
  }

  ~this()
  {
    SDL_Quit();
  }

  int getLineCount()
  {
    return 40;
  }

  void refresh(in ViewModel model)
  {
    if(model.quit)
      m_quit = true;
  }

  void run()
  {
    SDL_Event evt;

    while(!m_quit)
    {
      SDL_WaitEvent(&evt);
      switch(evt.type)
      {
      case SDL_KEYDOWN:
        switch(evt.key.keysym.sym)
        {
        case SDLK_BACKSPACE:
          m_sink.onChar('\x08');
          break;
        case SDLK_TAB:
          m_sink.onChar('\t');
          break;
        case SDLK_RETURN:
          m_sink.onChar('\x0D');
          break;
        default:
          break;
        }

        break;
      case SDL_TEXTINPUT:
        import std.conv;
        const txt = to!string(evt.text.text.ptr);

        foreach(c; txt)
          m_sink.onChar(c);

        break;

      case SDL_WINDOWEVENT:

        if(evt.window.event == SDL_WINDOWEVENT_CLOSE)
          return;

        break;

      default:
        break;
      }

      SDL_RenderPresent(m_renderer);
    }
  }

  bool m_quit;
  SDL_Renderer* m_renderer;
  InputSink m_sink;
}

