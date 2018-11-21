// Copyright (C) 2017 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// helper for unit tests (only).

void assertEquals(S, T)(S expected, T actual, string file = __FILE__, size_t line = __LINE__)
{
  import core.exception;
  import std.string;

  if(expected == actual)
    return;

  const msg = format("Expected: '%s', but was: '%s'", expected, actual);
  throw new AssertError(msg, file, line);
}

