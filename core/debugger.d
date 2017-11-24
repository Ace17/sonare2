/*
 * Copyright (C) 2017 - Sebastien Alaiwan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import std.string;

import core.sys.posix.stdio;
import core.sys.posix.stdlib;
import core.sys.posix.unistd;

import document;
import ptrace;

void run(Document doc, string path)
{
  auto child_pid = fork();

  if(child_pid < 0)
  {
    perror("fork");
    return;
  }

  if(child_pid > 0)
    run_debugger(child_pid);
  else
    run_target(path);
}

void run_debugger(pid_t child_pid)
{
  int waitStatus;
  int icounter = 0;
  printf("debugger started\n");

  // Wait for child to stop on its first instruction
  wait(&waitStatus);

  while(WIFSTOPPED(waitStatus))
  {
    icounter++;

    user_regs_struct regs;
    ptrace.ptrace(PTraceRequest.PTRACE_GETREGS, child_pid, null, &regs);
    const instr = ptrace.ptrace(PTraceRequest.PTRACE_PEEKTEXT, child_pid, cast(void*)regs.rip, null);

    printf("[%u] RIP = 0x%08x. instr = 0x%08x\n",
           icounter, regs.rip, instr);

    // Make the child execute another instruction
    if(ptrace.ptrace(PTraceRequest.PTRACE_SINGLESTEP, child_pid, null, null) < 0)
    {
      perror("ptrace");
      return;
    }

    // Wait for child to stop on its next instruction
    wait(&waitStatus);
  }

  printf("the child executed %u instructions\n", icounter);
}

void run_target(string path)
{
  const char* programname = toStringz(path);

  /* Allow tracing of this process */
  if(ptrace.ptrace(PTraceRequest.PTRACE_TRACEME, 0, null, null) < 0)
  {
    perror("ptrace");
    return;
  }

  /* Replace this process's image with the given program */
  execl(programname, programname, 0);
}

