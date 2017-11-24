import std.c.linux.linux;
import core.stdc.config : c_ulong, c_long;

/// Argument for `personality (2)` to disable ASLR
enum ADDR_NO_RANDOMIZE = 0x0040000;

/// PTrace commands. See ptrace(2) for more info.
enum PTraceRequest : int {
	PTRACE_TRACEME = 0,
	PTRACE_PEEKTEXT = 1,
	PTRACE_PEEKDATA = 2,
	PTRACE_PEEKUSER = 3,
	PTRACE_POKETEXT = 4,
	PTRACE_POKEDATA = 5,
	PTRACE_POKEUSER = 6,
	PTRACE_CONT = 7,
	PTRACE_KILL = 8,
	PTRACE_SINGLESTEP = 9,
	PTRACE_GETREGS = 12,
	PTRACE_SETREGS = 13,
	PTRACE_GETFPREGS = 14,
	PTRACE_SETFPREGS = 15,
	PTRACE_ATTACH = 16,
	PTRACE_DETACH = 17,
	PTRACE_GETFPXREGS = 18,
	PTRACE_SETFPXREGS = 19,
	PTRACE_SYSCALL = 24,
	PTRACE_SETOPTIONS = 0x4200,
	PTRACE_GETEVENTMSG = 0x4201,
	PTRACE_GETSIGINFO = 0x4202,
	PTRACE_SETSIGINFO = 0x4203,
	PTRACE_GETREGSET = 0x4204,
	PTRACE_SETREGSET = 0x4205,
	PTRACE_SEIZE = 0x4206,
	PTRACE_INTERRUPT = 0x4207,
	PTRACE_LISTEN = 0x4208,
	PTRACE_PEEKSIGINFO = 0x4209,
};

/// Options for PTRACE_SETOPTIONS. See ptrace(2) for more info.
enum PTraceOptions : int {
	PTRACE_O_TRACESYSGOOD = 0x00000001,
	PTRACE_O_TRACEFORK = 0x00000002,
	PTRACE_O_TRACEVFORK = 0x00000004,
	PTRACE_O_TRACECLONE = 0x00000008,
	PTRACE_O_TRACEEXEC = 0x00000010,
	PTRACE_O_TRACEVFORKDONE = 0x00000020,
	PTRACE_O_TRACEEXIT = 0x00000040,
	PTRACE_O_TRACESECCOMP = 0x00000080,
	PTRACE_O_EXITKILL = 0x00100000,
	PTRACE_O_MASK = 0x001000ff,
};

version(X86) {
	// TODO: FPX regs
	struct user_fpregs_struct
	{
		c_long cwd;
		c_long swd;
		c_long twd;
		c_long fip;
		c_long fcs;
		c_long foo;
		c_long fos;
		c_long[20] st_space;
	};
	struct user_regs_struct
	{
		c_long ebx;
		c_long ecx;
		c_long edx;
		c_long esi;
		c_long edi;
		c_long ebp;
		c_long eax;
		c_long xds;
		c_long xes;
		c_long xfs;
		c_long xgs;
		c_long orig_eax;
		c_long eip;
		c_long xcs;
		c_long eflags;
		c_long esp;
		c_long xss;
	};
} else version (X86_64) {
	struct user_fpregs_struct
	{
		ushort cwd;
		ushort swd;
		ushort ftw;
		ushort fop;
		c_ulong rip;
		c_ulong rdp;
		uint mxcsr;
		uint mxcr_mask;
		uint[32] st_space;   /* 8*16 bytes for each FP-reg = 128 bytes */
		uint[64] xmm_space;  /* 16*16 bytes for each XMM-reg = 256 bytes */
		uint[24] padding;
	};

	struct user_regs_struct
	{
		c_ulong r15;
		c_ulong r14;
		c_ulong r13;
		c_ulong r12;
		c_ulong rbp;
		c_ulong rbx;
		c_ulong r11;
		c_ulong r10;
		c_ulong r9;
		c_ulong r8;
		c_ulong rax;
		c_ulong rcx;
		c_ulong rdx;
		c_ulong rsi;
		c_ulong rdi;
		c_ulong orig_rax;
		c_ulong rip;
		c_ulong cs;
		c_ulong eflags;
		c_ulong rsp;
		c_ulong ss;
		c_ulong fs_base;
		c_ulong gs_base;
		c_ulong ds;
		c_ulong es;
		c_ulong fs;
		c_ulong gs;
	};

} else static assert(false, "Unsupported architecture.");

extern(C) {
	/// personality (2)
	int personality(c_ulong);
	
	/// ptrace (2)
	c_long ptrace(PTraceRequest, pid_t, void*, void*);
}
