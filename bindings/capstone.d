void test()
{
  import std.stdio;
  immutable CODE = "\x55\x48\x8b\x05\xb8\x13\x00\x00";

  csh handle;
  if (cs_open(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_64, &handle) != cs_err.CS_ERR_OK)
    throw new Exception("can't open capstone");

  cs_insn *insn;
  const count = cs_disasm(handle, cast(ubyte*)CODE.ptr, CODE.length, 0x1000UL, 0UL, &insn);
  if (count <= 0)
    throw new Exception("failed to disassemble");

  for (size_t j = 0; j < count; j++)
    writefln("0x%.8X: %.5s %s",
        insn[j].address,
        insn[j].mnemonic,
        insn[j].op_str);

  cs_free(insn, count);

  cs_close(&handle);
}

extern(C):

/*
 Initialize CS handle: this must be done before any usage of CS.

 @arch: architecture type (CS_ARCH_*)
 @mode: hardware mode. This is combined of CS_MODE_*
 @handle: pointer to handle, which will be updated at return time

 @return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
 for detailed error).
*/
cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle);

/*
 Close CS handle: MUST do to release the handle when it is not used anymore.
 NOTE: this must be only called when there is no longer usage of Capstone,
 not even access to cs_insn array. The reason is the this API releases some
 cached memory, thus access to any Capstone API after cs_close() might crash
 your application.

 In fact,this API invalidate @handle by ZERO out its value (i.e *handle = 0).

 @handle: pointer to a handle returned by cs_open()

 @return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
 for detailed error).
*/
cs_err cs_close(csh *handle);

/*
 Disassemble binary code, given the code buffer, size, address and number
 of instructions to be decoded.
 This API dynamically allocate memory to contain disassembled instruction.
 Resulted instructions will be put into @*insn

 NOTE 1: this API will automatically determine memory needed to contain
 output disassembled instructions in @insn.

 NOTE 2: caller must free the allocated memory itself to avoid memory leaking.

 NOTE 3: for system with scarce memory to be dynamically allocated such as
 OS kernel or firmware, the API cs_disasm_iter() might be a better choice than
 cs_disasm(). The reason is that with cs_disasm(), based on limited available
 memory, we have to calculate in advance how many instructions to be disassembled,
 which complicates things. This is especially troublesome for the case @count=0,
 when cs_disasm() runs uncontrollably (until either end of input buffer, or
 when it encounters an invalid instruction).

 @handle: handle returned by cs_open()
 @code: buffer containing raw binary code to be disassembled.
 @code_size: size of the above code buffer.
 @address: address of the first instruction in given raw code buffer.
 @insn: array of instructions filled in by this API.
	   NOTE: @insn will be allocated by this function, and should be freed
	   with cs_free() API.
 @count: number of instructions to be disassembled, or 0 to get all of them

 @return: the number of successfully disassembled instructions,
 or 0 if this function failed to disassemble the given code

 On failure, call cs_errno() for error code.
*/
size_t cs_disasm(csh handle, const ubyte *code, size_t code_size, ulong address, size_t count, cs_insn **insn);

/*
 Free memory allocated by cs_malloc() or cs_disasm() (argument @insn)

 @insn: pointer returned by @insn argument in cs_disasm() or cs_malloc()
 @count: number of cs_insn structures returned by cs_disasm(), or 1
     to free memory allocated by cs_malloc().
*/
void cs_free(cs_insn *insn, size_t count);

// Handle using with all API
alias csh = size_t;

// Architecture type
enum cs_arch
{
	CS_ARCH_ARM = 0,	// ARM architecture (including Thumb, Thumb-2)
	CS_ARCH_ARM64,		// ARM-64, also called AArch64
	CS_ARCH_MIPS,		// Mips architecture
	CS_ARCH_X86,		// X86 architecture (including x86 & x86-64)
	CS_ARCH_PPC,		// PowerPC architecture
	CS_ARCH_SPARC,		// Sparc architecture
	CS_ARCH_SYSZ,		// SystemZ architecture
	CS_ARCH_XCORE,		// XCore architecture
	CS_ARCH_MAX,
	CS_ARCH_ALL = 0xFFFF, // All architectures - for cs_support()
};

// Mode type
enum cs_mode
{
	CS_MODE_LITTLE_ENDIAN = 0,	// little-endian mode (default mode)
	CS_MODE_ARM = 0,	// 32-bit ARM
	CS_MODE_16 = 1 << 1,	// 16-bit mode (X86)
	CS_MODE_32 = 1 << 2,	// 32-bit mode (X86)
	CS_MODE_64 = 1 << 3,	// 64-bit mode (X86, PPC)
	CS_MODE_THUMB = 1 << 4,	// ARM's Thumb mode, including Thumb-2
	CS_MODE_MCLASS = 1 << 5,	// ARM's Cortex-M series
	CS_MODE_V8 = 1 << 6,	// ARMv8 A32 encodings for ARM
	CS_MODE_MICRO = 1 << 4, // MicroMips mode (MIPS)
	CS_MODE_MIPS3 = 1 << 5, // Mips III ISA
	CS_MODE_MIPS32R6 = 1 << 6, // Mips32r6 ISA
	CS_MODE_MIPSGP64 = 1 << 7, // General Purpose Registers are 64-bit wide (MIPS)
	CS_MODE_V9 = 1 << 4, // SparcV9 mode (Sparc)
	CS_MODE_BIG_ENDIAN = 1 << 31,	// big-endian mode
	CS_MODE_MIPS32 = CS_MODE_32,	// Mips32 ISA (Mips)
	CS_MODE_MIPS64 = CS_MODE_64,	// Mips64 ISA (Mips)
};

// Detail information of disassembled instruction
struct cs_insn
{
	// Instruction ID (basically a numeric ID for the instruction mnemonic)
	// Find the instruction id in the '[ARCH]_insn' enum in the header file
	// of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
	// 'x86_insn' in x86.h for X86, etc...
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	// NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
	uint id;

	// Address (EIP) of this instruction
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	ulong address;

	// Size of this instruction
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	ushort size;

	// Machine bytes of this instruction, with number of bytes indicated by @size above
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	ubyte[16] bytes;

	// Ascii text of instruction mnemonic
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	char[32] mnemonic;

	// Ascii text of instruction operands
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	char[160] op_str;

	// Pointer to cs_detail.
	// NOTE: detail pointer is only valid when both requirements below are met:
	// (1) CS_OP_DETAIL = CS_OPT_ON
	// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
	//
	// NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
	//     is not NULL, its content is still irrelevant.
	cs_detail *detail;
};

struct cs_detail
{
}

enum cs_err
{
	CS_ERR_OK = 0,   // No error: everything was fine
	CS_ERR_MEM,      // Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
	CS_ERR_ARCH,     // Unsupported architecture: cs_open()
	CS_ERR_HANDLE,   // Invalid handle: cs_op_count(), cs_op_index()
	CS_ERR_CSH,	     // Invalid csh argument: cs_close(), cs_errno(), cs_option()
	CS_ERR_MODE,     // Invalid/unsupported mode: cs_open()
	CS_ERR_OPTION,   // Invalid/unsupported option: cs_option()
	CS_ERR_DETAIL,   // Information is unavailable because detail option is OFF
	CS_ERR_MEMSETUP, // Dynamic memory management uninitialized (see CS_OPT_MEM)
	CS_ERR_VERSION,  // Unsupported version (bindings)
	CS_ERR_DIET,     // Access irrelevant data in "diet" engine
	CS_ERR_SKIPDATA, // Access irrelevant data for "data" instruction in SKIPDATA mode
	CS_ERR_X86_ATT,  // X86 AT&T syntax is unsupported (opt-out at compile time)
	CS_ERR_X86_INTEL, // X86 Intel syntax is unsupported (opt-out at compile time)
};

