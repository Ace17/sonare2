// Copyright (C) 2018 - Sebastien Alaiwan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// Loader for ELF files

import std.conv;
import std.file;
import std.string;

import document;
import loader;

static this()
{
  g_Loaders.register("elf", new ElfLoader);
}

class ElfLoader : Loader
{
  bool probe(string path)
  {
    const data = cast(ubyte[])std.file.read(path);

    if(data[0 .. 4] !=[0x7f, 'E', 'L', 'F'])
      return false;

    return true;
  }

  void load(Document prog, string path, ulong address)
  {
    if(address != ulong.max)
      throw new Exception("ELF loading to a user-specified address isn't implemented");

    const rawBytes = cast(ubyte[])std.file.read(path);
    auto elf = parse(rawBytes);
    switch(elf.fileHeader.e_machine)
    {
    case EM_386:
      prog.arch = "x86_32";
      break;
    case EM_ARM:
      prog.arch = "arm_32";
      break;
    default:
      throw new Exception(format("ELF: unknown machine type: %d", elf.fileHeader.e_machine));
    }

    gatherAllSymbols(prog, elf);
    mapSections(prog, elf);

    prog.entryPoint = elf.fileHeader.e_entry;
    prog.symbols[elf.fileHeader.e_entry] = "entry0";
  }

private:
  void mapSections(Document prog, ElfBinary elf)
  {
    foreach(ref raw_sect; elf.raw_sections)
    {
      const sh = &elf.sectionHeaders[raw_sect.section_index];

      // skip reserved sections
      if(sh.sh_type == SHT_NULL)
        continue;

      if(sh.sh_type == SHT_STRTAB)
        continue;

      if(sh.sh_type == SHT_SYMTAB)
        continue;

      if(sh.sh_type == SHT_REL || sh.sh_type == SHT_RELA)
        continue;

      string sectionName = elf.GetSectionName(raw_sect.section_index);
      const sectionAddr = cast(uint)sh.sh_addr;

      const hasBits = sh.sh_type != SHT_NOBITS;
      const executable = sh.sh_flags & SHF_EXECINSTR ? true : false;

      if(hasBits && executable && sectionName == ".text")
      {
        Region reg;

        reg.address = sectionAddr;
        reg.data = raw_sect.data;

        prog.regions ~= reg;
      }
    }
  }

  void gatherAllSymbols(Document prog, ElfBinary elf)
  {
    foreach(symtab; elf.symbol_tables)
    {
      foreach(SYM_TAB_IDX iSymbolIdx, s; symtab.symbols)
      {
        if(iSymbolIdx == 0)
          continue;

        if(s.st_name)
        {
          string sName = elf.GetSymbolName(symtab.section_index, iSymbolIdx);
          prog.symbols[s.st_value] = sName;
        }
      }
    }
  }
}

alias int SECTION_IDX;
alias int SYM_TAB_IDX;
alias int STR_TAB_IDX;

class CStringTable
{
  SECTION_IDX section_index;
  string[] strings;
  string data;

  string GetString(STR_TAB_IDX index)
  {
    return to!string(&data[index]);
  }
}

// type-safe version of ELF standard structure
struct FileHeader
{
  ubyte[EI_NIDENT] e_ident; /* Magic number and other info */
  ET e_type;              /* Object file type */
  Elf32_Half e_machine;    /* Architecture */
  Elf32_Word e_version;    /* Object file version */
  Elf32_Addr e_entry;      /* Entry point virtual address */
  Elf32_Off e_phoff;      /* Program header table file offset */
  Elf32_Off e_shoff;      /* Section header table file offset */
  Elf32_Word e_flags;      /* Processor-specific flags */
  Elf32_Half e_ehsize;     /* ELF header size in bytes */
  Elf32_Half e_phentsize;  /* Program header table entry size */
  Elf32_Half e_phnum;      /* Program header table entry count */
  Elf32_Half e_shentsize;  /* Section header table entry size */
  Elf32_Half e_shnum;      /* Section header table entry count */
  SECTION_IDX e_shstrndx;   /* Section header string table index */
}

// type-safe version of ELF standard structure
struct SectionHeader
{
  STR_TAB_IDX sh_name;      // Section name (string tbl index)
  SHT sh_type;      // Section type
  Elf32_Word sh_flags;     // Section flags
  Elf32_Addr sh_addr;      // Section virtual addr at execution
  Elf32_Off sh_offset;    // Section file offset
  Elf32_Word sh_size;      // Section size in bytes
  SECTION_IDX sh_link;      // Link to another section
  Elf32_Word sh_info;      // Additional section information
  Elf32_Word sh_addralign; // Section alignment
  Elf32_Word sh_entsize;   // Entry size if section holds table

  SECTION_IDX getPatchedSectionIdx() const
  {
    assert(sh_type == SHT_RELA || sh_type == SHT_REL);
    return cast(SECTION_IDX)sh_info;
  }
}

/**
 * @brief type-safe version of Elf32_Sym standard structure
 */
struct SElfSymbol
{
  STR_TAB_IDX st_name;    // Symbol name (string tbl index)
  Elf32_Addr st_value;   // Symbol value
  Elf32_Word st_size;    // Symbol size
  ubyte st_info;    // Symbol type and binding
  ubyte st_other;   // Symbol visibility
  SECTION_IDX st_shndx;   // Section index

  string Name;
}

/**
 * @brief type-safe version of Elf32_Rel standard structure
 */
class CRelocation
{
  Elf32_Addr r_offset;   // Address
  Elf32_Word r_info;     // Relocation type and symbol index

  SYM_TAB_IDX getSymbolIdx() const
  {
    return cast(SYM_TAB_IDX)(r_info >> 8);
  }

  uint getRelocationType() const
  {
    return r_info & 0xff;
  }

  SElfSymbol AssociatedSymbol;
}

class CSymbolTable
{
  SECTION_IDX section_index;
  SElfSymbol[] symbols;

  // Pointer to the string table containing the symbol names
  CStringTable p_strtab;

  // Pointer to the string table containing the section names
  CStringTable p_shstrtab;
}

class CRelocationTable
{
  SECTION_IDX section_index;
  CRelocation[] rels;

  CSymbolTable p_symtab;
  CRawSection p_patch;
}

class CProgbitsSection
{
  SECTION_IDX section_index;
  ubyte[] data;
}

struct SByteInfo
{
  bool hasSymbols() const
  {
    return symbols.length > 0;
  }

  bool hasRelocation() const
  {
    return Relocation !is null;
    // return bHasRelocation;
  }

  bool bHasRelocation = false;

  CRelocation Relocation;

  /**
   * @brief symbol whose address will be used to compute the relocation.
   */
  string rel_symbol;

  /**
   * @brief section containing the relocation symbol
   */
  SECTION_IDX rel_section;

  /**
   * @brief Relocation is relative to the byte address
   */
  bool rel_relative = false;

  /**
   * @brief Symbols that point to this byte
   */
  string[] symbols;
}

class CRawSection
{
  SECTION_IDX section_index;
  ubyte[] data;
  SByteInfo[] info;
}

class Stream
{
  this(const(ubyte)[] data_)
  {
    data = data_;
  }

  void readExact(void* dst, size_t n)
  {
    auto bytes = cast(ubyte*)dst;

    foreach(k; 0 .. n)
      bytes[k] = nextByte();
  }

  void read(ubyte[] s)
  {
    readExact(s.ptr, s.length);
  }

  ubyte getc()
  {
    return nextByte();
  }

  ubyte nextByte()
  {
    return data[pos++];
  }

  void position(long pos_)
  {
    pos = pos_;
  }

  long position()
  {
    return pos;
  }

  long pos;

  const(ubyte)[] data;
}

ElfBinary parse(const ubyte[] data)
{
  auto r = new ElfBinary;
  r.parse(data);
  return r;
}

class ElfBinary
{
  int bits;
  CStringTable[] string_tables;
  CSymbolTable[] symbol_tables;
  CRelocationTable[] reloc_table;
  CProgbitsSection[] progbits_sections;
  CRawSection[] raw_sections;

  FileHeader fileHeader;
  SectionHeader[] sectionHeaders;
  ProgramHeader[] programHeaders;

  CStringTable GetStringTable(SECTION_IDX section_index)
  {
    foreach(t; string_tables)
    {
      if(t.section_index == section_index)
        return t;
    }

    throw new Exception("String table not found");
  }

  CSymbolTable GetSymbolTable(SECTION_IDX section_index)
  {
    foreach(t; symbol_tables)
    {
      if(t.section_index == section_index)
        return t;
    }

    throw new Exception("Symbol table not found");
  }

  string GetSectionName(SECTION_IDX section_index)
  {
    STR_TAB_IDX string_index = sectionHeaders[section_index].sh_name;
    return GetStringTable(fileHeader.e_shstrndx).GetString(string_index);
  }

  string GetSymbolName(SECTION_IDX symtab_sh_idx, SYM_TAB_IDX sym_idx)
  {
    return GetSymbolName(GetSymbolTable(symtab_sh_idx), sym_idx);
  }

  string GetSymbolName(CSymbolTable symtab, SYM_TAB_IDX iSymbolIndex)
  {
    SElfSymbol s = symtab.symbols[iSymbolIndex];
    int iSymType = s.st_info & 0xf;
    string sName;

    if(iSymType == STT_SECTION)
    {
      sName = "start_section." ~ GetSectionName(s.st_shndx);
    }
    else
    {
      sName = symtab.p_strtab.GetString(s.st_name);
      assert(sName != "");
    }

    assert(sName != "");
    return sName;
  }

private:
  void ParseElfHeader(Stream f, ref FileHeader hdr)
  {
    f.readExact(hdr.e_ident.ptr, EI_NIDENT);

    if(hdr.e_ident[0 .. 8] !=[0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00])
      throw new Exception("not a 32-bit ELF file");

    hdr.e_type = cast(ET) get_Elf32_Half(f);
    hdr.e_machine = get_Elf32_Half(f);
    hdr.e_version = get_Elf32_Word(f);
    hdr.e_entry = get_Elf32_Addr(f);
    hdr.e_phoff = get_Elf32_Off(f);
    hdr.e_shoff = get_Elf32_Off(f);
    hdr.e_flags = get_Elf32_Word(f);
    hdr.e_ehsize = get_Elf32_Half(f);
    hdr.e_phentsize = get_Elf32_Half(f);
    hdr.e_phnum = get_Elf32_Half(f);
    hdr.e_shentsize = get_Elf32_Half(f);
    hdr.e_shnum = get_Elf32_Half(f);
    hdr.e_shstrndx = cast(SECTION_IDX) get_Elf32_Half(f);

    assert(hdr.e_version == EV_CURRENT);
  }

  SectionHeader ParseSectionHeader(Stream f)
  {
    SectionHeader hdr;
    hdr.sh_name = cast(STR_TAB_IDX) get_Elf32_Word(f);
    hdr.sh_type = cast(SHT) get_Elf32_Word(f);
    hdr.sh_flags = get_Elf32_Word(f);
    hdr.sh_addr = get_Elf32_Addr(f);
    hdr.sh_offset = get_Elf32_Off(f);
    hdr.sh_size = get_Elf32_Word(f);
    hdr.sh_link = cast(SECTION_IDX) get_Elf32_Word(f);
    hdr.sh_info = get_Elf32_Word(f);
    hdr.sh_addralign = get_Elf32_Word(f);
    hdr.sh_entsize = get_Elf32_Word(f);

    return hdr;
  }

  void ParseProgramHeader(Stream f)
  {
    // parse program header
    assert(fileHeader.e_phoff != 0);

    programHeaders.length = fileHeader.e_phnum + 1;

    for(int i = 0; i <= fileHeader.e_phnum; ++i)
    {
      f.position(fileHeader.e_phoff + i * fileHeader.e_phentsize);
      programHeaders[i].p_type = get_Elf32_Word(f);
      programHeaders[i].p_offset = get_Elf32_Off(f);
      programHeaders[i].p_vaddr = get_Elf32_Addr(f);
      programHeaders[i].p_paddr = get_Elf32_Addr(f);
      programHeaders[i].p_filesz = get_Elf32_Word(f);
      programHeaders[i].p_memsz = get_Elf32_Word(f);
      programHeaders[i].p_flags = get_Elf32_Word(f);
      programHeaders[i].p_align = get_Elf32_Word(f);
    }
  }

  void ParseSectionHeaders(Stream f)
  {
    // parse section headers
    assert(fileHeader.e_shoff != 0);

    for(int i = 0; i < fileHeader.e_shnum; ++i)
    {
      f.position(fileHeader.e_shoff + i * fileHeader.e_shentsize);
      sectionHeaders ~= ParseSectionHeader(f);
    }
  }

  // Parses input stream and fills internal buffers with raw
  void ParseRawSections(Stream f)
  {
    foreach(SECTION_IDX i, sh; sectionHeaders)
    {
      CRawSection raw_sect = new CRawSection;
      raw_sect.section_index = i;
      raw_sect.data.length = sh.sh_size;
      raw_sect.info.length = sh.sh_size;

      if(sh.sh_type != SHT_NOBITS)
      {
        f.position(sh.sh_offset);
        f.read(raw_sect.data);
      }

      raw_sections ~= raw_sect;
    }
  }

  // Parses all string tables and construct abstract versions of them.
  void ParseStringTables(Stream f)
  {
    // parse string tables
    foreach(SECTION_IDX i, sh; sectionHeaders)
    {
      if(sh.sh_type != SHT_STRTAB)
        continue;

      CStringTable table = new CStringTable;
      table.section_index = i;

      f.position(sh.sh_offset);

      string s = "";

      while(f.position() < sh.sh_offset + sh.sh_size)
      {
        int c = f.getc();
        char cc = cast(char)c;
        table.data ~= cc;

        if(c == 0)
        {
          table.strings ~= s;
          s = "";
        }
        else
        {
          s ~= cc;
        }
      }

      string_tables ~= table;
    }
  }

  void ParseSymbolTables(Stream f)
  {
    foreach(SECTION_IDX i, sh; sectionHeaders)
    {
      if(sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM)
        continue;

      CSymbolTable table = new CSymbolTable;
      table.section_index = i;

      // link to strtab section
      table.p_strtab = GetStringTable(sh.sh_link);
      f.position(sh.sh_offset);

      SYM_TAB_IDX SymbolIdx = 0;

      while(f.position() < sh.sh_offset + sh.sh_size)
      {
        SElfSymbol sym;

        sym.st_name = cast(STR_TAB_IDX) get_Elf32_Word(f);
        sym.st_value = get_Elf32_Addr(f);
        sym.st_size = get_Elf32_Word(f);
        sym.st_info = f.getc();
        sym.st_other = f.getc();
        sym.st_shndx = cast(SECTION_IDX) get_Elf32_Half(f);

        table.symbols ~= sym;

        if((sym.st_shndx < SHN_LORESERVE || sym.st_shndx > SHN_HIRESERVE) && sym.st_shndx > 0)
        {
          // if(sym.st_name > 0)
          {
            string sSymbolName = GetSymbolName(table, SymbolIdx);
            sym.Name = sSymbolName;
            // raw_sections[sym.st_shndx].info[sym.st_value].symbols ~= sSymbolName;
          }
        }

        SymbolIdx++;
      }

      symbol_tables ~= table;
    }
  }

  void ParseRelocationSections(Stream f)
  {
    // parse relocation sections
    foreach(SECTION_IDX i, sh; sectionHeaders)
    {
      if(sh.sh_type != SHT_REL)
        continue;

      CRelocationTable table = new CRelocationTable;
      table.section_index = i;

      // link to symtab section
      table.p_symtab = GetSymbolTable(sh.sh_link); // sh_link
      table.p_patch = raw_sections[sh.sh_info];
      f.position(sh.sh_offset);

      while(f.position() < sh.sh_offset + sh.sh_size)
      {
        // parse one relocation entry
        CRelocation rel = new CRelocation;

        rel.r_offset = get_Elf32_Addr(f);
        rel.r_info = get_Elf32_Word(f);
        SYM_TAB_IDX iSymbolIndex = rel.getSymbolIdx();

        rel.AssociatedSymbol = table.p_symtab.symbols[iSymbolIndex];

        table.rels ~= rel;

        // set the "has relocation" flag on the first byte of the patched dword.
        uint iRelocType = rel.getRelocationType();

        if(iRelocType == R_386_32)
        {
          table.p_patch.info[rel.r_offset].rel_relative = false;
        }
        else if(iRelocType == R_386_PC32)
        {
          table.p_patch.info[rel.r_offset].rel_relative = true;
        }
        else
        {
          throw new Exception(format("Unsupported relocation type : %d", iRelocType));
        }

        table.p_patch.info[rel.r_offset].bHasRelocation = true;
        table.p_patch.info[rel.r_offset].rel_symbol = GetSymbolName(table.p_symtab, iSymbolIndex);
        table.p_patch.info[rel.r_offset].rel_section = sh.sh_link;
        table.p_patch.info[rel.r_offset].Relocation = rel;
        assert(table.p_patch.info[rel.r_offset].rel_symbol != "");
      }

      reloc_table ~= table;
    }
  }

  void ParseCode(Stream f)
  {
    // parse progbits sections
    foreach(SECTION_IDX i, sh; sectionHeaders)
    {
      if(sh.sh_type != SHT_PROGBITS)
        continue;

      CProgbitsSection progbits = new CProgbitsSection;
      progbits.section_index = i;
      f.position(sh.sh_offset);
      progbits.data.length = sh.sh_size;

      f.read(progbits.data);

      progbits_sections ~= progbits;
    }
  }

  void parse(const ubyte[] data)
  {
    auto f = new Stream(data);
    ParseElfHeader(f, fileHeader);

    if(fileHeader.e_phoff != 0)
      ParseProgramHeader(f);

    ParseSectionHeaders(f);
    ParseRawSections(f);
    ParseStringTables(f);
    ParseSymbolTables(f);
    // ParseRelocationSections(f);
    ParseCode(f);
  }
}

enum ET
{
  NONE = 0,         /* No file type */
  REL = 1,          /* Relocatable file */
  EXEC = 2,         /* Executable file */
  DYN = 3,          /* Shared object file */
  CORE = 4,         /* Core file */
  NUM = 5,          /* Number of defined types */
  LOOS = 0xfe00,    /* OS-specific range start */
  HIOS = 0xfeff,    /* OS-specific range end */
  LOPROC = 0xff00,  /* Processor-specific range start */
  HIPROC = 0xffff,  /* Processor-specific range end */
}

// Symbol types
enum STT
{
  NOTYPE = 0,   /* Symbol type is unspecified */
  OBJECT = 1,   /* Symbol is a data object */
  FUNC = 2,     /* Symbol is a code object */
  SECTION = 3,  /* Symbol associated with a section */
  FILE = 4,     /* Symbol's name is file name */
  COMMON = 5,   /* Symbol is a common data object */
  TLS = 6,      /* Symbol is thread-local data object*/
  NUM = 7,      /* Number of defined types.  */
  LOOS = 10,    /* Start of OS-specific */
  HIOS = 12,    /* End of OS-specific */
  LOPROC = 13,  /* Start of processor-specific */
  HIPROC = 15,  /* End of processor-specific */
}

// Section types
enum SHT
{
  NULL = 0,   /* Section header table entry unused */
  PROGBITS = 1,   /* Program data */
  SYMTAB = 2,   /* Symbol table */
  STRTAB = 3,   /* String table */
  RELA = 4,   /* Relocation entries with addends */
  HASH = 5,   /* Symbol hash table */
  DYNAMIC = 6,   /* Dynamic linking information */
  NOTE = 7,   /* Notes */
  NOBITS = 8,   /* Program space with no data (bss) */
  REL = 9,   /* Relocation entries, no addends */
  SHLIB = 10,  /* Reserved */
  DYNSYM = 11,  /* Dynamic linker symbol table */
  INIT_ARRAY = 14,  /* Array of constructors */
  FINI_ARRAY = 15,  /* Array of destructors */
  PREINIT_ARRAY = 16,  /* Array of pre-constructors */
  GROUP = 17,  /* Section group */
  SYMTAB_SHNDX = 18,  /* Extended section indeces */
  NUM = 19,  /* Number of defined types.  */

  LOOS = 0x60000000,  /* Start OS-specific.  */
  GNU_HASH = 0x6ffffff6,  /* GNU-style hash table.  */
  GNU_LIBLIST = 0x6ffffff7,  /* Prelink library list */
  CHECKSUM = 0x6ffffff8,  /* Checksum for DSO content.  */
  // LOSUNW     = 0x6ffffffa,  /* Sun-specific low bound.  */
  SUNW_move = 0x6ffffffa,
  SUNW_COMDAT = 0x6ffffffb,
  SUNW_syminfo = 0x6ffffffc,
  GNU_verdef = 0x6ffffffd,  /* Version definition section.  */
  GNU_verneed = 0x6ffffffe,  /* Version needs section.  */
  GNU_versym = 0x6fffffff,  /* Version symbol table.  */
  // HISUNW     = 0x6fffffff,  /* Sun-specific high bound.  */
  HIOS = 0x6fffffff,  /* End OS-specific type */
  LOPROC = 0x70000000,  /* Start of processor-specific */
  HIPROC = 0x7fffffff,  /* End of processor-specific */
  LOUSER = 0x80000000,  /* Start of application-specific */
  HIUSER = 0x8fffffff,  /* End of application-specific */
}

//
// I/O functions
//
Elf32_Half get_Elf32_Half(Stream s)
{
  Elf32_Half w;
  s.readExact(&w, 2);
  return w;
}

Elf32_Word get_Elf32_Word(Stream s)
{
  Elf32_Word w;
  s.readExact(&w, 4);
  return w;
}

Elf32_Addr get_Elf32_Addr(Stream s)
{
  Elf32_Addr w;
  s.readExact(&w, 4);
  return w;
}

Elf32_Off get_Elf32_Off(Stream s)
{
  Elf32_Off w;
  s.readExact(&w, 4);
  return w;
}

///////////////////////////////////////////////////////////////////////////////
//
// ELF types and consts
//
///////////////////////////////////////////////////////////////////////////////

alias ushort uint16_t;
alias uint uint32_t;
alias ulong uint64_t;

alias short int16_t;
alias int int32_t;
alias long int64_t;

/* Type for a 16-bit quantity.  */
alias uint16_t Elf32_Half;
alias uint16_t Elf64_Half;

/* Types for signed and u32-bit quantities.  */
alias uint32_t Elf32_Word;
alias int32_t Elf32_Sword;
alias uint32_t Elf64_Word;
alias int32_t Elf64_Sword;

/* Types for signed and u64-bit quantities.  */
alias uint64_t Elf32_Xword;
alias int64_t Elf32_Sxword;
alias uint64_t Elf64_Xword;
alias int64_t Elf64_Sxword;

/* Type of addresses.  */
alias uint32_t Elf32_Addr;
alias uint64_t Elf64_Addr;

/* Type of file offsets.  */
alias uint32_t Elf32_Off;
alias uint64_t Elf64_Off;

/* Type for section indices, which are 16-bit quantities.  */
alias uint16_t Elf32_Section;
alias uint16_t Elf64_Section;

/* Type for version symbol information.  */
alias Elf32_Half Elf32_Versym;
alias Elf64_Half Elf64_Versym;

/* The ELF file header.  This appears at the start of every ELF file.  */

const EI_NIDENT = 16;

struct Elf32_Ehdr
{
  ubyte[EI_NIDENT] e_ident; /* Magic number and other info */
  Elf32_Half e_type;     /* Object file type */
  Elf32_Half e_machine;    /* Architecture */
  Elf32_Word e_version;    /* Object file version */
  Elf32_Addr e_entry;    /* Entry point virtual address */
  Elf32_Off e_phoff;    /* Program header table file offset */
  Elf32_Off e_shoff;    /* Section header table file offset */
  Elf32_Word e_flags;    /* Processor-specific flags */
  Elf32_Half e_ehsize;   /* ELF header size in bytes */
  Elf32_Half e_phentsize;    /* Program header table entry size */
  Elf32_Half e_phnum;    /* Program header table entry count */
  Elf32_Half e_shentsize;    /* Section header table entry size */
  Elf32_Half e_shnum;    /* Section header table entry count */
  Elf32_Half e_shstrndx;   /* Section header string table index */
}

struct Elf64_Ehdr
{
  ubyte[EI_NIDENT] e_ident; /* Magic number and other info */
  Elf64_Half e_type;     /* Object file type */
  Elf64_Half e_machine;    /* Architecture */
  Elf64_Word e_version;    /* Object file version */
  Elf64_Addr e_entry;    /* Entry point virtual address */
  Elf64_Off e_phoff;    /* Program header table file offset */
  Elf64_Off e_shoff;    /* Section header table file offset */
  Elf64_Word e_flags;    /* Processor-specific flags */
  Elf64_Half e_ehsize;   /* ELF header size in bytes */
  Elf64_Half e_phentsize;    /* Program header table entry size */
  Elf64_Half e_phnum;    /* Program header table entry count */
  Elf64_Half e_shentsize;    /* Section header table entry size */
  Elf64_Half e_shnum;    /* Section header table entry count */
  Elf64_Half e_shstrndx;   /* Section header string table index */
}

/* Fields in the e_ident array.  The EI_* macros are indices into the
   array.  The macros under each EI_* macro are the values the byte
   may have.  */

const EI_MAG0 = 0;   /* File identification byte 0 index */
const ELFMAG0 = 0x7f;    /* Magic number byte 0 */

const EI_MAG1 = 1;   /* File identification byte 1 index */
const ELFMAG1 = 'E';   /* Magic number byte 1 */

const EI_MAG2 = 2;   /* File identification byte 2 index */
const ELFMAG2 = 'L';   /* Magic number byte 2 */

const EI_MAG3 = 3;   /* File identification byte 3 index */
const ELFMAG3 = 'F';   /* Magic number byte 3 */

/* Conglomeration of the identification bytes, for easy testing as a word.  */
const ELFMAG = "\177ELF";
const SELFMAG = 4;

const EI_CLASS = 4;   /* File class byte index */
const ELFCLASSNONE = 0;   /* Invalid class */
const ELFCLASS32 = 1;   /* 32-bit objects */
const ELFCLASS64 = 2;   /* 64-bit objects */
const ELFCLASSNUM = 3;

const EI_DATA = 5;   /* Data encoding byte index */
const ELFDATANONE = 0;   /* Invalid data encoding */
const ELFDATA2LSB = 1;   /* 2's complement, little endian */
const ELFDATA2MSB = 2;   /* 2's complement, big endian */
const ELFDATANUM = 3;

const EI_VERSION = 6;   /* File version byte index */
/* Value must be EV_CURRENT */

const EI_OSABI = 7;   /* OS ABI identification */
const ELFOSABI_NONE = 0; /* UNIX System V ABI */
const ELFOSABI_SYSV = 0; /* Alias.  */
const ELFOSABI_HPUX = 1; /* HP-UX */
const ELFOSABI_NETBSD = 2; /* NetBSD.  */
const ELFOSABI_LINUX = 3; /* Linux.  */
const ELFOSABI_SOLARIS = 6; /* Sun Solaris.  */
const ELFOSABI_AIX = 7; /* IBM AIX.  */
const ELFOSABI_IRIX = 8; /* SGI Irix.  */
const ELFOSABI_FREEBSD = 9; /* FreeBSD.  */
const ELFOSABI_TRU64 = 10;  /* Compaq TRU64 UNIX.  */
const ELFOSABI_MODESTO = 11;  /* Novell Modesto.  */
const ELFOSABI_OPENBSD = 12;  /* OpenBSD.  */
const ELFOSABI_ARM = 97;  /* ARM */
const ELFOSABI_STANDALONE = 255; /* Standalone (embedded) application */

const EI_ABIVERSION = 8;   /* ABI version */

const EI_PAD = 9;   /* Byte index of padding bytes */

/* Legal values for e_type (object file type).  */

const ET_NONE = 0;   /* No file type */
const ET_REL = 1;   /* Relocatable file */
const ET_EXEC = 2;   /* Executable file */
const ET_DYN = 3;   /* Shared object file */
const ET_CORE = 4;   /* Core file */
const ET_NUM = 5;   /* Number of defined types */
const ET_LOOS = 0xfe00;    /* OS-specific range start */
const ET_HIOS = 0xfeff;    /* OS-specific range end */
const ET_LOPROC = 0xff00;    /* Processor-specific range start */
const ET_HIPROC = 0xffff;    /* Processor-specific range end */

/* Legal values for e_machine (architecture).  */

const EM_NONE = 0;           /* No machine */
const EM_M32 = 1;            /* AT&T WE 32100 */
const EM_SPARC = 2;          /* SUN SPARC */
const EM_386 = 3;            /* Intel 80386 */
const EM_68K = 4;            /* Motorola m68k family */
const EM_88K = 5;            /* Motorola m88k family */
const EM_860 = 7;            /* Intel 80860 */
const EM_MIPS = 8;           /* MIPS R3000 big-endian */
const EM_S370 = 9;           /* IBM System/370 */
const EM_MIPS_RS3_LE = 10;   /* MIPS R3000 little-endian */

const EM_PARISC = 15;        /* HPPA */
const EM_VPP500 = 17;        /* Fujitsu VPP500 */
const EM_SPARC32PLUS = 18;   /* Sun's "v8plus" */
const EM_960 = 19;           /* Intel 80960 */
const EM_PPC = 20;           /* PowerPC */
const EM_PPC64 = 21;         /* PowerPC 64-bit */
const EM_S390 = 22;          /* IBM S390 */

const EM_V800 = 36;          /* NEC V800 series */
const EM_FR20 = 37;          /* Fujitsu FR20 */
const EM_RH32 = 38;          /* TRW RH-32 */
const EM_RCE = 39;           /* Motorola RCE */
const EM_ARM = 40;           /* ARM */
const EM_FAKE_ALPHA = 41;    /* Digital Alpha */
const EM_SH = 42;            /* Hitachi SH */
const EM_SPARCV9 = 43;       /* SPARC v9 64-bit */
const EM_TRICORE = 44;       /* Siemens Tricore */
const EM_ARC = 45;           /* Argonaut RISC Core */
const EM_H8_300 = 46;        /* Hitachi H8/300 */
const EM_H8_300H = 47;       /* Hitachi H8/300H */
const EM_H8S = 48;           /* Hitachi H8S */
const EM_H8_500 = 49;        /* Hitachi H8/500 */
const EM_IA_64 = 50;         /* Intel Merced */
const EM_MIPS_X = 51;        /* Stanford MIPS-X */
const EM_COLDFIRE = 52;      /* Motorola Coldfire */
const EM_68HC12 = 53;        /* Motorola M68HC12 */
const EM_MMA = 54;           /* Fujitsu MMA Multimedia Accelerator*/
const EM_PCP = 55;           /* Siemens PCP */
const EM_NCPU = 56;          /* Sony nCPU embeeded RISC */
const EM_NDR1 = 57;          /* Denso NDR1 microprocessor */
const EM_STARCORE = 58;      /* Motorola Start*Core processor */
const EM_ME16 = 59;          /* Toyota ME16 processor */
const EM_ST100 = 60;         /* STMicroelectronic ST100 processor */
const EM_TINYJ = 61;         /* Advanced Logic Corp. Tinyj emb.fam*/
const EM_X86_64 = 62;        /* AMD x86-64 architecture */
const EM_PDSP = 63;          /* Sony DSP Processor */

const EM_FX66 = 66;          /* Siemens FX66 microcontroller */
const EM_ST9PLUS = 67;       /* STMicroelectronics ST9+ 8/16 mc */
const EM_ST7 = 68;           /* STmicroelectronics ST7 8 bit mc */
const EM_68HC16 = 69;        /* Motorola MC68HC16 microcontroller */
const EM_68HC11 = 70;        /* Motorola MC68HC11 microcontroller */
const EM_68HC08 = 71;        /* Motorola MC68HC08 microcontroller */
const EM_68HC05 = 72;        /* Motorola MC68HC05 microcontroller */
const EM_SVX = 73;           /* Silicon Graphics SVx */
const EM_ST19 = 74;          /* STMicroelectronics ST19 8 bit mc */
const EM_VAX = 75;           /* Digital VAX */
const EM_CRIS = 76;          /* Axis Communications 32-bit embedded processor */
const EM_JAVELIN = 77;       /* Infineon Technologies 32-bit embedded processor */
const EM_FIREPATH = 78;      /* Element 14 64-bit DSP Processor */
const EM_ZSP = 79;           /* LSI Logic 16-bit DSP Processor */
const EM_MMIX = 80;          /* Donald Knuth's educational 64-bit processor */
const EM_HUANY = 81;         /* Harvard University machine-independent object files */
const EM_PRISM = 82;         /* SiTera Prism */
const EM_AVR = 83;           /* Atmel AVR 8-bit microcontroller */
const EM_FR30 = 84;          /* Fujitsu FR30 */
const EM_D10V = 85;          /* Mitsubishi D10V */
const EM_D30V = 86;          /* Mitsubishi D30V */
const EM_V850 = 87;          /* NEC v850 */
const EM_M32R = 88;          /* Mitsubishi M32R */
const EM_MN10300 = 89;       /* Matsushita MN10300 */
const EM_MN10200 = 90;       /* Matsushita MN10200 */
const EM_PJ = 91;            /* picoJava */
const EM_OPENRISC = 92;      /* OpenRISC 32-bit embedded processor */
const EM_ARC_A5 = 93;        /* ARC Cores Tangent-A5 */
const EM_XTENSA = 94;        /* Tensilica Xtensa Architecture */
const EM_NUM = 95;

/* If it is necessary to assign new unofficial EM_* values, please
   pick large random numbers (0x8523, 0xa7f2, etc.) to minimize the
   chances of collision with official or non-GNU unofficial values.  */

const EM_ALPHA = 0x9026;

/* Legal values for e_version (version).  */

const EV_NONE = 0;   /* Invalid ELF version */
const EV_CURRENT = 1;   /* Current version */
const EV_NUM = 2;

/* Section header.  */

struct Elf32_Shdr
{
  Elf32_Word sh_name;    /* Section name (string tbl index) */
  Elf32_Word sh_type;    /* Section type */
  Elf32_Word sh_flags;   /* Section flags */
  Elf32_Addr sh_addr;    /* Section virtual addr at execution */
  Elf32_Off sh_offset;    /* Section file offset */
  Elf32_Word sh_size;    /* Section size in bytes */
  Elf32_Word sh_link;    /* Link to another section */
  Elf32_Word sh_info;    /* Additional section information */
  Elf32_Word sh_addralign;   /* Section alignment */
  Elf32_Word sh_entsize;   /* Entry size if section holds table */
}

struct Elf64_Shdr
{
  Elf64_Word sh_name;    /* Section name (string tbl index) */
  Elf64_Word sh_type;    /* Section type */
  Elf64_Xword sh_flags;   /* Section flags */
  Elf64_Addr sh_addr;    /* Section virtual addr at execution */
  Elf64_Off sh_offset;    /* Section file offset */
  Elf64_Xword sh_size;    /* Section size in bytes */
  Elf64_Word sh_link;    /* Link to another section */
  Elf64_Word sh_info;    /* Additional section information */
  Elf64_Xword sh_addralign;   /* Section alignment */
  Elf64_Xword sh_entsize;   /* Entry size if section holds table */
}

/* Special section indices.  */

const SHN_UNDEF = 0;   /* Undefined section */
const SHN_LORESERVE = 0xff00;    /* Start of reserved indices */
const SHN_LOPROC = 0xff00;    /* Start of processor-specific */
const SHN_BEFORE = 0xff00;    /* Order section before all others
                                 (Solaris).  */
const SHN_AFTER = 0xff01;    /* Order section after all others
                                (Solaris).  */
const SHN_HIPROC = 0xff1f;    /* End of processor-specific */
const SHN_LOOS = 0xff20;    /* Start of OS-specific */
const SHN_HIOS = 0xff3f;    /* End of OS-specific */
const SHN_ABS = 0xfff1;    /* Associated symbol is absolute */
const SHN_COMMON = 0xfff2;    /* Associated symbol is common */
const SHN_XINDEX = 0xffff;    /* Index is in extra table.  */
const SHN_HIRESERVE = 0xffff;    /* End of reserved indices */

/* Legal values for sh_type (section type).  */

const SHT_NULL = 0;   /* Section header table entry unused */
const SHT_PROGBITS = 1;   /* Program data */
const SHT_SYMTAB = 2;   /* Symbol table */
const SHT_STRTAB = 3;   /* String table */
const SHT_RELA = 4;   /* Relocation entries with addends */
const SHT_HASH = 5;   /* Symbol hash table */
const SHT_DYNAMIC = 6;   /* Dynamic linking information */
const SHT_NOTE = 7;   /* Notes */
const SHT_NOBITS = 8;   /* Program space with no data (bss) */
const SHT_REL = 9;   /* Relocation entries, no addends */
const SHT_SHLIB = 10;    /* Reserved */
const SHT_DYNSYM = 11;    /* Dynamic linker symbol table */
const SHT_INIT_ARRAY = 14;    /* Array of constructors */
const SHT_FINI_ARRAY = 15;    /* Array of destructors */
const SHT_PREINIT_ARRAY = 16;    /* Array of pre-constructors */
const SHT_GROUP = 17;    /* Section group */
const SHT_SYMTAB_SHNDX = 18;    /* Extended section indeces */
const SHT_NUM = 19;    /* Number of defined types.  */
const SHT_LOOS = 0x60000000;  /* Start OS-specific.  */
const SHT_GNU_HASH = 0x6ffffff6;  /* GNU-style hash table.  */
const SHT_GNU_LIBLIST = 0x6ffffff7;  /* Prelink library list */
const SHT_CHECKSUM = 0x6ffffff8;  /* Checksum for DSO content.  */
const SHT_LOSUNW = 0x6ffffffa;  /* Sun-specific low bound.  */
const SHT_SUNW_move = 0x6ffffffa;
const SHT_SUNW_COMDAT = 0x6ffffffb;
const SHT_SUNW_syminfo = 0x6ffffffc;
const SHT_GNU_verdef = 0x6ffffffd;  /* Version definition section.  */
const SHT_GNU_verneed = 0x6ffffffe;  /* Version needs section.  */
const SHT_GNU_versym = 0x6fffffff;  /* Version symbol table.  */
const SHT_HISUNW = 0x6fffffff;  /* Sun-specific high bound.  */
const SHT_HIOS = 0x6fffffff;  /* End OS-specific type */
const SHT_LOPROC = 0x70000000;  /* Start of processor-specific */
const SHT_HIPROC = 0x7fffffff;  /* End of processor-specific */
const SHT_LOUSER = 0x80000000;  /* Start of application-specific */
const SHT_HIUSER = 0x8fffffff;  /* End of application-specific */

/* Legal values for sh_flags (section flags).  */

const SHF_WRITE = (1 << 0); /* Writable */
const SHF_ALLOC = (1 << 1); /* Occupies memory during execution */
const SHF_EXECINSTR = (1 << 2); /* Executable */
const SHF_MERGE = (1 << 4); /* Might be merged */
const SHF_STRINGS = (1 << 5); /* Contains nul-terminated strings */
const SHF_INFO_LINK = (1 << 6); /* `sh_info' contains SHT index */
const SHF_LINK_ORDER = (1 << 7); /* Preserve order after combining */
const SHF_OS_NONCONFORMING = (1 << 8); /* Non-standard OS specific handling
                                          required */
const SHF_GROUP = (1 << 9); /* Section is member of a group.  */
const SHF_TLS = (1 << 10);  /* Section hold thread-local data.  */
const SHF_MASKOS = 0x0ff00000; /* OS-specific.  */
const SHF_MASKPROC = 0xf0000000; /* Processor-specific */
const SHF_ORDERED = (1 << 30);  /* Special ordering requirement (Solaris).  */
const SHF_EXCLUDE = (1 << 31);  /* Section is excluded unless referenced or allocated (Solaris).*/

/* Section group handling.  */
const GRP_COMDAT = 0x1;   /* Mark group as COMDAT.  */

/* Symbol table entry.  */

struct Elf32_Sym
{
  align (1) : Elf32_Word st_name;    /* Symbol name (string tbl index) */
  Elf32_Addr st_value;   /* Symbol value */
  Elf32_Word st_size;    /* Symbol size */
  ubyte st_info;    /* Symbol type and binding */
  ubyte st_other;   /* Symbol visibility */
  Elf32_Half st_shndx;   /* Section index */
}

struct Elf64_Sym
{
  align (1) : Elf64_Word st_name;    /* Symbol name (string tbl index) */
  ubyte st_info;    /* Symbol type and binding */
  ubyte st_other;   /* Symbol visibility */
  Elf64_Section st_shndx;   /* Section index */
  Elf64_Addr st_value;   /* Symbol value */
  Elf64_Xword st_size;    /* Symbol size */
}

/* The syminfo section if available contains additional information about
   every dynamic symbol.  */

struct Elf32_Syminfo
{
  Elf32_Half si_boundto;    /* Direct bindings, symbol bound to */
  Elf32_Half si_flags;      /* Per symbol flags */
}

struct Elf64_Syminfo
{
  Elf64_Half si_boundto;    /* Direct bindings, symbol bound to */
  Elf64_Half si_flags;      /* Per symbol flags */
}

/* Possible values for si_boundto.  */
const SYMINFO_BT_SELF = 0xffff;  /* Symbol bound to self */
const SYMINFO_BT_PARENT = 0xfffe;  /* Symbol bound to parent */
const SYMINFO_BT_LOWRESERVE = 0xff00;  /* Beginning of reserved entries */

/* Possible bitmasks for si_flags.  */
const SYMINFO_FLG_DIRECT = 0x0001;  /* Direct bound symbol */
const SYMINFO_FLG_PASSTHRU = 0x0002;  /* Pass-thru symbol for translator */
const SYMINFO_FLG_COPY = 0x0004;  /* Symbol is a copy-reloc */
const SYMINFO_FLG_LAZYLOAD = 0x0008;  /* Symbol bound to object to be lazy
                                         loaded */
/* Syminfo version values.  */
const SYMINFO_NONE = 0;
const SYMINFO_CURRENT = 1;
const SYMINFO_NUM = 2;

/+
   /* How to extract and insert information held in the st_info field.  */

   int ELF32_ST_BIND(val)  (((ubyte) (val)) >> 4)
   const ELF32_ST_TYPE(val)  ((val) & 0xf)
   const ELF32_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))

   /* Both Elf32_Sym and Elf64_Sym use the same one-byte st_info field.  */
   const ELF64_ST_BIND(val) = ELF32_ST_BIND; (val)
   const ELF64_ST_TYPE(val) = ELF32_ST_TYPE; (val)
   const ELF64_ST_INFO(bind, = type); ELF32_ST_INFO ((bind), (type))

   /* Legal values for ST_BIND subfield of st_info (symbol binding).  */
 +/

const STB_LOCAL = 0;   /* Local symbol */
const STB_GLOBAL = 1;   /* Global symbol */
const STB_WEAK = 2;   /* Weak symbol */
const STB_NUM = 3;   /* Number of defined types.  */
const STB_LOOS = 10;    /* Start of OS-specific */
const STB_HIOS = 12;    /* End of OS-specific */
const STB_LOPROC = 13;    /* Start of processor-specific */
const STB_HIPROC = 15;    /* End of processor-specific */

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

const STT_NOTYPE = 0;   /* Symbol type is unspecified */
const STT_OBJECT = 1;   /* Symbol is a data object */
const STT_FUNC = 2;   /* Symbol is a code object */
const STT_SECTION = 3;   /* Symbol associated with a section */
const STT_FILE = 4;   /* Symbol's name is file name */
const STT_COMMON = 5;   /* Symbol is a common data object */
const STT_TLS = 6;   /* Symbol is thread-local data object*/
const STT_NUM = 7;   /* Number of defined types.  */
const STT_LOOS = 10;    /* Start of OS-specific */
const STT_HIOS = 12;    /* End of OS-specific */
const STT_LOPROC = 13;    /* Start of processor-specific */
const STT_HIPROC = 15;    /* End of processor-specific */

/* Symbol table indices are found in the hash buckets and chain table
   of a symbol hash table section.  This special index value indicates
   the end of a chain, meaning no further symbols are found in that bucket.  */

const STN_UNDEF = 0;   /* End of a chain.  */

/* How to extract and insert information held in the st_other field.  */

// const ELF32_ST_VISIBILITY(o) = ((o); & 0x03)

/* For ELF64 the definitions are the same.  */
// const ELF64_ST_VISIBILITY(o) = ELF32_ST_VISIBILITY; (o)

/* Symbol visibility specification encoded in the st_other field.  */
const STV_DEFAULT = 0;   /* Default symbol visibility rules */
const STV_INTERNAL = 1;   /* Processor specific hidden class */
const STV_HIDDEN = 2;   /* Sym unavailable in other modules */
const STV_PROTECTED = 3;   /* Not preemptible, not exported */

/* Relocation table entry without addend (in section of type SHT_REL).  */

struct Elf32_Rel
{
  Elf32_Addr r_offset;   /* Address */
  Elf32_Word r_info;     /* Relocation type and symbol index */
}

/* I have seen two different definitions of the Elf64_Rel and
   Elf64_Rela structures, so we'll leave them out until Novell (or
   whoever) gets their act together.  */
/* The following, at least, is used on Sparc v9, MIPS, and Alpha.  */

struct Elf64_Rel
{
  Elf64_Addr r_offset;   /* Address */
  Elf64_Xword r_info;     /* Relocation type and symbol index */
}

/* Relocation table entry with addend (in section of type SHT_RELA).  */

struct Elf32_Rela
{
  Elf32_Addr r_offset;   /* Address */
  Elf32_Word r_info;     /* Relocation type and symbol index */
  Elf32_Sword r_addend;   /* Addend */
}

struct Elf64_Rela
{
  Elf64_Addr r_offset;   /* Address */
  Elf64_Xword r_info;     /* Relocation type and symbol index */
  Elf64_Sxword r_addend;   /* Addend */
}

/* How to extract and insert information held in the r_info field.  */

/+
   const ELF32_R_SYM(val) = ((val); >> 8)
   const ELF32_R_TYPE(val) = ((val); & 0xff)
   const ELF32_R_INFO(sym, = type);   (((sym) << 8) + ((type) & 0xff))

   const ELF64_R_SYM(i) = ((i); >> 32)
   const ELF64_R_TYPE(i) = ((i); & 0xffffffff)
   const ELF64_R_INFO(sym,type) = ((((Elf64_Xword); (sym)) << 32) + (type))
 +/

/* Program segment header.  */

struct ProgramHeader
{
  Elf32_Word p_type;     /* Segment type */
  Elf32_Off p_offset;   /* Segment file offset */
  Elf32_Addr p_vaddr;    /* Segment virtual address */
  Elf32_Addr p_paddr;    /* Segment physical address */
  Elf32_Word p_filesz;   /* Segment size in file */
  Elf32_Word p_memsz;    /* Segment size in memory */
  Elf32_Word p_flags;    /* Segment flags */
  Elf32_Word p_align;    /* Segment alignment */
}

struct Elf64_Phdr
{
  Elf64_Word p_type;     /* Segment type */
  Elf64_Word p_flags;    /* Segment flags */
  Elf64_Off p_offset;   /* Segment file offset */
  Elf64_Addr p_vaddr;    /* Segment virtual address */
  Elf64_Addr p_paddr;    /* Segment physical address */
  Elf64_Xword p_filesz;   /* Segment size in file */
  Elf64_Xword p_memsz;    /* Segment size in memory */
  Elf64_Xword p_align;    /* Segment alignment */
}

/* Legal values for p_type (segment type).  */

const PT_NULL = 0;   /* Program header table entry unused */
const PT_LOAD = 1;   /* Loadable program segment */
const PT_DYNAMIC = 2;   /* Dynamic linking information */
const PT_INTERP = 3;   /* Program interpreter */
const PT_NOTE = 4;   /* Auxiliary information */
const PT_SHLIB = 5;   /* Reserved */
const PT_PHDR = 6;   /* Entry for header table itself */
const PT_TLS = 7;   /* Thread-local storage segment */
const PT_NUM = 8;   /* Number of defined types */
const PT_LOOS = 0x60000000;  /* Start of OS-specific */
const PT_GNU_EH_FRAME = 0x6474e550;  /* GCC .eh_frame_hdr segment */
const PT_GNU_STACK = 0x6474e551;  /* Indicates stack executability */
const PT_GNU_RELRO = 0x6474e552;  /* Read-only after relocation */
const PT_LOSUNW = 0x6ffffffa;
const PT_SUNWBSS = 0x6ffffffa;  /* Sun Specific segment */
const PT_SUNWSTACK = 0x6ffffffb;  /* Stack segment */
const PT_HISUNW = 0x6fffffff;
const PT_HIOS = 0x6fffffff;  /* End of OS-specific */
const PT_LOPROC = 0x70000000;  /* Start of processor-specific */
const PT_HIPROC = 0x7fffffff;  /* End of processor-specific */

/* Legal values for p_flags (segment flags).  */

const PF_X = (1 << 0);  /* Segment is executable */
const PF_W = (1 << 1);  /* Segment is writable */
const PF_R = (1 << 2);  /* Segment is readable */
const PF_MASKOS = 0x0ff00000;  /* OS-specific */
const PF_MASKPROC = 0xf0000000;  /* Processor-specific */

/* Legal values for note segment descriptor types for core files. */

const NT_PRSTATUS = 1;   /* Contains copy of prstatus struct */
const NT_FPREGSET = 2;   /* Contains copy of fpregset struct */
const NT_PRPSINFO = 3;   /* Contains copy of prpsinfo struct */
const NT_PRXREG = 4;   /* Contains copy of prxregset struct */
const NT_TASKSTRUCT = 4;   /* Contains copy of task structure */
const NT_PLATFORM = 5;   /* String from sysinfo(SI_PLATFORM) */
const NT_AUXV = 6;   /* Contains copy of auxv array */
const NT_GWINDOWS = 7;   /* Contains copy of gwindows struct */
const NT_ASRS = 8;   /* Contains copy of asrset struct */
const NT_PSTATUS = 10;    /* Contains copy of pstatus struct */
const NT_PSINFO = 13;    /* Contains copy of psinfo struct */
const NT_PRCRED = 14;    /* Contains copy of prcred struct */
const NT_UTSNAME = 15;    /* Contains copy of utsname struct */
const NT_LWPSTATUS = 16;    /* Contains copy of lwpstatus struct */
const NT_LWPSINFO = 17;    /* Contains copy of lwpinfo struct */
const NT_PRFPXREG = 20;    /* Contains copy of fprxregset struct*/
const NT_PRXFPREG = 0x46e62b7f;  /* Contains copy of user_fxsr_struct*/

/* Legal values for the note segment descriptor types for object files.  */

const NT_VERSION = 1;   /* Contains a version string.  */

/* Dynamic section entry.  */

struct Elf32_Dyn
{
  Elf32_Sword d_tag;      /* Dynamic entry type */
  union union_t
  {
    Elf32_Word d_val;     /* Integer value */
    Elf32_Addr d_ptr;     /* Address value */
  };
  union_t d_un;
}

struct Elf64_Dyn
{
  Elf64_Sxword d_tag;      /* Dynamic entry type */
  union union_t
  {
    Elf64_Xword d_val;    /* Integer value */
    Elf64_Addr d_ptr;     /* Address value */
  };
  union_t d_un;
}

/* Legal values for d_tag (dynamic entry type).  */

const DT_NULL = 0;   /* Marks end of dynamic section */
const DT_NEEDED = 1;   /* Name of needed library */
const DT_PLTRELSZ = 2;   /* Size in bytes of PLT relocs */
const DT_PLTGOT = 3;   /* Processor defined value */
const DT_HASH = 4;   /* Address of symbol hash table */
const DT_STRTAB = 5;   /* Address of string table */
const DT_SYMTAB = 6;   /* Address of symbol table */
const DT_RELA = 7;   /* Address of Rela relocs */
const DT_RELASZ = 8;   /* Total size of Rela relocs */
const DT_RELAENT = 9;   /* Size of one Rela reloc */
const DT_STRSZ = 10;    /* Size of string table */
const DT_SYMENT = 11;    /* Size of one symbol table entry */
const DT_INIT = 12;    /* Address of init function */
const DT_FINI = 13;    /* Address of termination function */
const DT_SONAME = 14;    /* Name of shared object */
const DT_RPATH = 15;    /* Library search path (deprecated) */
const DT_SYMBOLIC = 16;    /* Start symbol search here */
const DT_REL = 17;    /* Address of Rel relocs */
const DT_RELSZ = 18;    /* Total size of Rel relocs */
const DT_RELENT = 19;    /* Size of one Rel reloc */
const DT_PLTREL = 20;    /* Type of reloc in PLT */
const DT_DEBUG = 21;    /* For debugging; unspecified */
const DT_TEXTREL = 22;    /* Reloc might modify .text */
const DT_JMPREL = 23;    /* Address of PLT relocs */
const DT_BIND_NOW = 24;    /* Process relocations of object */
const DT_INIT_ARRAY = 25;    /* Array with addresses of init fct */
const DT_FINI_ARRAY = 26;    /* Array with addresses of fini fct */
const DT_INIT_ARRAYSZ = 27;    /* Size in bytes of DT_INIT_ARRAY */
const DT_FINI_ARRAYSZ = 28;    /* Size in bytes of DT_FINI_ARRAY */
const DT_RUNPATH = 29;    /* Library search path */
const DT_FLAGS = 30;    /* Flags for the object being loaded */
const DT_ENCODING = 32;    /* Start of encoded range */
const DT_PREINIT_ARRAY = 32;   /* Array with addresses of preinit fct*/
const DT_PREINIT_ARRAYSZ = 33;   /* size in bytes of DT_PREINIT_ARRAY */
const DT_NUM = 34;    /* Number used */
const DT_LOOS = 0x6000000d;  /* Start of OS-specific */
const DT_HIOS = 0x6ffff000;  /* End of OS-specific */
const DT_LOPROC = 0x70000000;  /* Start of processor-specific */
const DT_HIPROC = 0x7fffffff;  /* End of processor-specific */
const DT_MIPS_NUM = 0x32;
const DT_PROCNUM = DT_MIPS_NUM; /* Most used by any processor */

/* DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
   Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
   approach.  */
const DT_VALRNGLO = 0x6ffffd00;
const DT_GNU_PRELINKED = 0x6ffffdf5; /* Prelinking timestamp */
const DT_GNU_CONFLICTSZ = 0x6ffffdf6;  /* Size of conflict section */
const DT_GNU_LIBLISTSZ = 0x6ffffdf7; /* Size of library list */
const DT_CHECKSUM = 0x6ffffdf8;
const DT_PLTPADSZ = 0x6ffffdf9;
const DT_MOVEENT = 0x6ffffdfa;
const DT_MOVESZ = 0x6ffffdfb;
const DT_FEATURE_1 = 0x6ffffdfc;  /* Feature selection (DTF_*).  */
const DT_POSFLAG_1 = 0x6ffffdfd;  /* Flags for DT_* entries, effecting
                                     the following DT_* entry.  */
const DT_SYMINSZ = 0x6ffffdfe;  /* Size of syminfo table (in bytes) */
const DT_SYMINENT = 0x6ffffdff;  /* Entry size of syminfo */
const DT_VALRNGHI = 0x6ffffdff;
// const DT_VALTAGIDX(tag) = (DT_VALRNGHI; - (tag)) /* Reverse order! */
const DT_VALNUM = 12;

/* DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
   Dyn.d_un.d_ptr field of the Elf*_Dyn structure.

   If any adjustment is made to the ELF object after it has been
   built these entries will need to be adjusted.  */
const DT_ADDRRNGLO = 0x6ffffe00;
const DT_GNU_HASH = 0x6ffffef5;  /* GNU-style hash table.  */
const DT_TLSDESC_PLT = 0x6ffffef6;
const DT_TLSDESC_GOT = 0x6ffffef7;
const DT_GNU_CONFLICT = 0x6ffffef8;  /* Start of conflict section */
const DT_GNU_LIBLIST = 0x6ffffef9;  /* Library list */
const DT_CONFIG = 0x6ffffefa;  /* Configuration information.  */
const DT_DEPAUDIT = 0x6ffffefb;  /* Dependency auditing.  */
const DT_AUDIT = 0x6ffffefc;  /* Object auditing.  */
const DT_PLTPAD = 0x6ffffefd;  /* PLT padding.  */
const DT_MOVETAB = 0x6ffffefe;  /* Move table.  */
const DT_SYMINFO = 0x6ffffeff;  /* Syminfo table.  */
const DT_ADDRRNGHI = 0x6ffffeff;
// const DT_ADDRTAGIDX(tag) = (DT_ADDRRNGHI; - (tag))  /* Reverse order! */
const DT_ADDRNUM = 11;

/* The versioning entry types.  The next are defined as part of the
   GNU extension.  */
const DT_VERSYM = 0x6ffffff0;

const DT_RELACOUNT = 0x6ffffff9;
const DT_RELCOUNT = 0x6ffffffa;

/* These were chosen by Sun.  */
const DT_FLAGS_1 = 0x6ffffffb;  /* State flags, see DF_1_* below.  */
const DT_VERDEF = 0x6ffffffc;  /* Address of version definition
                                  table */
const DT_VERDEFNUM = 0x6ffffffd;  /* Number of version definitions */
const DT_VERNEED = 0x6ffffffe;  /* Address of table with needed
                                   versions */
const DT_VERNEEDNUM = 0x6fffffff;  /* Number of needed versions */
// const DT_VERSIONTAGIDX(tag) = (DT_VERNEEDNUM; - (tag)) /* Reverse order! */
const DT_VERSIONTAGNUM = 16;

/* Sun added these machine-independent extensions in the "processor-specific"
   range.  Be compatible.  */
const DT_AUXILIARY = 0x7ffffffd;      /* Shared object to load before self */
const DT_FILTER = 0x7fffffff;      /* Shared object to get values from */
// const DT_EXTRATAGIDX(tag) = ((Elf32_Word)-((Elf32_Sword); (tag) <<1>>1)-1)
const DT_EXTRANUM = 3;

/* Values of `d_un.d_val' in the DT_FLAGS entry.  */
const DF_ORIGIN = 0x00000001;  /* Object may use DF_ORIGIN */
const DF_SYMBOLIC = 0x00000002;  /* Symbol resolutions starts here */
const DF_TEXTREL = 0x00000004;  /* Object contains text relocations */
const DF_BIND_NOW = 0x00000008;  /* No lazy binding for this object */
const DF_STATIC_TLS = 0x00000010;  /* Module uses the static TLS model */

/* State flags selectable in the `d_un.d_val' element of the DT_FLAGS_1
   entry in the dynamic section.  */
const DF_1_NOW = 0x00000001;  /* Set RTLD_NOW for this object.  */
const DF_1_GLOBAL = 0x00000002;  /* Set RTLD_GLOBAL for this object.  */
const DF_1_GROUP = 0x00000004;  /* Set RTLD_GROUP for this object.  */
const DF_1_NODELETE = 0x00000008;  /* Set RTLD_NODELETE for this object.*/
const DF_1_LOADFLTR = 0x00000010;  /* Trigger filtee loading at runtime.*/
const DF_1_INITFIRST = 0x00000020;  /* Set RTLD_INITFIRST for this object*/
const DF_1_NOOPEN = 0x00000040;  /* Set RTLD_NOOPEN for this object.  */
const DF_1_ORIGIN = 0x00000080;  /* $ORIGIN must be handled.  */
const DF_1_DIRECT = 0x00000100;  /* Direct binding enabled.  */
const DF_1_TRANS = 0x00000200;
const DF_1_INTERPOSE = 0x00000400;  /* Object is used to interpose.  */
const DF_1_NODEFLIB = 0x00000800;  /* Ignore default lib search path.  */
const DF_1_NODUMP = 0x00001000;  /* Object can't be dldump'ed.  */
const DF_1_CONFALT = 0x00002000;  /* Configuration alternative created.*/
const DF_1_ENDFILTEE = 0x00004000;  /* Filtee terminates filters search. */
const DF_1_DISPRELDNE = 0x00008000;  /* Disp reloc applied at build time. */
const DF_1_DISPRELPND = 0x00010000;  /* Disp reloc applied at run-time.  */

/* Flags for the feature selection in DT_FEATURE_1.  */
const DTF_1_PARINIT = 0x00000001;
const DTF_1_CONFEXP = 0x00000002;

/* Flags in the DT_POSFLAG_1 entry effecting only the next DT_* entry.  */
const DF_P1_LAZYLOAD = 0x00000001;  /* Lazyload following object.  */
const DF_P1_GROUPPERM = 0x00000002;  /* Symbols from next object are not
                                        generally available.  */

/* Version definition sections.  */

struct Elf32_Verdef
{
  Elf32_Half vd_version;   /* Version revision */
  Elf32_Half vd_flags;   /* Version information */
  Elf32_Half vd_ndx;     /* Version Index */
  Elf32_Half vd_cnt;     /* Number of associated aux entries */
  Elf32_Word vd_hash;    /* Version name hash value */
  Elf32_Word vd_aux;     /* Offset in bytes to verdaux array */
  Elf32_Word vd_next;    /* Offset in bytes to next verdef
                            entry */
}

struct Elf64_Verdef
{
  Elf64_Half vd_version;   /* Version revision */
  Elf64_Half vd_flags;   /* Version information */
  Elf64_Half vd_ndx;     /* Version Index */
  Elf64_Half vd_cnt;     /* Number of associated aux entries */
  Elf64_Word vd_hash;    /* Version name hash value */
  Elf64_Word vd_aux;     /* Offset in bytes to verdaux array */
  Elf64_Word vd_next;    /* Offset in bytes to next verdef
                            entry */
}

/* Legal values for vd_version (version revision).  */
const VER_DEF_NONE = 0;   /* No version */
const VER_DEF_CURRENT = 1;   /* Current version */
const VER_DEF_NUM = 2;   /* Given version number */

/* Legal values for vd_flags (version information flags).  */
const VER_FLG_BASE = 0x1;   /* Version definition of file itself */
const VER_FLG_WEAK = 0x2;   /* Weak version identifier */

/* Versym symbol index values.  */
const VER_NDX_LOCAL = 0; /* Symbol is local.  */
const VER_NDX_GLOBAL = 1; /* Symbol is global.  */
const VER_NDX_LORESERVE = 0xff00;  /* Beginning of reserved entries.  */
const VER_NDX_ELIMINATE = 0xff01;  /* Symbol is to be eliminated.  */

/* Auxialiary version information.  */

struct Elf32_Verdaux
{
  Elf32_Word vda_name;   /* Version or dependency names */
  Elf32_Word vda_next;   /* Offset in bytes to next verdaux
                            entry */
}

struct Elf64_Verdaux
{
  Elf64_Word vda_name;   /* Version or dependency names */
  Elf64_Word vda_next;   /* Offset in bytes to next verdaux
                            entry */
}

/* Version dependency section.  */

struct Elf32_Verneed
{
  Elf32_Half vn_version;   /* Version of structure */
  Elf32_Half vn_cnt;     /* Number of associated aux entries */
  Elf32_Word vn_file;    /* Offset of filename for this
                            dependency */
  Elf32_Word vn_aux;     /* Offset in bytes to vernaux array */
  Elf32_Word vn_next;    /* Offset in bytes to next verneed
                            entry */
}

struct Elf64_Verneed
{
  Elf64_Half vn_version;   /* Version of structure */
  Elf64_Half vn_cnt;     /* Number of associated aux entries */
  Elf64_Word vn_file;    /* Offset of filename for this
                            dependency */
  Elf64_Word vn_aux;     /* Offset in bytes to vernaux array */
  Elf64_Word vn_next;    /* Offset in bytes to next verneed
                            entry */
}

/* Legal values for vn_version (version revision).  */
const VER_NEED_NONE = 0;    /* No version */
const VER_NEED_CURRENT = 1;    /* Current version */
const VER_NEED_NUM = 2;    /* Given version number */

/* Auxiliary needed version information.  */

struct Elf32_Vernaux
{
  Elf32_Word vna_hash;   /* Hash value of dependency name */
  Elf32_Half vna_flags;    /* Dependency specific information */
  Elf32_Half vna_other;    /* Unused */
  Elf32_Word vna_name;   /* Dependency name string offset */
  Elf32_Word vna_next;   /* Offset in bytes to next vernaux
                            entry */
}

struct Elf64_Vernaux
{
  Elf64_Word vna_hash;   /* Hash value of dependency name */
  Elf64_Half vna_flags;    /* Dependency specific information */
  Elf64_Half vna_other;    /* Unused */
  Elf64_Word vna_name;   /* Dependency name string offset */
  Elf64_Word vna_next;   /* Offset in bytes to next vernaux
                            entry */
}

/* Legal values for vna_flags.  */
// const VER_FLG_WEAK = 0x2;   /* Weak version identifier */

/* Auxiliary vector.  */

/* This vector is normally only used by the program interpreter.  The
   usual definition in an ABI supplement uses the name auxv_t.  The
   vector is not usually defined in a standard <elf.h> file, but it
   can't hurt.  We rename it to avoid conflicts.  The sizes of these
   types are an arrangement between the exec server and the program
   interpreter, so we don't fully specify them here.  */

struct Elf32_auxv_t
{
  uint32_t a_type;    /* Entry type */
  union union_t
  {
    uint32_t a_val;   /* Integer value */
    /* We use to have pointer elements added here.  We cannot do that,
       though, since it does not work when using 32-bit definitions
       on 64-bit platforms and vice versa.  */
  };
  union_t a_un;
}

struct Elf64_auxv_t
{
  uint64_t a_type;    /* Entry type */
  union union_t
  {
    uint64_t a_val;   /* Integer value */
    /* We use to have pointer elements added here.  We cannot do that,
       though, since it does not work when using 32-bit definitions
       on 64-bit platforms and vice versa.  */
  };
  union_t a_un;
}

/* Legal values for a_type (entry type).  */

const AT_NULL = 0;   /* End of vector */
const AT_IGNORE = 1;   /* Entry should be ignored */
const AT_EXECFD = 2;   /* File descriptor of program */
const AT_PHDR = 3;   /* Program headers for program */
const AT_PHENT = 4;   /* Size of program header entry */
const AT_PHNUM = 5;   /* Number of program headers */
const AT_PAGESZ = 6;   /* System page size */
const AT_BASE = 7;   /* Base address of interpreter */
const AT_FLAGS = 8;   /* Flags */
const AT_ENTRY = 9;   /* Entry point of program */
const AT_NOTELF = 10;    /* Program is not ELF */
const AT_UID = 11;    /* Real uid */
const AT_EUID = 12;    /* Effective uid */
const AT_GID = 13;    /* Real gid */
const AT_EGID = 14;    /* Effective gid */
const AT_CLKTCK = 17;    /* Frequency of times() */

/* Some more special a_type values describing the hardware.  */
const AT_PLATFORM = 15;    /* String identifying platform.  */
const AT_HWCAP = 16;    /* Machine dependent hints about
                           processor capabilities.  */

/* This entry gives some information about the FPU initialization
   performed by the kernel.  */
const AT_FPUCW = 18;    /* Used FPU control word.  */

/* Cache block sizes.  */
const AT_DCACHEBSIZE = 19;    /* Data cache block size.  */
const AT_ICACHEBSIZE = 20;    /* Instruction cache block size.  */
const AT_UCACHEBSIZE = 21;    /* Unified cache block size.  */

/* A special ignored value for PPC, used by the kernel to control the
   interpretation of the AUXV. Must be > 16.  */
const AT_IGNOREPPC = 22;    /* Entry should be ignored.  */

const AT_SECURE = 23;    /* Boolean, was exec setuid-like?  */

/* Pointer to the global system page used for system calls and other
   nice things.  */
const AT_SYSINFO = 32;
const AT_SYSINFO_EHDR = 33;

/* Shapes of the caches.  Bits 0-3 contains associativity; bits 4-7 contains
   log2 of line size; mask those to get cache size.  */
const AT_L1I_CACHESHAPE = 34;
const AT_L1D_CACHESHAPE = 35;
const AT_L2_CACHESHAPE = 36;
const AT_L3_CACHESHAPE = 37;

/* Note section contents.  Each entry in the note section begins with
   a header of a fixed form.  */

struct Elf32_Nhdr
{
  Elf32_Word n_namesz;      /* Length of the note's name.  */
  Elf32_Word n_descsz;      /* Length of the note's descriptor.  */
  Elf32_Word n_type;      /* Type of the note.  */
}

struct Elf64_Nhdr
{
  Elf64_Word n_namesz;      /* Length of the note's name.  */
  Elf64_Word n_descsz;      /* Length of the note's descriptor.  */
  Elf64_Word n_type;      /* Type of the note.  */
}

/* Known names of notes.  */

/* Solaris entries in the note section have this name.  */
const ELF_NOTE_SOLARIS = "SUNW; Solaris";

/* Note entries for GNU systems have this name.  */
const ELF_NOTE_GNU = "GNU";

/* Defined types of notes for Solaris.  */

/* Value of descriptor (one word) is desired pagesize for the binary.  */
const ELF_NOTE_PAGESIZE_HINT = 1;

/* Defined note types for GNU systems.  */

/* ABI information.  The descriptor consists of words:
   word 0: OS descriptor
   word 1: major version of the ABI
   word 2: minor version of the ABI
   word 3: subminor version of the ABI
 */
const ELF_NOTE_ABI = 1;

/* Known OSes.  These value can appear in word 0 of an ELF_NOTE_ABI
   note section entry.  */
const ELF_NOTE_OS_LINUX = 0;
const ELF_NOTE_OS_GNU = 1;
const ELF_NOTE_OS_SOLARIS2 = 2;
const ELF_NOTE_OS_FREEBSD = 3;

/* Move records.  */
struct Elf32_Move
{
  Elf32_Xword m_value;    /* Symbol value.  */
  Elf32_Word m_info;    /* Size and index.  */
  Elf32_Word m_poffset;   /* Symbol offset.  */
  Elf32_Half m_repeat;    /* Repeat count.  */
  Elf32_Half m_stride;    /* Stride info.  */
}

struct Elf64_Move
{
  Elf64_Xword m_value;    /* Symbol value.  */
  Elf64_Xword m_info;   /* Size and index.  */
  Elf64_Xword m_poffset;  /* Symbol offset.  */
  Elf64_Half m_repeat;    /* Repeat count.  */
  Elf64_Half m_stride;    /* Stride info.  */
}

/+
   /* Macro to construct move records.  */
   const ELF32_M_SYM(info) = ((info); >> 8)
   const ELF32_M_SIZE(info) = ((ubyte); (info))
   const ELF32_M_INFO(sym, = size); (((sym) << 8) + (ubyte) (size))

   const ELF64_M_SYM(info) = ELF32_M_SYM; (info)
   const ELF64_M_SIZE(info) = ELF32_M_SIZE; (info)
   const ELF64_M_INFO(sym, = size); ELF32_M_INFO (sym, size)
 +/

/* Motorola 68k specific definitions.  */

/* Values for Elf32_Ehdr.e_flags.  */
const EF_CPU32 = 0x00810000;

/* m68k relocs.  */

const R_68K_NONE = 0;   /* No reloc */
const R_68K_32 = 1;   /* Direct 32 bit  */
const R_68K_16 = 2;   /* Direct 16 bit  */
const R_68K_8 = 3;   /* Direct 8 bit  */
const R_68K_PC32 = 4;   /* PC relative 32 bit */
const R_68K_PC16 = 5;   /* PC relative 16 bit */
const R_68K_PC8 = 6;   /* PC relative 8 bit */
const R_68K_GOT32 = 7;   /* 32 bit PC relative GOT entry */
const R_68K_GOT16 = 8;   /* 16 bit PC relative GOT entry */
const R_68K_GOT8 = 9;   /* 8 bit PC relative GOT entry */
const R_68K_GOT32O = 10;    /* 32 bit GOT offset */
const R_68K_GOT16O = 11;    /* 16 bit GOT offset */
const R_68K_GOT8O = 12;    /* 8 bit GOT offset */
const R_68K_PLT32 = 13;    /* 32 bit PC relative PLT address */
const R_68K_PLT16 = 14;    /* 16 bit PC relative PLT address */
const R_68K_PLT8 = 15;    /* 8 bit PC relative PLT address */
const R_68K_PLT32O = 16;    /* 32 bit PLT offset */
const R_68K_PLT16O = 17;    /* 16 bit PLT offset */
const R_68K_PLT8O = 18;    /* 8 bit PLT offset */
const R_68K_COPY = 19;    /* Copy symbol at runtime */
const R_68K_GLOB_DAT = 20;    /* Create GOT entry */
const R_68K_JMP_SLOT = 21;    /* Create PLT entry */
const R_68K_RELATIVE = 22;    /* Adjust by program base */
/* Keep this the last entry.  */
const R_68K_NUM = 23;

/* Intel 80386 specific definitions.  */

/* i386 relocs.  */

const R_386_NONE = 0;    /* No reloc */
const R_386_32 = 1;    /* Direct 32 bit  */
const R_386_PC32 = 2;    /* PC relative 32 bit */
const R_386_GOT32 = 3;    /* 32 bit GOT entry */
const R_386_PLT32 = 4;    /* 32 bit PLT address */
const R_386_COPY = 5;    /* Copy symbol at runtime */
const R_386_GLOB_DAT = 6;    /* Create GOT entry */
const R_386_JMP_SLOT = 7;    /* Create PLT entry */
const R_386_RELATIVE = 8;    /* Adjust by program base */
const R_386_GOTOFF = 9;    /* 32 bit offset to GOT */
const R_386_GOTPC = 10;   /* 32 bit PC relative offset to GOT */
const R_386_32PLT = 11;
const R_386_TLS_TPOFF = 14;   /* Offset in static TLS block */
const R_386_TLS_IE = 15;   /* Address of GOT entry for static TLS
                              block offset */
const R_386_TLS_GOTIE = 16;   /* GOT entry for static TLS block
                                 offset */
const R_386_TLS_LE = 17;   /* Offset relative to static TLS
                              block */
const R_386_TLS_GD = 18;   /* Direct 32 bit for GNU version of
                              general dynamic thread local data */
const R_386_TLS_LDM = 19;   /* Direct 32 bit for GNU version of
                               local dynamic thread local data
                               in LE code */
const R_386_16 = 20;
const R_386_PC16 = 21;
const R_386_8 = 22;
const R_386_PC8 = 23;
const R_386_TLS_GD_32 = 24;   /* Direct 32 bit for general dynamic
                                 thread local data */
const R_386_TLS_GD_PUSH = 25;   /* Tag for pushl in GD TLS code */
const R_386_TLS_GD_CALL = 26;   /* Relocation for call to
                                   __tls_get_addr() */
const R_386_TLS_GD_POP = 27;   /* Tag for popl in GD TLS code */
const R_386_TLS_LDM_32 = 28;   /* Direct 32 bit for local dynamic
                                  thread local data in LE code */
const R_386_TLS_LDM_PUSH = 29;   /* Tag for pushl in LDM TLS code */
const R_386_TLS_LDM_CALL = 30;   /* Relocation for call to
                                    __tls_get_addr() in LDM code */
const R_386_TLS_LDM_POP = 31;   /* Tag for popl in LDM TLS code */
const R_386_TLS_LDO_32 = 32;   /* Offset relative to TLS block */
const R_386_TLS_IE_32 = 33;   /* GOT entry for negated static TLS
                                 block offset */
const R_386_TLS_LE_32 = 34;   /* Negated offset relative to static
                                 TLS block */
const R_386_TLS_DTPMOD32 = 35;   /* ID of module containing symbol */
const R_386_TLS_DTPOFF32 = 36;   /* Offset in TLS block */
const R_386_TLS_TPOFF32 = 37;   /* Negated offset in static TLS block */
/* Keep this the last entry.  */
const R_386_NUM = 38;

/* SUN SPARC specific definitions.  */

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

const STT_SPARC_REGISTER = 13;  /* Global register reserved to app. */

/* Values for Elf64_Ehdr.e_flags.  */

const EF_SPARCV9_MM = 3;
const EF_SPARCV9_TSO = 0;
const EF_SPARCV9_PSO = 1;
const EF_SPARCV9_RMO = 2;
const EF_SPARC_LEDATA = 0x800000; /* little endian data */
const EF_SPARC_EXT_MASK = 0xFFFF00;
const EF_SPARC_32PLUS = 0x000100; /* generic V8+ features */
const EF_SPARC_SUN_US1 = 0x000200; /* Sun UltraSPARC1 extensions */
const EF_SPARC_HAL_R1 = 0x000400; /* HAL R1 extensions */
const EF_SPARC_SUN_US3 = 0x000800; /* Sun UltraSPARCIII extensions */

/* SPARC relocs.  */

const R_SPARC_NONE = 0; /* No reloc */
const R_SPARC_8 = 1; /* Direct 8 bit */
const R_SPARC_16 = 2; /* Direct 16 bit */
const R_SPARC_32 = 3; /* Direct 32 bit */
const R_SPARC_DISP8 = 4; /* PC relative 8 bit */
const R_SPARC_DISP16 = 5; /* PC relative 16 bit */
const R_SPARC_DISP32 = 6; /* PC relative 32 bit */
const R_SPARC_WDISP30 = 7; /* PC relative 30 bit shifted */
const R_SPARC_WDISP22 = 8; /* PC relative 22 bit shifted */
const R_SPARC_HI22 = 9; /* High 22 bit */
const R_SPARC_22 = 10;  /* Direct 22 bit */
const R_SPARC_13 = 11;  /* Direct 13 bit */
const R_SPARC_LO10 = 12;  /* Truncated 10 bit */
const R_SPARC_GOT10 = 13;  /* Truncated 10 bit GOT entry */
const R_SPARC_GOT13 = 14;  /* 13 bit GOT entry */
const R_SPARC_GOT22 = 15;  /* 22 bit GOT entry shifted */
const R_SPARC_PC10 = 16;  /* PC relative 10 bit truncated */
const R_SPARC_PC22 = 17;  /* PC relative 22 bit shifted */
const R_SPARC_WPLT30 = 18;  /* 30 bit PC relative PLT address */
const R_SPARC_COPY = 19;  /* Copy symbol at runtime */
const R_SPARC_GLOB_DAT = 20;  /* Create GOT entry */
const R_SPARC_JMP_SLOT = 21;  /* Create PLT entry */
const R_SPARC_RELATIVE = 22;  /* Adjust by program base */
const R_SPARC_UA32 = 23;  /* Direct 32 bit unaligned */

/* Additional Sparc64 relocs.  */

const R_SPARC_PLT32 = 24;  /* Direct 32 bit ref to PLT entry */
const R_SPARC_HIPLT22 = 25;  /* High 22 bit PLT entry */
const R_SPARC_LOPLT10 = 26;  /* Truncated 10 bit PLT entry */
const R_SPARC_PCPLT32 = 27;  /* PC rel 32 bit ref to PLT entry */
const R_SPARC_PCPLT22 = 28;  /* PC rel high 22 bit PLT entry */
const R_SPARC_PCPLT10 = 29;  /* PC rel trunc 10 bit PLT entry */
const R_SPARC_10 = 30;  /* Direct 10 bit */
const R_SPARC_11 = 31;  /* Direct 11 bit */
const R_SPARC_64 = 32;  /* Direct 64 bit */
const R_SPARC_OLO10 = 33;  /* 10bit with secondary 13bit addend */
const R_SPARC_HH22 = 34;  /* Top 22 bits of direct 64 bit */
const R_SPARC_HM10 = 35;  /* High middle 10 bits of ... */
const R_SPARC_LM22 = 36;  /* Low middle 22 bits of ... */
const R_SPARC_PC_HH22 = 37;  /* Top 22 bits of pc rel 64 bit */
const R_SPARC_PC_HM10 = 38;  /* High middle 10 bit of ... */
const R_SPARC_PC_LM22 = 39;  /* Low miggle 22 bits of ... */
const R_SPARC_WDISP16 = 40;  /* PC relative 16 bit shifted */
const R_SPARC_WDISP19 = 41;  /* PC relative 19 bit shifted */
const R_SPARC_7 = 43;  /* Direct 7 bit */
const R_SPARC_5 = 44;  /* Direct 5 bit */
const R_SPARC_6 = 45;  /* Direct 6 bit */
const R_SPARC_DISP64 = 46;  /* PC relative 64 bit */
const R_SPARC_PLT64 = 47;  /* Direct 64 bit ref to PLT entry */
const R_SPARC_HIX22 = 48;  /* High 22 bit complemented */
const R_SPARC_LOX10 = 49;  /* Truncated 11 bit complemented */
const R_SPARC_H44 = 50;  /* Direct high 12 of 44 bit */
const R_SPARC_M44 = 51;  /* Direct mid 22 of 44 bit */
const R_SPARC_L44 = 52;  /* Direct low 10 of 44 bit */
const R_SPARC_REGISTER = 53;  /* Global register usage */
const R_SPARC_UA64 = 54;  /* Direct 64 bit unaligned */
const R_SPARC_UA16 = 55;  /* Direct 16 bit unaligned */
const R_SPARC_TLS_GD_HI22 = 56;
const R_SPARC_TLS_GD_LO10 = 57;
const R_SPARC_TLS_GD_ADD = 58;
const R_SPARC_TLS_GD_CALL = 59;
const R_SPARC_TLS_LDM_HI22 = 60;
const R_SPARC_TLS_LDM_LO10 = 61;
const R_SPARC_TLS_LDM_ADD = 62;
const R_SPARC_TLS_LDM_CALL = 63;
const R_SPARC_TLS_LDO_HIX22 = 64;
const R_SPARC_TLS_LDO_LOX10 = 65;
const R_SPARC_TLS_LDO_ADD = 66;
const R_SPARC_TLS_IE_HI22 = 67;
const R_SPARC_TLS_IE_LO10 = 68;
const R_SPARC_TLS_IE_LD = 69;
const R_SPARC_TLS_IE_LDX = 70;
const R_SPARC_TLS_IE_ADD = 71;
const R_SPARC_TLS_LE_HIX22 = 72;
const R_SPARC_TLS_LE_LOX10 = 73;
const R_SPARC_TLS_DTPMOD32 = 74;
const R_SPARC_TLS_DTPMOD64 = 75;
const R_SPARC_TLS_DTPOFF32 = 76;
const R_SPARC_TLS_DTPOFF64 = 77;
const R_SPARC_TLS_TPOFF32 = 78;
const R_SPARC_TLS_TPOFF64 = 79;
/* Keep this the last entry.  */
const R_SPARC_NUM = 80;

/* For Sparc64, legal values for d_tag of Elf64_Dyn.  */

const DT_SPARC_REGISTER = 0x70000001;
const DT_SPARC_NUM = 2;

/* Bits present in AT_HWCAP on SPARC.  */

const HWCAP_SPARC_FLUSH = 1; /* The CPU supports flush insn.  */
const HWCAP_SPARC_STBAR = 2;
const HWCAP_SPARC_SWAP = 4;
const HWCAP_SPARC_MULDIV = 8;
const HWCAP_SPARC_V9 = 16;  /* The CPU is v9, so v8plus is ok.  */
const HWCAP_SPARC_ULTRA3 = 32;
const HWCAP_SPARC_BLKINIT = 64;  /* Sun4v with block-init/load-twin.  */

/* MIPS R3000 specific definitions.  */

/* Legal values for e_flags field of Elf32_Ehdr.  */

const EF_MIPS_NOREORDER = 1;   /* A .noreorder directive was used */
const EF_MIPS_PIC = 2;   /* Contains PIC code */
const EF_MIPS_CPIC = 4;   /* Uses PIC calling sequence */
const EF_MIPS_XGOT = 8;
const EF_MIPS_64BIT_WHIRL = 16;
const EF_MIPS_ABI2 = 32;
const EF_MIPS_ABI_ON32 = 64;
const EF_MIPS_ARCH = 0xf0000000;  /* MIPS architecture level */

/* Legal values for MIPS architecture level.  */

const EF_MIPS_ARCH_1 = 0x00000000;  /* -mips1 code.  */
const EF_MIPS_ARCH_2 = 0x10000000;  /* -mips2 code.  */
const EF_MIPS_ARCH_3 = 0x20000000;  /* -mips3 code.  */
const EF_MIPS_ARCH_4 = 0x30000000;  /* -mips4 code.  */
const EF_MIPS_ARCH_5 = 0x40000000;  /* -mips5 code.  */
const EF_MIPS_ARCH_32 = 0x60000000;  /* MIPS32 code.  */
const EF_MIPS_ARCH_64 = 0x70000000;  /* MIPS64 code.  */

/* The following are non-official names and should not be used.  */

const E_MIPS_ARCH_1 = 0x00000000;  /* -mips1 code.  */
const E_MIPS_ARCH_2 = 0x10000000;  /* -mips2 code.  */
const E_MIPS_ARCH_3 = 0x20000000;  /* -mips3 code.  */
const E_MIPS_ARCH_4 = 0x30000000;  /* -mips4 code.  */
const E_MIPS_ARCH_5 = 0x40000000;  /* -mips5 code.  */
const E_MIPS_ARCH_32 = 0x60000000;  /* MIPS32 code.  */
const E_MIPS_ARCH_64 = 0x70000000;  /* MIPS64 code.  */

/* Special section indices.  */

const SHN_MIPS_ACOMMON = 0xff00;  /* Allocated common symbols */
const SHN_MIPS_TEXT = 0xff01;  /* Allocated test symbols.  */
const SHN_MIPS_DATA = 0xff02;  /* Allocated data symbols.  */
const SHN_MIPS_SCOMMON = 0xff03;  /* Small common symbols */
const SHN_MIPS_SUNDEFINED = 0xff04;  /* Small undefined symbols */

/* Legal values for sh_type field of Elf32_Shdr.  */

const SHT_MIPS_LIBLIST = 0x70000000; /* Shared objects used in link */
const SHT_MIPS_MSYM = 0x70000001;
const SHT_MIPS_CONFLICT = 0x70000002; /* Conflicting symbols */
const SHT_MIPS_GPTAB = 0x70000003; /* Global data area sizes */
const SHT_MIPS_UCODE = 0x70000004; /* Reserved for SGI/MIPS compilers */
const SHT_MIPS_DEBUG = 0x70000005; /* MIPS ECOFF debugging information*/
const SHT_MIPS_REGINFO = 0x70000006; /* Register usage information */
const SHT_MIPS_PACKAGE = 0x70000007;
const SHT_MIPS_PACKSYM = 0x70000008;
const SHT_MIPS_RELD = 0x70000009;
const SHT_MIPS_IFACE = 0x7000000b;
const SHT_MIPS_CONTENT = 0x7000000c;
const SHT_MIPS_OPTIONS = 0x7000000d; /* Miscellaneous options.  */
const SHT_MIPS_SHDR = 0x70000010;
const SHT_MIPS_FDESC = 0x70000011;
const SHT_MIPS_EXTSYM = 0x70000012;
const SHT_MIPS_DENSE = 0x70000013;
const SHT_MIPS_PDESC = 0x70000014;
const SHT_MIPS_LOCSYM = 0x70000015;
const SHT_MIPS_AUXSYM = 0x70000016;
const SHT_MIPS_OPTSYM = 0x70000017;
const SHT_MIPS_LOCSTR = 0x70000018;
const SHT_MIPS_LINE = 0x70000019;
const SHT_MIPS_RFDESC = 0x7000001a;
const SHT_MIPS_DELTASYM = 0x7000001b;
const SHT_MIPS_DELTAINST = 0x7000001c;
const SHT_MIPS_DELTACLASS = 0x7000001d;
const SHT_MIPS_DWARF = 0x7000001e; /* DWARF debugging information.  */
const SHT_MIPS_DELTADECL = 0x7000001f;
const SHT_MIPS_SYMBOL_LIB = 0x70000020;
const SHT_MIPS_EVENTS = 0x70000021; /* Event section.  */
const SHT_MIPS_TRANSLATE = 0x70000022;
const SHT_MIPS_PIXIE = 0x70000023;
const SHT_MIPS_XLATE = 0x70000024;
const SHT_MIPS_XLATE_DEBUG = 0x70000025;
const SHT_MIPS_WHIRL = 0x70000026;
const SHT_MIPS_EH_REGION = 0x70000027;
const SHT_MIPS_XLATE_OLD = 0x70000028;
const SHT_MIPS_PDR_EXCEPTION = 0x70000029;

/* Legal values for sh_flags field of Elf32_Shdr.  */

const SHF_MIPS_GPREL = 0x10000000; /* Must be part of global data area */
const SHF_MIPS_MERGE = 0x20000000;
const SHF_MIPS_ADDR = 0x40000000;
const SHF_MIPS_STRINGS = 0x80000000;
const SHF_MIPS_NOSTRIP = 0x08000000;
const SHF_MIPS_LOCAL = 0x04000000;
const SHF_MIPS_NAMES = 0x02000000;
const SHF_MIPS_NODUPE = 0x01000000;

/* Symbol tables.  */

/* MIPS specific values for `st_other'.  */
const STO_MIPS_DEFAULT = 0x0;
const STO_MIPS_INTERNAL = 0x1;
const STO_MIPS_HIDDEN = 0x2;
const STO_MIPS_PROTECTED = 0x3;
const STO_MIPS_SC_ALIGN_UNUSED = 0xff;

/* MIPS specific values for `st_info'.  */
const STB_MIPS_SPLIT_COMMON = 13;

/* Entries found in sections of type SHT_MIPS_GPTAB.  */

union Elf32_gptab
{
  struct struct_a
  {
    Elf32_Word gt_current_g_value;  /* -G value used for compilation */
    Elf32_Word gt_unused;   /* Not used */
  }
  struct_a gt_header;      /* First entry in section */

  struct struct_b
  {
    Elf32_Word gt_g_value;    /* If this value were used for -G */
    Elf32_Word gt_bytes;    /* This many bytes would be used */
  }
  struct_b gt_entry;       /* Subsequent entries in section */
}

/* Entry found in sections of type SHT_MIPS_REGINFO.  */

struct Elf32_RegInfo
{
  Elf32_Word ri_gprmask;   /* General registers used */
  Elf32_Word[4] ri_cprmask;    /* Coprocessor registers used */
  Elf32_Sword ri_gp_value;    /* $gp register value */
}

/* Entries found in sections of type SHT_MIPS_OPTIONS.  */

struct Elf_Options
{
  ubyte kind;   /* Determines interpretation of the
                   variable part of descriptor.  */
  ubyte size;   /* Size of descriptor, including header.  */
  Elf32_Section section;  /* Section header index of section affected,
                             0 for global options.  */
  Elf32_Word info;    /* Kind-specific information.  */
}

/* Values for `kind' field in Elf_Options.  */

const ODK_NULL = 0; /* Undefined.  */
const ODK_REGINFO = 1; /* Register usage information.  */
const ODK_EXCEPTIONS = 2; /* Exception processing options.  */
const ODK_PAD = 3; /* Section padding options.  */
const ODK_HWPATCH = 4; /* Hardware workarounds performed */
const ODK_FILL = 5; /* record the fill value used by the linker. */
const ODK_TAGS = 6; /* reserve space for desktop tools to write. */
const ODK_HWAND = 7; /* HW workarounds.  'AND' bits when merging. */
const ODK_HWOR = 8; /* HW workarounds.  'OR' bits when merging.  */

/* Values for `info' in Elf_Options for ODK_EXCEPTIONS entries.  */

const OEX_FPU_MIN = 0x1f;  /* FPE's which MUST be enabled.  */
const OEX_FPU_MAX = 0x1f00;  /* FPE's which MAY be enabled.  */
const OEX_PAGE0 = 0x10000; /* page zero must be mapped.  */
const OEX_SMM = 0x20000; /* Force sequential memory mode?  */
const OEX_FPDBUG = 0x40000; /* Force floating point debug mode?  */
const OEX_PRECISEFP = OEX_FPDBUG;
const OEX_DISMISS = 0x80000; /* Dismiss invalid address faults?  */

const OEX_FPU_INVAL = 0x10;
const OEX_FPU_DIV0 = 0x08;
const OEX_FPU_OFLO = 0x04;
const OEX_FPU_UFLO = 0x02;
const OEX_FPU_INEX = 0x01;

/* Masks for `info' in Elf_Options for an ODK_HWPATCH entry.  */

const OHW_R4KEOP = 0x1; /* R4000 end-of-page patch.  */
const OHW_R8KPFETCH = 0x2; /* may need R8000 prefetch patch.  */
const OHW_R5KEOP = 0x4; /* R5000 end-of-page patch.  */
const OHW_R5KCVTL = 0x8; /* R5000 cvt.[ds].l bug.  clean=1.  */

const OPAD_PREFIX = 0x1;
const OPAD_POSTFIX = 0x2;
const OPAD_SYMBOL = 0x4;

/* Entry found in `.options' section.  */

struct Elf_Options_Hw
{
  Elf32_Word hwp_flags1;  /* Extra flags.  */
  Elf32_Word hwp_flags2;  /* Extra flags.  */
}

/* Masks for `info' in ElfOptions for ODK_HWAND and ODK_HWOR entries.  */

const OHWA0_R4KEOP_CHECKED = 0x00000001;
const OHWA1_R4KEOP_CLEAN = 0x00000002;

/* MIPS relocs.  */

const R_MIPS_NONE = 0; /* No reloc */
const R_MIPS_16 = 1; /* Direct 16 bit */
const R_MIPS_32 = 2; /* Direct 32 bit */
const R_MIPS_REL32 = 3; /* PC relative 32 bit */
const R_MIPS_26 = 4; /* Direct 26 bit shifted */
const R_MIPS_HI16 = 5; /* High 16 bit */
const R_MIPS_LO16 = 6; /* Low 16 bit */
const R_MIPS_GPREL16 = 7; /* GP relative 16 bit */
const R_MIPS_LITERAL = 8; /* 16 bit literal entry */
const R_MIPS_GOT16 = 9; /* 16 bit GOT entry */
const R_MIPS_PC16 = 10;  /* PC relative 16 bit */
const R_MIPS_CALL16 = 11;  /* 16 bit GOT entry for function */
const R_MIPS_GPREL32 = 12;  /* GP relative 32 bit */

const R_MIPS_SHIFT5 = 16;
const R_MIPS_SHIFT6 = 17;
const R_MIPS_64 = 18;
const R_MIPS_GOT_DISP = 19;
const R_MIPS_GOT_PAGE = 20;
const R_MIPS_GOT_OFST = 21;
const R_MIPS_GOT_HI16 = 22;
const R_MIPS_GOT_LO16 = 23;
const R_MIPS_SUB = 24;
const R_MIPS_INSERT_A = 25;
const R_MIPS_INSERT_B = 26;
const R_MIPS_DELETE = 27;
const R_MIPS_HIGHER = 28;
const R_MIPS_HIGHEST = 29;
const R_MIPS_CALL_HI16 = 30;
const R_MIPS_CALL_LO16 = 31;
const R_MIPS_SCN_DISP = 32;
const R_MIPS_REL16 = 33;
const R_MIPS_ADD_IMMEDIATE = 34;
const R_MIPS_PJUMP = 35;
const R_MIPS_RELGOT = 36;
const R_MIPS_JALR = 37;
const R_MIPS_TLS_DTPMOD32 = 38;  /* Module number 32 bit */
const R_MIPS_TLS_DTPREL32 = 39;  /* Module-relative offset 32 bit */
const R_MIPS_TLS_DTPMOD64 = 40;  /* Module number 64 bit */
const R_MIPS_TLS_DTPREL64 = 41;  /* Module-relative offset 64 bit */
const R_MIPS_TLS_GD = 42;  /* 16 bit GOT offset for GD */
const R_MIPS_TLS_LDM = 43;  /* 16 bit GOT offset for LDM */
const R_MIPS_TLS_DTPREL_HI16 = 44;  /* Module-relative offset, high 16 bits */
const R_MIPS_TLS_DTPREL_LO16 = 45;  /* Module-relative offset, low 16 bits */
const R_MIPS_TLS_GOTTPREL = 46;  /* 16 bit GOT offset for IE */
const R_MIPS_TLS_TPREL32 = 47;  /* TP-relative offset, 32 bit */
const R_MIPS_TLS_TPREL64 = 48;  /* TP-relative offset, 64 bit */
const R_MIPS_TLS_TPREL_HI16 = 49;  /* TP-relative offset, high 16 bits */
const R_MIPS_TLS_TPREL_LO16 = 50;  /* TP-relative offset, low 16 bits */
const R_MIPS_GLOB_DAT = 51;
/* Keep this the last entry.  */
const R_MIPS_NUM = 52;

/* Legal values for p_type field of ProgramHeader.  */

const PT_MIPS_REGINFO = 0x70000000;  /* Register usage information */
const PT_MIPS_RTPROC = 0x70000001;  /* Runtime procedure table. */
const PT_MIPS_OPTIONS = 0x70000002;

/* Special program header types.  */

const PF_MIPS_LOCAL = 0x10000000;

/* Legal values for d_tag field of Elf32_Dyn.  */

const DT_MIPS_RLD_VERSION = 0x70000001; /* Runtime linker interface version */
const DT_MIPS_TIME_STAMP = 0x70000002; /* Timestamp */
const DT_MIPS_ICHECKSUM = 0x70000003; /* Checksum */
const DT_MIPS_IVERSION = 0x70000004; /* Version string (string tbl index) */
const DT_MIPS_FLAGS = 0x70000005; /* Flags */
const DT_MIPS_BASE_ADDRESS = 0x70000006; /* Base address */
const DT_MIPS_MSYM = 0x70000007;
const DT_MIPS_CONFLICT = 0x70000008; /* Address of CONFLICT section */
const DT_MIPS_LIBLIST = 0x70000009; /* Address of LIBLIST section */
const DT_MIPS_LOCAL_GOTNO = 0x7000000a; /* Number of local GOT entries */
const DT_MIPS_CONFLICTNO = 0x7000000b; /* Number of CONFLICT entries */
const DT_MIPS_LIBLISTNO = 0x70000010; /* Number of LIBLIST entries */
const DT_MIPS_SYMTABNO = 0x70000011; /* Number of DYNSYM entries */
const DT_MIPS_UNREFEXTNO = 0x70000012; /* First external DYNSYM */
const DT_MIPS_GOTSYM = 0x70000013; /* First GOT entry in DYNSYM */
const DT_MIPS_HIPAGENO = 0x70000014; /* Number of GOT page table entries */
const DT_MIPS_RLD_MAP = 0x70000016; /* Address of run time loader map.  */
const DT_MIPS_DELTA_CLASS = 0x70000017; /* Delta C++ class definition.  */
const DT_MIPS_DELTA_CLASS_NO = 0x70000018; /* Number of entries in
                                              DT_MIPS_DELTA_CLASS.  */
const DT_MIPS_DELTA_INSTANCE = 0x70000019; /* Delta C++ class instances.  */
const DT_MIPS_DELTA_INSTANCE_NO = 0x7000001a; /* Number of entries in
                                                 DT_MIPS_DELTA_INSTANCE.  */
const DT_MIPS_DELTA_RELOC = 0x7000001b; /* Delta relocations.  */
const DT_MIPS_DELTA_RELOC_NO = 0x7000001c; /* Number of entries in
                                              DT_MIPS_DELTA_RELOC.  */
const DT_MIPS_DELTA_SYM = 0x7000001d; /* Delta symbols that Delta
                                         relocations refer to.  */
const DT_MIPS_DELTA_SYM_NO = 0x7000001e; /* Number of entries in
                                            DT_MIPS_DELTA_SYM.  */
const DT_MIPS_DELTA_CLASSSYM = 0x70000020; /* Delta symbols that hold the
                                              class declaration.  */
const DT_MIPS_DELTA_CLASSSYM_NO = 0x70000021; /* Number of entries in
                                                 DT_MIPS_DELTA_CLASSSYM.  */
const DT_MIPS_CXX_FLAGS = 0x70000022; /* Flags indicating for C++ flavor.  */
const DT_MIPS_PIXIE_INIT = 0x70000023;
const DT_MIPS_SYMBOL_LIB = 0x70000024;
const DT_MIPS_LOCALPAGE_GOTIDX = 0x70000025;
const DT_MIPS_LOCAL_GOTIDX = 0x70000026;
const DT_MIPS_HIDDEN_GOTIDX = 0x70000027;
const DT_MIPS_PROTECTED_GOTIDX = 0x70000028;
const DT_MIPS_OPTIONS = 0x70000029; /* Address of .options.  */
const DT_MIPS_INTERFACE = 0x7000002a; /* Address of .interface.  */
const DT_MIPS_DYNSTR_ALIGN = 0x7000002b;
const DT_MIPS_INTERFACE_SIZE = 0x7000002c; /* Size of the .interface section. */
const DT_MIPS_RLD_TEXT_RESOLVE_ADDR = 0x7000002d; /* Address of rld_text_rsolve
                                                     function stored in GOT.  */
const DT_MIPS_PERF_SUFFIX = 0x7000002e; /* Default suffix of dso to be added
                                           by rld on dlopen() calls.  */
const DT_MIPS_COMPACT_SIZE = 0x7000002f; /* (O32)Size of compact rel section. */
const DT_MIPS_GP_VALUE = 0x70000030; /* GP value for aux GOTs.  */
const DT_MIPS_AUX_DYNAMIC = 0x70000031; /* Address of aux .dynamic.  */
// const DT_MIPS_NUM = 0x32;

/* Legal values for DT_MIPS_FLAGS Elf32_Dyn entry.  */

const RHF_NONE = 0;    /* No flags */
const RHF_QUICKSTART = (1 << 0); /* Use quickstart */
const RHF_NOTPOT = (1 << 1); /* Hash size not power of 2 */
const RHF_NO_LIBRARY_REPLACEMENT = (1 << 2); /* Ignore LD_LIBRARY_PATH */
const RHF_NO_MOVE = (1 << 3);
const RHF_SGI_ONLY = (1 << 4);
const RHF_GUARANTEE_INIT = (1 << 5);
const RHF_DELTA_C_PLUS_PLUS = (1 << 6);
const RHF_GUARANTEE_START_INIT = (1 << 7);
const RHF_PIXIE = (1 << 8);
const RHF_DEFAULT_DELAY_LOAD = (1 << 9);
const RHF_REQUICKSTART = (1 << 10);
const RHF_REQUICKSTARTED = (1 << 11);
const RHF_CORD = (1 << 12);
const RHF_NO_UNRES_UNDEF = (1 << 13);
const RHF_RLD_ORDER_SAFE = (1 << 14);

/* Entries found in sections of type SHT_MIPS_LIBLIST.  */

struct Elf32_Lib
{
  Elf32_Word l_name;    /* Name (string table index) */
  Elf32_Word l_time_stamp;  /* Timestamp */
  Elf32_Word l_checksum;  /* Checksum */
  Elf32_Word l_version;   /* Interface version */
  Elf32_Word l_flags;   /* Flags */
}

struct Elf64_Lib
{
  Elf64_Word l_name;    /* Name (string table index) */
  Elf64_Word l_time_stamp;  /* Timestamp */
  Elf64_Word l_checksum;  /* Checksum */
  Elf64_Word l_version;   /* Interface version */
  Elf64_Word l_flags;   /* Flags */
}

/* Legal values for l_flags.  */

const LL_NONE = 0;
const LL_EXACT_MATCH = (1 << 0);  /* Require exact match */
const LL_IGNORE_INT_VER = (1 << 1);  /* Ignore interface version */
const LL_REQUIRE_MINOR = (1 << 2);
const LL_EXPORTS = (1 << 3);
const LL_DELAY_LOAD = (1 << 4);
const LL_DELTA = (1 << 5);

/* Entries found in sections of type SHT_MIPS_CONFLICT.  */

alias Elf32_Addr Elf32_Conflict;

/* HPPA specific definitions.  */

/* Legal values for e_flags field of Elf32_Ehdr.  */

const EF_PARISC_TRAPNIL = 0x00010000; /* Trap nil pointer dereference.  */
const EF_PARISC_EXT = 0x00020000; /* Program uses arch. extensions. */
const EF_PARISC_LSB = 0x00040000; /* Program expects little endian. */
const EF_PARISC_WIDE = 0x00080000; /* Program expects wide mode.  */
const EF_PARISC_NO_KABP = 0x00100000; /* No kernel assisted branch
                                         prediction.  */
const EF_PARISC_LAZYSWAP = 0x00400000; /* Allow lazy swapping.  */
const EF_PARISC_ARCH = 0x0000ffff; /* Architecture version.  */

/* Defined values for `e_flags & EF_PARISC_ARCH' are:  */

const EFA_PARISC_1_0 = 0x020b; /* PA-RISC 1.0 big-endian.  */
const EFA_PARISC_1_1 = 0x0210; /* PA-RISC 1.1 big-endian.  */
const EFA_PARISC_2_0 = 0x0214; /* PA-RISC 2.0 big-endian.  */

/* Additional section indeces.  */

const SHN_PARISC_ANSI_COMMON = 0xff00;     /* Section for tenatively declared
                                              symbols in ANSI C.  */
const SHN_PARISC_HUGE_COMMON = 0xff01;     /* Common blocks in huge model.  */

/* Legal values for sh_type field of Elf32_Shdr.  */

const SHT_PARISC_EXT = 0x70000000; /* Contains product specific ext. */
const SHT_PARISC_UNWIND = 0x70000001; /* Unwind information.  */
const SHT_PARISC_DOC = 0x70000002; /* Debug info for optimized code. */

/* Legal values for sh_flags field of Elf32_Shdr.  */

const SHF_PARISC_SHORT = 0x20000000; /* Section with short addressing. */
const SHF_PARISC_HUGE = 0x40000000; /* Section far from gp.  */
const SHF_PARISC_SBP = 0x80000000; /* Static branch prediction code. */

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

const STT_PARISC_MILLICODE = 13;  /* Millicode function entry point.  */

const STT_HP_OPAQUE = (STT_LOOS + 0x1);
const STT_HP_STUB = (STT_LOOS + 0x2);

/* HPPA relocs.  */

const R_PARISC_NONE = 0; /* No reloc.  */
const R_PARISC_DIR32 = 1; /* Direct 32-bit reference.  */
const R_PARISC_DIR21L = 2; /* Left 21 bits of eff. address.  */
const R_PARISC_DIR17R = 3; /* Right 17 bits of eff. address.  */
const R_PARISC_DIR17F = 4; /* 17 bits of eff. address.  */
const R_PARISC_DIR14R = 6; /* Right 14 bits of eff. address.  */
const R_PARISC_PCREL32 = 9; /* 32-bit rel. address.  */
const R_PARISC_PCREL21L = 10;  /* Left 21 bits of rel. address.  */
const R_PARISC_PCREL17R = 11;  /* Right 17 bits of rel. address.  */
const R_PARISC_PCREL17F = 12;  /* 17 bits of rel. address.  */
const R_PARISC_PCREL14R = 14;  /* Right 14 bits of rel. address.  */
const R_PARISC_DPREL21L = 18;  /* Left 21 bits of rel. address.  */
const R_PARISC_DPREL14R = 22;  /* Right 14 bits of rel. address.  */
const R_PARISC_GPREL21L = 26;  /* GP-relative, left 21 bits.  */
const R_PARISC_GPREL14R = 30;  /* GP-relative, right 14 bits.  */
const R_PARISC_LTOFF21L = 34;  /* LT-relative, left 21 bits.  */
const R_PARISC_LTOFF14R = 38;  /* LT-relative, right 14 bits.  */
const R_PARISC_SECREL32 = 41;  /* 32 bits section rel. address.  */
const R_PARISC_SEGBASE = 48;  /* No relocation, set segment base.  */
const R_PARISC_SEGREL32 = 49;  /* 32 bits segment rel. address.  */
const R_PARISC_PLTOFF21L = 50;  /* PLT rel. address, left 21 bits.  */
const R_PARISC_PLTOFF14R = 54;  /* PLT rel. address, right 14 bits.  */
const R_PARISC_LTOFF_FPTR32 = 57;  /* 32 bits LT-rel. function pointer. */
const R_PARISC_LTOFF_FPTR21L = 58;  /* LT-rel. fct ptr, left 21 bits. */
const R_PARISC_LTOFF_FPTR14R = 62;  /* LT-rel. fct ptr, right 14 bits. */
const R_PARISC_FPTR64 = 64;  /* 64 bits function address.  */
const R_PARISC_PLABEL32 = 65;  /* 32 bits function address.  */
const R_PARISC_PLABEL21L = 66;  /* Left 21 bits of fdesc address */
const R_PARISC_PLABEL14R = 70;  /* Right 14 bits of fdesc address */
const R_PARISC_PCREL64 = 72;  /* 64 bits PC-rel. address.  */
const R_PARISC_PCREL22F = 74;  /* 22 bits PC-rel. address.  */
const R_PARISC_PCREL14WR = 75;  /* PC-rel. address, right 14 bits.  */
const R_PARISC_PCREL14DR = 76;  /* PC rel. address, right 14 bits.  */
const R_PARISC_PCREL16F = 77;  /* 16 bits PC-rel. address.  */
const R_PARISC_PCREL16WF = 78;  /* 16 bits PC-rel. address.  */
const R_PARISC_PCREL16DF = 79;  /* 16 bits PC-rel. address.  */
const R_PARISC_DIR64 = 80;  /* 64 bits of eff. address.  */
const R_PARISC_DIR14WR = 83;  /* 14 bits of eff. address.  */
const R_PARISC_DIR14DR = 84;  /* 14 bits of eff. address.  */
const R_PARISC_DIR16F = 85;  /* 16 bits of eff. address.  */
const R_PARISC_DIR16WF = 86;  /* 16 bits of eff. address.  */
const R_PARISC_DIR16DF = 87;  /* 16 bits of eff. address.  */
const R_PARISC_GPREL64 = 88;  /* 64 bits of GP-rel. address.  */
const R_PARISC_GPREL14WR = 91;  /* GP-rel. address, right 14 bits.  */
const R_PARISC_GPREL14DR = 92;  /* GP-rel. address, right 14 bits.  */
const R_PARISC_GPREL16F = 93;  /* 16 bits GP-rel. address.  */
const R_PARISC_GPREL16WF = 94;  /* 16 bits GP-rel. address.  */
const R_PARISC_GPREL16DF = 95;  /* 16 bits GP-rel. address.  */
const R_PARISC_LTOFF64 = 96;  /* 64 bits LT-rel. address.  */
const R_PARISC_LTOFF14WR = 99;  /* LT-rel. address, right 14 bits.  */
const R_PARISC_LTOFF14DR = 100; /* LT-rel. address, right 14 bits.  */
const R_PARISC_LTOFF16F = 101; /* 16 bits LT-rel. address.  */
const R_PARISC_LTOFF16WF = 102; /* 16 bits LT-rel. address.  */
const R_PARISC_LTOFF16DF = 103; /* 16 bits LT-rel. address.  */
const R_PARISC_SECREL64 = 104; /* 64 bits section rel. address.  */
const R_PARISC_SEGREL64 = 112; /* 64 bits segment rel. address.  */
const R_PARISC_PLTOFF14WR = 115; /* PLT-rel. address, right 14 bits.  */
const R_PARISC_PLTOFF14DR = 116; /* PLT-rel. address, right 14 bits.  */
const R_PARISC_PLTOFF16F = 117; /* 16 bits LT-rel. address.  */
const R_PARISC_PLTOFF16WF = 118; /* 16 bits PLT-rel. address.  */
const R_PARISC_PLTOFF16DF = 119; /* 16 bits PLT-rel. address.  */
const R_PARISC_LTOFF_FPTR64 = 120; /* 64 bits LT-rel. function ptr.  */
const R_PARISC_LTOFF_FPTR14WR = 123; /* LT-rel. fct. ptr., right 14 bits. */
const R_PARISC_LTOFF_FPTR14DR = 124; /* LT-rel. fct. ptr., right 14 bits. */
const R_PARISC_LTOFF_FPTR16F = 125; /* 16 bits LT-rel. function ptr.  */
const R_PARISC_LTOFF_FPTR16WF = 126; /* 16 bits LT-rel. function ptr.  */
const R_PARISC_LTOFF_FPTR16DF = 127; /* 16 bits LT-rel. function ptr.  */
const R_PARISC_LORESERVE = 128;
const R_PARISC_COPY = 128; /* Copy relocation.  */
const R_PARISC_IPLT = 129; /* Dynamic reloc, imported PLT */
const R_PARISC_EPLT = 130; /* Dynamic reloc, exported PLT */
const R_PARISC_TPREL32 = 153; /* 32 bits TP-rel. address.  */
const R_PARISC_TPREL21L = 154; /* TP-rel. address, left 21 bits.  */
const R_PARISC_TPREL14R = 158; /* TP-rel. address, right 14 bits.  */
const R_PARISC_LTOFF_TP21L = 162; /* LT-TP-rel. address, left 21 bits. */
const R_PARISC_LTOFF_TP14R = 166; /* LT-TP-rel. address, right 14 bits.*/
const R_PARISC_LTOFF_TP14F = 167; /* 14 bits LT-TP-rel. address.  */
const R_PARISC_TPREL64 = 216; /* 64 bits TP-rel. address.  */
const R_PARISC_TPREL14WR = 219; /* TP-rel. address, right 14 bits.  */
const R_PARISC_TPREL14DR = 220; /* TP-rel. address, right 14 bits.  */
const R_PARISC_TPREL16F = 221; /* 16 bits TP-rel. address.  */
const R_PARISC_TPREL16WF = 222; /* 16 bits TP-rel. address.  */
const R_PARISC_TPREL16DF = 223; /* 16 bits TP-rel. address.  */
const R_PARISC_LTOFF_TP64 = 224; /* 64 bits LT-TP-rel. address.  */
const R_PARISC_LTOFF_TP14WR = 227; /* LT-TP-rel. address, right 14 bits.*/
const R_PARISC_LTOFF_TP14DR = 228; /* LT-TP-rel. address, right 14 bits.*/
const R_PARISC_LTOFF_TP16F = 229; /* 16 bits LT-TP-rel. address.  */
const R_PARISC_LTOFF_TP16WF = 230; /* 16 bits LT-TP-rel. address.  */
const R_PARISC_LTOFF_TP16DF = 231; /* 16 bits LT-TP-rel. address.  */

const R_PARISC_GNU_VTENTRY = 232;
const R_PARISC_GNU_VTINHERIT = 233;
const R_PARISC_TLS_GD21L = 234; /* GD 21-bit left */
const R_PARISC_TLS_GD14R = 235; /* GD 14-bit right */
const R_PARISC_TLS_GDCALL = 236; /* GD call to __t_g_a */
const R_PARISC_TLS_LDM21L = 237; /* LD module 21-bit left */
const R_PARISC_TLS_LDM14R = 238; /* LD module 14-bit right */
const R_PARISC_TLS_LDMCALL = 239; /* LD module call to __t_g_a */
const R_PARISC_TLS_LDO21L = 240; /* LD offset 21-bit left */
const R_PARISC_TLS_LDO14R = 241; /* LD offset 14-bit right */
const R_PARISC_TLS_DTPMOD32 = 242; /* DTP module 32-bit */
const R_PARISC_TLS_DTPMOD64 = 243; /* DTP module 64-bit */
const R_PARISC_TLS_DTPOFF32 = 244; /* DTP offset 32-bit */
const R_PARISC_TLS_DTPOFF64 = 245; /* DTP offset 32-bit */

const R_PARISC_TLS_LE21L = R_PARISC_TPREL21L;
const R_PARISC_TLS_LE14R = R_PARISC_TPREL14R;
const R_PARISC_TLS_IE21L = R_PARISC_LTOFF_TP21L;
const R_PARISC_TLS_IE14R = R_PARISC_LTOFF_TP14R;
const R_PARISC_TLS_TPREL32 = R_PARISC_TPREL32;
const R_PARISC_TLS_TPREL64 = R_PARISC_TPREL64;

const R_PARISC_HIRESERVE = 255;

/* Legal values for p_type field of ProgramHeader/Elf64_Phdr.  */

const PT_HP_TLS = (PT_LOOS + 0x0);
const PT_HP_CORE_NONE = (PT_LOOS + 0x1);
const PT_HP_CORE_VERSION = (PT_LOOS + 0x2);
const PT_HP_CORE_KERNEL = (PT_LOOS + 0x3);
const PT_HP_CORE_COMM = (PT_LOOS + 0x4);
const PT_HP_CORE_PROC = (PT_LOOS + 0x5);
const PT_HP_CORE_LOADABLE = (PT_LOOS + 0x6);
const PT_HP_CORE_STACK = (PT_LOOS + 0x7);
const PT_HP_CORE_SHM = (PT_LOOS + 0x8);
const PT_HP_CORE_MMF = (PT_LOOS + 0x9);
const PT_HP_PARALLEL = (PT_LOOS + 0x10);
const PT_HP_FASTBIND = (PT_LOOS + 0x11);
const PT_HP_OPT_ANNOT = (PT_LOOS + 0x12);
const PT_HP_HSL_ANNOT = (PT_LOOS + 0x13);
const PT_HP_STACK = (PT_LOOS + 0x14);

const PT_PARISC_ARCHEXT = 0x70000000;
const PT_PARISC_UNWIND = 0x70000001;

/* Legal values for p_flags field of ProgramHeader/Elf64_Phdr.  */

const PF_PARISC_SBP = 0x08000000;

const PF_HP_PAGE_SIZE = 0x00100000;
const PF_HP_FAR_SHARED = 0x00200000;
const PF_HP_NEAR_SHARED = 0x00400000;
const PF_HP_CODE = 0x01000000;
const PF_HP_MODIFY = 0x02000000;
const PF_HP_LAZYSWAP = 0x04000000;
const PF_HP_SBP = 0x08000000;

/* Alpha specific definitions.  */

/* Legal values for e_flags field of Elf64_Ehdr.  */

const EF_ALPHA_32BIT = 1; /* All addresses must be < 2GB.  */
const EF_ALPHA_CANRELAX = 2; /* Relocations for relaxing exist.  */

/* Legal values for sh_type field of Elf64_Shdr.  */

/* These two are primerily concerned with ECOFF debugging info.  */
const SHT_ALPHA_DEBUG = 0x70000001;
const SHT_ALPHA_REGINFO = 0x70000002;

/* Legal values for sh_flags field of Elf64_Shdr.  */

const SHF_ALPHA_GPREL = 0x10000000;

/* Legal values for st_other field of Elf64_Sym.  */
const STO_ALPHA_NOPV = 0x80;  /* No PV required.  */
const STO_ALPHA_STD_GPLOAD = 0x88;  /* PV only used for initial ldgp.  */

/* Alpha relocs.  */

const R_ALPHA_NONE = 0; /* No reloc */
const R_ALPHA_REFLONG = 1; /* Direct 32 bit */
const R_ALPHA_REFQUAD = 2; /* Direct 64 bit */
const R_ALPHA_GPREL32 = 3; /* GP relative 32 bit */
const R_ALPHA_LITERAL = 4; /* GP relative 16 bit w/optimization */
const R_ALPHA_LITUSE = 5; /* Optimization hint for LITERAL */
const R_ALPHA_GPDISP = 6; /* Add displacement to GP */
const R_ALPHA_BRADDR = 7; /* PC+4 relative 23 bit shifted */
const R_ALPHA_HINT = 8; /* PC+4 relative 16 bit shifted */
const R_ALPHA_SREL16 = 9; /* PC relative 16 bit */
const R_ALPHA_SREL32 = 10;  /* PC relative 32 bit */
const R_ALPHA_SREL64 = 11;  /* PC relative 64 bit */
const R_ALPHA_GPRELHIGH = 17;  /* GP relative 32 bit, high 16 bits */
const R_ALPHA_GPRELLOW = 18;  /* GP relative 32 bit, low 16 bits */
const R_ALPHA_GPREL16 = 19;  /* GP relative 16 bit */
const R_ALPHA_COPY = 24;  /* Copy symbol at runtime */
const R_ALPHA_GLOB_DAT = 25;  /* Create GOT entry */
const R_ALPHA_JMP_SLOT = 26;  /* Create PLT entry */
const R_ALPHA_RELATIVE = 27;  /* Adjust by program base */
const R_ALPHA_TLS_GD_HI = 28;
const R_ALPHA_TLSGD = 29;
const R_ALPHA_TLS_LDM = 30;
const R_ALPHA_DTPMOD64 = 31;
const R_ALPHA_GOTDTPREL = 32;
const R_ALPHA_DTPREL64 = 33;
const R_ALPHA_DTPRELHI = 34;
const R_ALPHA_DTPRELLO = 35;
const R_ALPHA_DTPREL16 = 36;
const R_ALPHA_GOTTPREL = 37;
const R_ALPHA_TPREL64 = 38;
const R_ALPHA_TPRELHI = 39;
const R_ALPHA_TPRELLO = 40;
const R_ALPHA_TPREL16 = 41;
/* Keep this the last entry.  */
const R_ALPHA_NUM = 46;

/* Magic values of the LITUSE relocation addend.  */
const LITUSE_ALPHA_ADDR = 0;
const LITUSE_ALPHA_BASE = 1;
const LITUSE_ALPHA_BYTOFF = 2;
const LITUSE_ALPHA_JSR = 3;
const LITUSE_ALPHA_TLS_GD = 4;
const LITUSE_ALPHA_TLS_LDM = 5;

/* Legal values for d_tag of Elf64_Dyn.  */
const DT_ALPHA_PLTRO = (DT_LOPROC + 0);
const DT_ALPHA_NUM = 1;

/* PowerPC specific declarations */

/* Values for Elf32/64_Ehdr.e_flags.  */
const EF_PPC_EMB = 0x80000000;  /* PowerPC embedded flag */

/* Cygnus local bits below */
const EF_PPC_RELOCATABLE = 0x00010000;  /* PowerPC -mrelocatable flag*/
const EF_PPC_RELOCATABLE_LIB = 0x00008000;  /* PowerPC -mrelocatable-lib
                                               flag */

/* PowerPC relocations defined by the ABIs */
const R_PPC_NONE = 0;
const R_PPC_ADDR32 = 1; /* 32bit absolute address */
const R_PPC_ADDR24 = 2; /* 26bit address, 2 bits ignored.  */
const R_PPC_ADDR16 = 3; /* 16bit absolute address */
const R_PPC_ADDR16_LO = 4; /* lower 16bit of absolute address */
const R_PPC_ADDR16_HI = 5; /* high 16bit of absolute address */
const R_PPC_ADDR16_HA = 6; /* adjusted high 16bit */
const R_PPC_ADDR14 = 7; /* 16bit address, 2 bits ignored */
const R_PPC_ADDR14_BRTAKEN = 8;
const R_PPC_ADDR14_BRNTAKEN = 9;
const R_PPC_REL24 = 10;  /* PC relative 26 bit */
const R_PPC_REL14 = 11;  /* PC relative 16 bit */
const R_PPC_REL14_BRTAKEN = 12;
const R_PPC_REL14_BRNTAKEN = 13;
const R_PPC_GOT16 = 14;
const R_PPC_GOT16_LO = 15;
const R_PPC_GOT16_HI = 16;
const R_PPC_GOT16_HA = 17;
const R_PPC_PLTREL24 = 18;
const R_PPC_COPY = 19;
const R_PPC_GLOB_DAT = 20;
const R_PPC_JMP_SLOT = 21;
const R_PPC_RELATIVE = 22;
const R_PPC_LOCAL24PC = 23;
const R_PPC_UADDR32 = 24;
const R_PPC_UADDR16 = 25;
const R_PPC_REL32 = 26;
const R_PPC_PLT32 = 27;
const R_PPC_PLTREL32 = 28;
const R_PPC_PLT16_LO = 29;
const R_PPC_PLT16_HI = 30;
const R_PPC_PLT16_HA = 31;
const R_PPC_SDAREL16 = 32;
const R_PPC_SECTOFF = 33;
const R_PPC_SECTOFF_LO = 34;
const R_PPC_SECTOFF_HI = 35;
const R_PPC_SECTOFF_HA = 36;

/* PowerPC relocations defined for the TLS access ABI.  */
const R_PPC_TLS = 67; /* none  (sym+add)@tls */
const R_PPC_DTPMOD32 = 68; /* word32  (sym+add)@dtpmod */
const R_PPC_TPREL16 = 69; /* half16* (sym+add)@tprel */
const R_PPC_TPREL16_LO = 70; /* half16  (sym+add)@tprel@l */
const R_PPC_TPREL16_HI = 71; /* half16  (sym+add)@tprel@h */
const R_PPC_TPREL16_HA = 72; /* half16  (sym+add)@tprel@ha */
const R_PPC_TPREL32 = 73; /* word32  (sym+add)@tprel */
const R_PPC_DTPREL16 = 74; /* half16* (sym+add)@dtprel */
const R_PPC_DTPREL16_LO = 75; /* half16  (sym+add)@dtprel@l */
const R_PPC_DTPREL16_HI = 76; /* half16  (sym+add)@dtprel@h */
const R_PPC_DTPREL16_HA = 77; /* half16  (sym+add)@dtprel@ha */
const R_PPC_DTPREL32 = 78; /* word32  (sym+add)@dtprel */
const R_PPC_GOT_TLSGD16 = 79; /* half16* (sym+add)@got@tlsgd */
const R_PPC_GOT_TLSGD16_LO = 80; /* half16  (sym+add)@got@tlsgd@l */
const R_PPC_GOT_TLSGD16_HI = 81; /* half16  (sym+add)@got@tlsgd@h */
const R_PPC_GOT_TLSGD16_HA = 82; /* half16  (sym+add)@got@tlsgd@ha */
const R_PPC_GOT_TLSLD16 = 83; /* half16* (sym+add)@got@tlsld */
const R_PPC_GOT_TLSLD16_LO = 84; /* half16  (sym+add)@got@tlsld@l */
const R_PPC_GOT_TLSLD16_HI = 85; /* half16  (sym+add)@got@tlsld@h */
const R_PPC_GOT_TLSLD16_HA = 86; /* half16  (sym+add)@got@tlsld@ha */
const R_PPC_GOT_TPREL16 = 87; /* half16* (sym+add)@got@tprel */
const R_PPC_GOT_TPREL16_LO = 88; /* half16  (sym+add)@got@tprel@l */
const R_PPC_GOT_TPREL16_HI = 89; /* half16  (sym+add)@got@tprel@h */
const R_PPC_GOT_TPREL16_HA = 90; /* half16  (sym+add)@got@tprel@ha */
const R_PPC_GOT_DTPREL16 = 91; /* half16* (sym+add)@got@dtprel */
const R_PPC_GOT_DTPREL16_LO = 92; /* half16* (sym+add)@got@dtprel@l */
const R_PPC_GOT_DTPREL16_HI = 93; /* half16* (sym+add)@got@dtprel@h */
const R_PPC_GOT_DTPREL16_HA = 94; /* half16* (sym+add)@got@dtprel@ha */

/* Keep this the last entry.  */
const R_PPC_NUM = 95;

/* The remaining relocs are from the Embedded ELF ABI, and are not
   in the SVR4 ELF ABI.  */
const R_PPC_EMB_NADDR32 = 101;
const R_PPC_EMB_NADDR16 = 102;
const R_PPC_EMB_NADDR16_LO = 103;
const R_PPC_EMB_NADDR16_HI = 104;
const R_PPC_EMB_NADDR16_HA = 105;
const R_PPC_EMB_SDAI16 = 106;
const R_PPC_EMB_SDA2I16 = 107;
const R_PPC_EMB_SDA2REL = 108;
const R_PPC_EMB_SDA21 = 109; /* 16 bit offset in SDA */
const R_PPC_EMB_MRKREF = 110;
const R_PPC_EMB_RELSEC16 = 111;
const R_PPC_EMB_RELST_LO = 112;
const R_PPC_EMB_RELST_HI = 113;
const R_PPC_EMB_RELST_HA = 114;
const R_PPC_EMB_BIT_FLD = 115;
const R_PPC_EMB_RELSDA = 116; /* 16 bit relative offset in SDA */

/* Diab tool relocations.  */
const R_PPC_DIAB_SDA21_LO = 180; /* like EMB_SDA21, but lower 16 bit */
const R_PPC_DIAB_SDA21_HI = 181; /* like EMB_SDA21, but high 16 bit */
const R_PPC_DIAB_SDA21_HA = 182; /* like EMB_SDA21, adjusted high 16 */
const R_PPC_DIAB_RELSDA_LO = 183; /* like EMB_RELSDA, but lower 16 bit */
const R_PPC_DIAB_RELSDA_HI = 184; /* like EMB_RELSDA, but high 16 bit */
const R_PPC_DIAB_RELSDA_HA = 185; /* like EMB_RELSDA, adjusted high 16 */

/* GNU relocs used in PIC code sequences.  */
const R_PPC_REL16 = 249; /* word32   (sym-.) */
const R_PPC_REL16_LO = 250; /* half16   (sym-.)@l */
const R_PPC_REL16_HI = 251; /* half16   (sym-.)@h */
const R_PPC_REL16_HA = 252; /* half16   (sym-.)@ha */

/* This is a phony reloc to handle any old fashioned TOC16 references
   that may still be in object files.  */
const R_PPC_TOC16 = 255;

/* PowerPC specific values for the Dyn d_tag field.  */
const DT_PPC_GOT = (DT_LOPROC + 0);
const DT_PPC_NUM = 1;

/* PowerPC64 relocations defined by the ABIs */
const R_PPC64_NONE = R_PPC_NONE;
const R_PPC64_ADDR32 = R_PPC_ADDR32; /* 32bit absolute address */
const R_PPC64_ADDR24 = R_PPC_ADDR24; /* 26bit address, word aligned */
const R_PPC64_ADDR16 = R_PPC_ADDR16; /* 16bit absolute address */
const R_PPC64_ADDR16_LO = R_PPC_ADDR16_LO; /* lower 16bits of address */
const R_PPC64_ADDR16_HI = R_PPC_ADDR16_HI; /* high 16bits of address. */
const R_PPC64_ADDR16_HA = R_PPC_ADDR16_HA; /* adjusted high 16bits.  */
const R_PPC64_ADDR14 = R_PPC_ADDR14; /* 16bit address, word aligned */
const R_PPC64_ADDR14_BRTAKEN = R_PPC_ADDR14_BRTAKEN;
const R_PPC64_ADDR14_BRNTAKEN = R_PPC_ADDR14_BRNTAKEN;
const R_PPC64_REL24 = R_PPC_REL24; /* PC-rel. 26 bit, word aligned */
const R_PPC64_REL14 = R_PPC_REL14; /* PC relative 16 bit */
const R_PPC64_REL14_BRTAKEN = R_PPC_REL14_BRTAKEN;
const R_PPC64_REL14_BRNTAKEN = R_PPC_REL14_BRNTAKEN;
const R_PPC64_GOT16 = R_PPC_GOT16;
const R_PPC64_GOT16_LO = R_PPC_GOT16_LO;
const R_PPC64_GOT16_HI = R_PPC_GOT16_HI;
const R_PPC64_GOT16_HA = R_PPC_GOT16_HA;

const R_PPC64_COPY = R_PPC_COPY;
const R_PPC64_GLOB_DAT = R_PPC_GLOB_DAT;
const R_PPC64_JMP_SLOT = R_PPC_JMP_SLOT;
const R_PPC64_RELATIVE = R_PPC_RELATIVE;

const R_PPC64_UADDR32 = R_PPC_UADDR32;
const R_PPC64_UADDR16 = R_PPC_UADDR16;
const R_PPC64_REL32 = R_PPC_REL32;
const R_PPC64_PLT32 = R_PPC_PLT32;
const R_PPC64_PLTREL32 = R_PPC_PLTREL32;
const R_PPC64_PLT16_LO = R_PPC_PLT16_LO;
const R_PPC64_PLT16_HI = R_PPC_PLT16_HI;
const R_PPC64_PLT16_HA = R_PPC_PLT16_HA;

const R_PPC64_SECTOFF = R_PPC_SECTOFF;
const R_PPC64_SECTOFF_LO = R_PPC_SECTOFF_LO;
const R_PPC64_SECTOFF_HI = R_PPC_SECTOFF_HI;
const R_PPC64_SECTOFF_HA = R_PPC_SECTOFF_HA;
const R_PPC64_ADDR30 = 37; /* word30 (S + A - P) >> 2 */
const R_PPC64_ADDR64 = 38; /* doubleword64 S + A */
const R_PPC64_ADDR16_HIGHER = 39; /* half16 #higher(S + A) */
const R_PPC64_ADDR16_HIGHERA = 40; /* half16 #highera(S + A) */
const R_PPC64_ADDR16_HIGHEST = 41; /* half16 #highest(S + A) */
const R_PPC64_ADDR16_HIGHESTA = 42; /* half16 #highesta(S + A) */
const R_PPC64_UADDR64 = 43; /* doubleword64 S + A */
const R_PPC64_REL64 = 44; /* doubleword64 S + A - P */
const R_PPC64_PLT64 = 45; /* doubleword64 L + A */
const R_PPC64_PLTREL64 = 46; /* doubleword64 L + A - P */
const R_PPC64_TOC16 = 47; /* half16* S + A - .TOC */
const R_PPC64_TOC16_LO = 48; /* half16 #lo(S + A - .TOC.) */
const R_PPC64_TOC16_HI = 49; /* half16 #hi(S + A - .TOC.) */
const R_PPC64_TOC16_HA = 50; /* half16 #ha(S + A - .TOC.) */
const R_PPC64_TOC = 51; /* doubleword64 .TOC */
const R_PPC64_PLTGOT16 = 52; /* half16* M + A */
const R_PPC64_PLTGOT16_LO = 53; /* half16 #lo(M + A) */
const R_PPC64_PLTGOT16_HI = 54; /* half16 #hi(M + A) */
const R_PPC64_PLTGOT16_HA = 55; /* half16 #ha(M + A) */

const R_PPC64_ADDR16_DS = 56; /* half16ds* (S + A) >> 2 */
const R_PPC64_ADDR16_LO_DS = 57; /* half16ds  #lo(S + A) >> 2 */
const R_PPC64_GOT16_DS = 58; /* half16ds* (G + A) >> 2 */
const R_PPC64_GOT16_LO_DS = 59; /* half16ds  #lo(G + A) >> 2 */
const R_PPC64_PLT16_LO_DS = 60; /* half16ds  #lo(L + A) >> 2 */
const R_PPC64_SECTOFF_DS = 61; /* half16ds* (R + A) >> 2 */
const R_PPC64_SECTOFF_LO_DS = 62; /* half16ds  #lo(R + A) >> 2 */
const R_PPC64_TOC16_DS = 63; /* half16ds* (S + A - .TOC.) >> 2 */
const R_PPC64_TOC16_LO_DS = 64; /* half16ds  #lo(S + A - .TOC.) >> 2 */
const R_PPC64_PLTGOT16_DS = 65; /* half16ds* (M + A) >> 2 */
const R_PPC64_PLTGOT16_LO_DS = 66; /* half16ds  #lo(M + A) >> 2 */

/* PowerPC64 relocations defined for the TLS access ABI.  */
const R_PPC64_TLS = 67; /* none  (sym+add)@tls */
const R_PPC64_DTPMOD64 = 68; /* doubleword64 (sym+add)@dtpmod */
const R_PPC64_TPREL16 = 69; /* half16* (sym+add)@tprel */
const R_PPC64_TPREL16_LO = 70; /* half16  (sym+add)@tprel@l */
const R_PPC64_TPREL16_HI = 71; /* half16  (sym+add)@tprel@h */
const R_PPC64_TPREL16_HA = 72; /* half16  (sym+add)@tprel@ha */
const R_PPC64_TPREL64 = 73; /* doubleword64 (sym+add)@tprel */
const R_PPC64_DTPREL16 = 74; /* half16* (sym+add)@dtprel */
const R_PPC64_DTPREL16_LO = 75; /* half16  (sym+add)@dtprel@l */
const R_PPC64_DTPREL16_HI = 76; /* half16  (sym+add)@dtprel@h */
const R_PPC64_DTPREL16_HA = 77; /* half16  (sym+add)@dtprel@ha */
const R_PPC64_DTPREL64 = 78; /* doubleword64 (sym+add)@dtprel */
const R_PPC64_GOT_TLSGD16 = 79; /* half16* (sym+add)@got@tlsgd */
const R_PPC64_GOT_TLSGD16_LO = 80; /* half16  (sym+add)@got@tlsgd@l */
const R_PPC64_GOT_TLSGD16_HI = 81; /* half16  (sym+add)@got@tlsgd@h */
const R_PPC64_GOT_TLSGD16_HA = 82; /* half16  (sym+add)@got@tlsgd@ha */
const R_PPC64_GOT_TLSLD16 = 83; /* half16* (sym+add)@got@tlsld */
const R_PPC64_GOT_TLSLD16_LO = 84; /* half16  (sym+add)@got@tlsld@l */
const R_PPC64_GOT_TLSLD16_HI = 85; /* half16  (sym+add)@got@tlsld@h */
const R_PPC64_GOT_TLSLD16_HA = 86; /* half16  (sym+add)@got@tlsld@ha */
const R_PPC64_GOT_TPREL16_DS = 87; /* half16ds* (sym+add)@got@tprel */
const R_PPC64_GOT_TPREL16_LO_DS = 88; /* half16ds (sym+add)@got@tprel@l */
const R_PPC64_GOT_TPREL16_HI = 89; /* half16  (sym+add)@got@tprel@h */
const R_PPC64_GOT_TPREL16_HA = 90; /* half16  (sym+add)@got@tprel@ha */
const R_PPC64_GOT_DTPREL16_DS = 91; /* half16ds* (sym+add)@got@dtprel */
const R_PPC64_GOT_DTPREL16_LO_DS = 92; /* half16ds (sym+add)@got@dtprel@l */
const R_PPC64_GOT_DTPREL16_HI = 93; /* half16  (sym+add)@got@dtprel@h */
const R_PPC64_GOT_DTPREL16_HA = 94; /* half16  (sym+add)@got@dtprel@ha */
const R_PPC64_TPREL16_DS = 95; /* half16ds* (sym+add)@tprel */
const R_PPC64_TPREL16_LO_DS = 96; /* half16ds  (sym+add)@tprel@l */
const R_PPC64_TPREL16_HIGHER = 97; /* half16  (sym+add)@tprel@higher */
const R_PPC64_TPREL16_HIGHERA = 98; /* half16  (sym+add)@tprel@highera */
const R_PPC64_TPREL16_HIGHEST = 99; /* half16  (sym+add)@tprel@highest */
const R_PPC64_TPREL16_HIGHESTA = 100; /* half16  (sym+add)@tprel@highesta */
const R_PPC64_DTPREL16_DS = 101; /* half16ds* (sym+add)@dtprel */
const R_PPC64_DTPREL16_LO_DS = 102; /* half16ds (sym+add)@dtprel@l */
const R_PPC64_DTPREL16_HIGHER = 103; /* half16 (sym+add)@dtprel@higher */
const R_PPC64_DTPREL16_HIGHERA = 104; /* half16  (sym+add)@dtprel@highera */
const R_PPC64_DTPREL16_HIGHEST = 105; /* half16  (sym+add)@dtprel@highest */
const R_PPC64_DTPREL16_HIGHESTA = 106; /* half16 (sym+add)@dtprel@highesta */

/* Keep this the last entry.  */
const R_PPC64_NUM = 107;

/* PowerPC64 specific values for the Dyn d_tag field.  */
const DT_PPC64_GLINK = (DT_LOPROC + 0);
const DT_PPC64_OPD = (DT_LOPROC + 1);
const DT_PPC64_OPDSZ = (DT_LOPROC + 2);
const DT_PPC64_NUM = 3;

/* ARM specific declarations */

/* Processor specific flags for the ELF header e_flags field.  */
const EF_ARM_RELEXEC = 0x01;
const EF_ARM_HASENTRY = 0x02;
const EF_ARM_INTERWORK = 0x04;
const EF_ARM_APCS_26 = 0x08;
const EF_ARM_APCS_FLOAT = 0x10;
const EF_ARM_PIC = 0x20;
const EF_ARM_ALIGN8 = 0x40;   /* 8-bit structure alignment is in use */
const EF_ARM_NEW_ABI = 0x80;
const EF_ARM_OLD_ABI = 0x100;

/* Other constants defined in the ARM ELF spec. version B-01.  */
/* NB. These conflict with values defined above.  */
const EF_ARM_SYMSARESORTED = 0x04;
const EF_ARM_DYNSYMSUSESEGIDX = 0x08;
const EF_ARM_MAPSYMSFIRST = 0x10;
const EF_ARM_EABIMASK = 0XFF000000;

// const EF_ARM_EABI_VERSION(flags) = ((flags); & EF_ARM_EABIMASK)
const EF_ARM_EABI_UNKNOWN = 0x00000000;
const EF_ARM_EABI_VER1 = 0x01000000;
const EF_ARM_EABI_VER2 = 0x02000000;

/* Additional symbol types for Thumb */
const STT_ARM_TFUNC = 0xd;

/* ARM-specific values for sh_flags */
const SHF_ARM_ENTRYSECT = 0x10000000;   /* Section contains an entry point */
const SHF_ARM_COMDEF = 0x80000000;   /* Section may be multiply defined
                                        in the input to a link step */

/* ARM-specific program header flags */
const PF_ARM_SB = 0x10000000;   /* Segment contains the location
                                   addressed by the static base */

/* Processor specific values for the Phdr p_type field.  */
const PT_ARM_EXIDX = 0x70000001;  /* .ARM.exidx segment */

/* ARM relocs.  */

const R_ARM_NONE = 0; /* No reloc */
const R_ARM_PC24 = 1; /* PC relative 26 bit branch */
const R_ARM_ABS32 = 2; /* Direct 32 bit  */
const R_ARM_REL32 = 3; /* PC relative 32 bit */
const R_ARM_PC13 = 4;
const R_ARM_ABS16 = 5; /* Direct 16 bit */
const R_ARM_ABS12 = 6; /* Direct 12 bit */
const R_ARM_THM_ABS5 = 7;
const R_ARM_ABS8 = 8; /* Direct 8 bit */
const R_ARM_SBREL32 = 9;
const R_ARM_THM_PC22 = 10;
const R_ARM_THM_PC8 = 11;
const R_ARM_AMP_VCALL9 = 12;
const R_ARM_SWI24 = 13;
const R_ARM_THM_SWI8 = 14;
const R_ARM_XPC25 = 15;
const R_ARM_THM_XPC22 = 16;
const R_ARM_TLS_DTPMOD32 = 17;  /* ID of module containing symbol */
const R_ARM_TLS_DTPOFF32 = 18;  /* Offset in TLS block */
const R_ARM_TLS_TPOFF32 = 19;  /* Offset in static TLS block */
const R_ARM_COPY = 20;  /* Copy symbol at runtime */
const R_ARM_GLOB_DAT = 21;  /* Create GOT entry */
const R_ARM_JUMP_SLOT = 22;  /* Create PLT entry */
const R_ARM_RELATIVE = 23;  /* Adjust by program base */
const R_ARM_GOTOFF = 24;  /* 32 bit offset to GOT */
const R_ARM_GOTPC = 25;  /* 32 bit PC relative offset to GOT */
const R_ARM_GOT32 = 26;  /* 32 bit GOT entry */
const R_ARM_PLT32 = 27;  /* 32 bit PLT address */
const R_ARM_ALU_PCREL_7_0 = 32;
const R_ARM_ALU_PCREL_15_8 = 33;
const R_ARM_ALU_PCREL_23_15 = 34;
const R_ARM_LDR_SBREL_11_0 = 35;
const R_ARM_ALU_SBREL_19_12 = 36;
const R_ARM_ALU_SBREL_27_20 = 37;
const R_ARM_GNU_VTENTRY = 100;
const R_ARM_GNU_VTINHERIT = 101;
const R_ARM_THM_PC11 = 102; /* thumb unconditional branch */
const R_ARM_THM_PC9 = 103; /* thumb conditional branch */
const R_ARM_TLS_GD32 = 104; /* PC-rel 32 bit for global dynamic
                               thread local data */
const R_ARM_TLS_LDM32 = 105; /* PC-rel 32 bit for local dynamic
                                thread local data */
const R_ARM_TLS_LDO32 = 106; /* 32 bit offset relative to TLS
                                block */
const R_ARM_TLS_IE32 = 107; /* PC-rel 32 bit for GOT entry of
                               static TLS block offset */
const R_ARM_TLS_LE32 = 108; /* 32 bit offset relative to static
                               TLS block */
const R_ARM_RXPC25 = 249;
const R_ARM_RSBREL32 = 250;
const R_ARM_THM_RPC22 = 251;
const R_ARM_RREL32 = 252;
const R_ARM_RABS22 = 253;
const R_ARM_RPC24 = 254;
const R_ARM_RBASE = 255;
/* Keep this the last entry.  */
const R_ARM_NUM = 256;

/* IA-64 specific declarations.  */

/* Processor specific flags for the Ehdr e_flags field.  */
const EF_IA_64_MASKOS = 0x0000000f;  /* os-specific flags */
const EF_IA_64_ABI64 = 0x00000010;  /* 64-bit ABI */
const EF_IA_64_ARCH = 0xff000000;  /* arch. version mask */

/* Processor specific values for the Phdr p_type field.  */
const PT_IA_64_ARCHEXT = (PT_LOPROC + 0) /* arch extension bits */;
const PT_IA_64_UNWIND = (PT_LOPROC + 1) /* ia64 unwind bits */;
const PT_IA_64_HP_OPT_ANOT = (PT_LOOS + 0x12);
const PT_IA_64_HP_HSL_ANOT = (PT_LOOS + 0x13);
const PT_IA_64_HP_STACK = (PT_LOOS + 0x14);

/* Processor specific flags for the Phdr p_flags field.  */
const PF_IA_64_NORECOV = 0x80000000;  /* spec insns w/o recovery */

/* Processor specific values for the Shdr sh_type field.  */
const SHT_IA_64_EXT = (SHT_LOPROC + 0); /* extension bits */
const SHT_IA_64_UNWIND = (SHT_LOPROC + 1); /* unwind bits */

/* Processor specific flags for the Shdr sh_flags field.  */
const SHF_IA_64_SHORT = 0x10000000;  /* section near gp */
const SHF_IA_64_NORECOV = 0x20000000;  /* spec insns w/o recovery */

/* Processor specific values for the Dyn d_tag field.  */
const DT_IA_64_PLT_RESERVE = (DT_LOPROC + 0);
const DT_IA_64_NUM = 1;

/* IA-64 relocations.  */
const R_IA64_NONE = 0x00;  /* none */
const R_IA64_IMM14 = 0x21;  /* symbol + addend, add imm14 */
const R_IA64_IMM22 = 0x22;  /* symbol + addend, add imm22 */
const R_IA64_IMM64 = 0x23;  /* symbol + addend, mov imm64 */
const R_IA64_DIR32MSB = 0x24;  /* symbol + addend, data4 MSB */
const R_IA64_DIR32LSB = 0x25;  /* symbol + addend, data4 LSB */
const R_IA64_DIR64MSB = 0x26;  /* symbol + addend, data8 MSB */
const R_IA64_DIR64LSB = 0x27;  /* symbol + addend, data8 LSB */
const R_IA64_GPREL22 = 0x2a;  /* @gprel(sym + add), add imm22 */
const R_IA64_GPREL64I = 0x2b;  /* @gprel(sym + add), mov imm64 */
const R_IA64_GPREL32MSB = 0x2c;  /* @gprel(sym + add), data4 MSB */
const R_IA64_GPREL32LSB = 0x2d;  /* @gprel(sym + add), data4 LSB */
const R_IA64_GPREL64MSB = 0x2e;  /* @gprel(sym + add), data8 MSB */
const R_IA64_GPREL64LSB = 0x2f;  /* @gprel(sym + add), data8 LSB */
const R_IA64_LTOFF22 = 0x32;  /* @ltoff(sym + add), add imm22 */
const R_IA64_LTOFF64I = 0x33;  /* @ltoff(sym + add), mov imm64 */
const R_IA64_PLTOFF22 = 0x3a;  /* @pltoff(sym + add), add imm22 */
const R_IA64_PLTOFF64I = 0x3b;  /* @pltoff(sym + add), mov imm64 */
const R_IA64_PLTOFF64MSB = 0x3e;  /* @pltoff(sym + add), data8 MSB */
const R_IA64_PLTOFF64LSB = 0x3f;  /* @pltoff(sym + add), data8 LSB */
const R_IA64_FPTR64I = 0x43;  /* @fptr(sym + add), mov imm64 */
const R_IA64_FPTR32MSB = 0x44;  /* @fptr(sym + add), data4 MSB */
const R_IA64_FPTR32LSB = 0x45;  /* @fptr(sym + add), data4 LSB */
const R_IA64_FPTR64MSB = 0x46;  /* @fptr(sym + add), data8 MSB */
const R_IA64_FPTR64LSB = 0x47;  /* @fptr(sym + add), data8 LSB */
const R_IA64_PCREL60B = 0x48;  /* @pcrel(sym + add), brl */
const R_IA64_PCREL21B = 0x49;  /* @pcrel(sym + add), ptb, call */
const R_IA64_PCREL21M = 0x4a;  /* @pcrel(sym + add), chk.s */
const R_IA64_PCREL21F = 0x4b;  /* @pcrel(sym + add), fchkf */
const R_IA64_PCREL32MSB = 0x4c;  /* @pcrel(sym + add), data4 MSB */
const R_IA64_PCREL32LSB = 0x4d;  /* @pcrel(sym + add), data4 LSB */
const R_IA64_PCREL64MSB = 0x4e;  /* @pcrel(sym + add), data8 MSB */
const R_IA64_PCREL64LSB = 0x4f;  /* @pcrel(sym + add), data8 LSB */
const R_IA64_LTOFF_FPTR22 = 0x52;  /* @ltoff(@fptr(s+a)), imm22 */
const R_IA64_LTOFF_FPTR64I = 0x53;  /* @ltoff(@fptr(s+a)), imm64 */
const R_IA64_LTOFF_FPTR32MSB = 0x54;  /* @ltoff(@fptr(s+a)), data4 MSB */
const R_IA64_LTOFF_FPTR32LSB = 0x55;  /* @ltoff(@fptr(s+a)), data4 LSB */
const R_IA64_LTOFF_FPTR64MSB = 0x56;  /* @ltoff(@fptr(s+a)), data8 MSB */
const R_IA64_LTOFF_FPTR64LSB = 0x57;  /* @ltoff(@fptr(s+a)), data8 LSB */
const R_IA64_SEGREL32MSB = 0x5c;  /* @segrel(sym + add), data4 MSB */
const R_IA64_SEGREL32LSB = 0x5d;  /* @segrel(sym + add), data4 LSB */
const R_IA64_SEGREL64MSB = 0x5e;  /* @segrel(sym + add), data8 MSB */
const R_IA64_SEGREL64LSB = 0x5f;  /* @segrel(sym + add), data8 LSB */
const R_IA64_SECREL32MSB = 0x64;  /* @secrel(sym + add), data4 MSB */
const R_IA64_SECREL32LSB = 0x65;  /* @secrel(sym + add), data4 LSB */
const R_IA64_SECREL64MSB = 0x66;  /* @secrel(sym + add), data8 MSB */
const R_IA64_SECREL64LSB = 0x67;  /* @secrel(sym + add), data8 LSB */
const R_IA64_REL32MSB = 0x6c;  /* data 4 + REL */
const R_IA64_REL32LSB = 0x6d;  /* data 4 + REL */
const R_IA64_REL64MSB = 0x6e;  /* data 8 + REL */
const R_IA64_REL64LSB = 0x6f;  /* data 8 + REL */
const R_IA64_LTV32MSB = 0x74;  /* symbol + addend, data4 MSB */
const R_IA64_LTV32LSB = 0x75;  /* symbol + addend, data4 LSB */
const R_IA64_LTV64MSB = 0x76;  /* symbol + addend, data8 MSB */
const R_IA64_LTV64LSB = 0x77;  /* symbol + addend, data8 LSB */
const R_IA64_PCREL21BI = 0x79;  /* @pcrel(sym + add), 21bit inst */
const R_IA64_PCREL22 = 0x7a;  /* @pcrel(sym + add), 22bit inst */
const R_IA64_PCREL64I = 0x7b;  /* @pcrel(sym + add), 64bit inst */
const R_IA64_IPLTMSB = 0x80;  /* dynamic reloc, imported PLT, MSB */
const R_IA64_IPLTLSB = 0x81;  /* dynamic reloc, imported PLT, LSB */
const R_IA64_COPY = 0x84;  /* copy relocation */
const R_IA64_SUB = 0x85;  /* Addend and symbol difference */
const R_IA64_LTOFF22X = 0x86;  /* LTOFF22, relaxable.  */
const R_IA64_LDXMOV = 0x87;  /* Use of LTOFF22X.  */
const R_IA64_TPREL14 = 0x91;  /* @tprel(sym + add), imm14 */
const R_IA64_TPREL22 = 0x92;  /* @tprel(sym + add), imm22 */
const R_IA64_TPREL64I = 0x93;  /* @tprel(sym + add), imm64 */
const R_IA64_TPREL64MSB = 0x96;  /* @tprel(sym + add), data8 MSB */
const R_IA64_TPREL64LSB = 0x97;  /* @tprel(sym + add), data8 LSB */
const R_IA64_LTOFF_TPREL22 = 0x9a;  /* @ltoff(@tprel(s+a)), imm2 */
const R_IA64_DTPMOD64MSB = 0xa6;  /* @dtpmod(sym + add), data8 MSB */
const R_IA64_DTPMOD64LSB = 0xa7;  /* @dtpmod(sym + add), data8 LSB */
const R_IA64_LTOFF_DTPMOD22 = 0xaa;  /* @ltoff(@dtpmod(sym + add)), imm22 */
const R_IA64_DTPREL14 = 0xb1;  /* @dtprel(sym + add), imm14 */
const R_IA64_DTPREL22 = 0xb2;  /* @dtprel(sym + add), imm22 */
const R_IA64_DTPREL64I = 0xb3;  /* @dtprel(sym + add), imm64 */
const R_IA64_DTPREL32MSB = 0xb4;  /* @dtprel(sym + add), data4 MSB */
const R_IA64_DTPREL32LSB = 0xb5;  /* @dtprel(sym + add), data4 LSB */
const R_IA64_DTPREL64MSB = 0xb6;  /* @dtprel(sym + add), data8 MSB */
const R_IA64_DTPREL64LSB = 0xb7;  /* @dtprel(sym + add), data8 LSB */
const R_IA64_LTOFF_DTPREL22 = 0xba;  /* @ltoff(@dtprel(s+a)), imm22 */

/* SH specific declarations */

/* SH relocs.  */
const R_SH_NONE = 0;
const R_SH_DIR32 = 1;
const R_SH_REL32 = 2;
const R_SH_DIR8WPN = 3;
const R_SH_IND12W = 4;
const R_SH_DIR8WPL = 5;
const R_SH_DIR8WPZ = 6;
const R_SH_DIR8BP = 7;
const R_SH_DIR8W = 8;
const R_SH_DIR8L = 9;
const R_SH_SWITCH16 = 25;
const R_SH_SWITCH32 = 26;
const R_SH_USES = 27;
const R_SH_COUNT = 28;
const R_SH_ALIGN = 29;
const R_SH_CODE = 30;
const R_SH_DATA = 31;
const R_SH_LABEL = 32;
const R_SH_SWITCH8 = 33;
const R_SH_GNU_VTINHERIT = 34;
const R_SH_GNU_VTENTRY = 35;
const R_SH_TLS_GD_32 = 144;
const R_SH_TLS_LD_32 = 145;
const R_SH_TLS_LDO_32 = 146;
const R_SH_TLS_IE_32 = 147;
const R_SH_TLS_LE_32 = 148;
const R_SH_TLS_DTPMOD32 = 149;
const R_SH_TLS_DTPOFF32 = 150;
const R_SH_TLS_TPOFF32 = 151;
const R_SH_GOT32 = 160;
const R_SH_PLT32 = 161;
const R_SH_COPY = 162;
const R_SH_GLOB_DAT = 163;
const R_SH_JMP_SLOT = 164;
const R_SH_RELATIVE = 165;
const R_SH_GOTOFF = 166;
const R_SH_GOTPC = 167;
/* Keep this the last entry.  */
const R_SH_NUM = 256;

/* Additional s390 relocs */

const R_390_NONE = 0; /* No reloc.  */
const R_390_8 = 1; /* Direct 8 bit.  */
const R_390_12 = 2; /* Direct 12 bit.  */
const R_390_16 = 3; /* Direct 16 bit.  */
const R_390_32 = 4; /* Direct 32 bit.  */
const R_390_PC32 = 5; /* PC relative 32 bit.  */
const R_390_GOT12 = 6; /* 12 bit GOT offset.  */
const R_390_GOT32 = 7; /* 32 bit GOT offset.  */
const R_390_PLT32 = 8; /* 32 bit PC relative PLT address.  */
const R_390_COPY = 9; /* Copy symbol at runtime.  */
const R_390_GLOB_DAT = 10;  /* Create GOT entry.  */
const R_390_JMP_SLOT = 11;  /* Create PLT entry.  */
const R_390_RELATIVE = 12;  /* Adjust by program base.  */
const R_390_GOTOFF32 = 13;  /* 32 bit offset to GOT.   */
const R_390_GOTPC = 14;  /* 32 bit PC relative offset to GOT.  */
const R_390_GOT16 = 15;  /* 16 bit GOT offset.  */
const R_390_PC16 = 16;  /* PC relative 16 bit.  */
const R_390_PC16DBL = 17;  /* PC relative 16 bit shifted by 1.  */
const R_390_PLT16DBL = 18;  /* 16 bit PC rel. PLT shifted by 1.  */
const R_390_PC32DBL = 19;  /* PC relative 32 bit shifted by 1.  */
const R_390_PLT32DBL = 20;  /* 32 bit PC rel. PLT shifted by 1.  */
const R_390_GOTPCDBL = 21;  /* 32 bit PC rel. GOT shifted by 1.  */
const R_390_64 = 22;  /* Direct 64 bit.  */
const R_390_PC64 = 23;  /* PC relative 64 bit.  */
const R_390_GOT64 = 24;  /* 64 bit GOT offset.  */
const R_390_PLT64 = 25;  /* 64 bit PC relative PLT address.  */
const R_390_GOTENT = 26;  /* 32 bit PC rel. to GOT entry >> 1. */
const R_390_GOTOFF16 = 27;  /* 16 bit offset to GOT. */
const R_390_GOTOFF64 = 28;  /* 64 bit offset to GOT. */
const R_390_GOTPLT12 = 29;  /* 12 bit offset to jump slot.  */
const R_390_GOTPLT16 = 30;  /* 16 bit offset to jump slot.  */
const R_390_GOTPLT32 = 31;  /* 32 bit offset to jump slot.  */
const R_390_GOTPLT64 = 32;  /* 64 bit offset to jump slot.  */
const R_390_GOTPLTENT = 33;  /* 32 bit rel. offset to jump slot.  */
const R_390_PLTOFF16 = 34;  /* 16 bit offset from GOT to PLT. */
const R_390_PLTOFF32 = 35;  /* 32 bit offset from GOT to PLT. */
const R_390_PLTOFF64 = 36;  /* 16 bit offset from GOT to PLT. */
const R_390_TLS_LOAD = 37;  /* Tag for load insn in TLS code.  */
const R_390_TLS_GDCALL = 38;  /* Tag for function call in general dynamic TLS code. */
const R_390_TLS_LDCALL = 39;  /* Tag for function call in local dynamic TLS code. */
const R_390_TLS_GD32 = 40;  /* Direct 32 bit for general dynamic thread local data.  */
const R_390_TLS_GD64 = 41;  /* Direct 64 bit for general dynamic thread local data.  */
const R_390_TLS_GOTIE12 = 42;  /* 12 bit GOT offset for static TLS block offset.  */
const R_390_TLS_GOTIE32 = 43;  /* 32 bit GOT offset for static TLS block offset.  */
const R_390_TLS_GOTIE64 = 44;  /* 64 bit GOT offset for static TLS block offset. */
const R_390_TLS_LDM32 = 45;  /* Direct 32 bit for local dynamic thread local data in LE code.  */
const R_390_TLS_LDM64 = 46;  /* Direct 64 bit for local dynamic thread local data in LE code.  */
const R_390_TLS_IE32 = 47;  /* 32 bit address of GOT entry for negated static TLS block offset.  */
const R_390_TLS_IE64 = 48;  /* 64 bit address of GOT entry for negated static TLS block offset.  */
const R_390_TLS_IEENT = 49;  /* 32 bit rel. offset to GOT entry for negated static TLS block offset.  */
const R_390_TLS_LE32 = 50;  /* 32 bit negated offset relative to static TLS block.  */
const R_390_TLS_LE64 = 51;  /* 64 bit negated offset relative to static TLS block.  */
const R_390_TLS_LDO32 = 52;  /* 32 bit offset relative to TLS block.  */
const R_390_TLS_LDO64 = 53;  /* 64 bit offset relative to TLS block.  */
const R_390_TLS_DTPMOD = 54;  /* ID of module containing symbol.  */
const R_390_TLS_DTPOFF = 55;  /* Offset in TLS block.  */
const R_390_TLS_TPOFF = 56;  /* Negated offset in static TLS block.  */
const R_390_20 = 57;  /* Direct 20 bit.  */
const R_390_GOT20 = 58;  /* 20 bit GOT offset.  */
const R_390_GOTPLT20 = 59;  /* 20 bit offset to jump slot.  */
const R_390_TLS_GOTIE20 = 60;  /* 20 bit GOT offset for static TLS
                                  block offset.  */
/* Keep this the last entry.  */
const R_390_NUM = 61;

/* CRIS relocations.  */
const R_CRIS_NONE = 0;
const R_CRIS_8 = 1;
const R_CRIS_16 = 2;
const R_CRIS_32 = 3;
const R_CRIS_8_PCREL = 4;
const R_CRIS_16_PCREL = 5;
const R_CRIS_32_PCREL = 6;
const R_CRIS_GNU_VTINHERIT = 7;
const R_CRIS_GNU_VTENTRY = 8;
const R_CRIS_COPY = 9;
const R_CRIS_GLOB_DAT = 10;
const R_CRIS_JUMP_SLOT = 11;
const R_CRIS_RELATIVE = 12;
const R_CRIS_16_GOT = 13;
const R_CRIS_32_GOT = 14;
const R_CRIS_16_GOTPLT = 15;
const R_CRIS_32_GOTPLT = 16;
const R_CRIS_32_GOTREL = 17;
const R_CRIS_32_PLT_GOTREL = 18;
const R_CRIS_32_PLT_PCREL = 19;

const R_CRIS_NUM = 20;

/* AMD x86-64 relocations.  */
const R_X86_64_NONE = 0; /* No reloc */
const R_X86_64_64 = 1; /* Direct 64 bit  */
const R_X86_64_PC32 = 2; /* PC relative 32 bit signed */
const R_X86_64_GOT32 = 3; /* 32 bit GOT entry */
const R_X86_64_PLT32 = 4; /* 32 bit PLT address */
const R_X86_64_COPY = 5; /* Copy symbol at runtime */
const R_X86_64_GLOB_DAT = 6; /* Create GOT entry */
const R_X86_64_JUMP_SLOT = 7; /* Create PLT entry */
const R_X86_64_RELATIVE = 8; /* Adjust by program base */
const R_X86_64_GOTPCREL = 9; /* 32 bit signed PC relative
                                offset to GOT */
const R_X86_64_32 = 10;  /* Direct 32 bit zero extended */
const R_X86_64_32S = 11;  /* Direct 32 bit sign extended */
const R_X86_64_16 = 12;  /* Direct 16 bit zero extended */
const R_X86_64_PC16 = 13;  /* 16 bit sign extended pc relative */
const R_X86_64_8 = 14;  /* Direct 8 bit sign extended  */
const R_X86_64_PC8 = 15;  /* 8 bit sign extended pc relative */
const R_X86_64_DTPMOD64 = 16;  /* ID of module containing symbol */
const R_X86_64_DTPOFF64 = 17;  /* Offset in module's TLS block */
const R_X86_64_TPOFF64 = 18;  /* Offset in initial TLS block */
const R_X86_64_TLSGD = 19;  /* 32 bit signed PC relative offset
                               to two GOT entries for GD symbol */
const R_X86_64_TLSLD = 20;  /* 32 bit signed PC relative offset
                               to two GOT entries for LD symbol */
const R_X86_64_DTPOFF32 = 21;  /* Offset in TLS block */
const R_X86_64_GOTTPOFF = 22;  /* 32 bit signed PC relative offset
                                  to GOT entry for IE symbol */
const R_X86_64_TPOFF32 = 23;  /* Offset in initial TLS block */

const R_X86_64_NUM = 24;

/* AM33 relocations.  */
const R_MN10300_NONE = 0; /* No reloc.  */
const R_MN10300_32 = 1; /* Direct 32 bit.  */
const R_MN10300_16 = 2; /* Direct 16 bit.  */
const R_MN10300_8 = 3; /* Direct 8 bit.  */
const R_MN10300_PCREL32 = 4; /* PC-relative 32-bit.  */
const R_MN10300_PCREL16 = 5; /* PC-relative 16-bit signed.  */
const R_MN10300_PCREL8 = 6; /* PC-relative 8-bit signed.  */
const R_MN10300_GNU_VTINHERIT = 7; /* Ancient C++ vtable garbage... */
const R_MN10300_GNU_VTENTRY = 8; /* ... collection annotation.  */
const R_MN10300_24 = 9; /* Direct 24 bit.  */
const R_MN10300_GOTPC32 = 10;  /* 32-bit PCrel offset to GOT.  */
const R_MN10300_GOTPC16 = 11;  /* 16-bit PCrel offset to GOT.  */
const R_MN10300_GOTOFF32 = 12;  /* 32-bit offset from GOT.  */
const R_MN10300_GOTOFF24 = 13;  /* 24-bit offset from GOT.  */
const R_MN10300_GOTOFF16 = 14;  /* 16-bit offset from GOT.  */
const R_MN10300_PLT32 = 15;  /* 32-bit PCrel to PLT entry.  */
const R_MN10300_PLT16 = 16;  /* 16-bit PCrel to PLT entry.  */
const R_MN10300_GOT32 = 17;  /* 32-bit offset to GOT entry.  */
const R_MN10300_GOT24 = 18;  /* 24-bit offset to GOT entry.  */
const R_MN10300_GOT16 = 19;  /* 16-bit offset to GOT entry.  */
const R_MN10300_COPY = 20;  /* Copy symbol at runtime.  */
const R_MN10300_GLOB_DAT = 21;  /* Create GOT entry.  */
const R_MN10300_JMP_SLOT = 22;  /* Create PLT entry.  */
const R_MN10300_RELATIVE = 23;  /* Adjust by program base.  */

const R_MN10300_NUM = 24;

/* M32R relocs.  */
const R_M32R_NONE = 0; /* No reloc. */
const R_M32R_16 = 1; /* Direct 16 bit. */
const R_M32R_32 = 2; /* Direct 32 bit. */
const R_M32R_24 = 3; /* Direct 24 bit. */
const R_M32R_10_PCREL = 4; /* PC relative 10 bit shifted. */
const R_M32R_18_PCREL = 5; /* PC relative 18 bit shifted. */
const R_M32R_26_PCREL = 6; /* PC relative 26 bit shifted. */
const R_M32R_HI16_ULO = 7; /* High 16 bit with ulow. */
const R_M32R_HI16_SLO = 8; /* High 16 bit with signed low. */
const R_M32R_LO16 = 9; /* Low 16 bit. */
const R_M32R_SDA16 = 10;  /* 16 bit offset in SDA. */
const R_M32R_GNU_VTINHERIT = 11;
const R_M32R_GNU_VTENTRY = 12;
/* M32R relocs use SHT_RELA.  */
const R_M32R_16_RELA = 33;  /* Direct 16 bit. */
const R_M32R_32_RELA = 34;  /* Direct 32 bit. */
const R_M32R_24_RELA = 35;  /* Direct 24 bit. */
const R_M32R_10_PCREL_RELA = 36;  /* PC relative 10 bit shifted. */
const R_M32R_18_PCREL_RELA = 37;  /* PC relative 18 bit shifted. */
const R_M32R_26_PCREL_RELA = 38;  /* PC relative 26 bit shifted. */
const R_M32R_HI16_ULO_RELA = 39;  /* High 16 bit with ulow */
const R_M32R_HI16_SLO_RELA = 40;  /* High 16 bit with signed low */
const R_M32R_LO16_RELA = 41;  /* Low 16 bit */
const R_M32R_SDA16_RELA = 42;  /* 16 bit offset in SDA */
const R_M32R_RELA_GNU_VTINHERIT = 43;
const R_M32R_RELA_GNU_VTENTRY = 44;
const R_M32R_REL32 = 45;  /* PC relative 32 bit.  */

const R_M32R_GOT24 = 48;          /* 24 bit GOT entry */
const R_M32R_26_PLTREL = 49;      /* 26 bit PC relative to PLT shifted */
const R_M32R_COPY = 50;           /* Copy symbol at runtime */
const R_M32R_GLOB_DAT = 51;       /* Create GOT entry */
const R_M32R_JMP_SLOT = 52;       /* Create PLT entry */
const R_M32R_RELATIVE = 53;       /* Adjust by program base */
const R_M32R_GOTOFF = 54;         /* 24 bit offset to GOT */
const R_M32R_GOTPC24 = 55;        /* 24 bit PC relative offset to GOT */
const R_M32R_GOT16_HI_ULO = 56;   /* High 16 bit GOT entry with unsigned low */
const R_M32R_GOT16_HI_SLO = 57;   /* High 16 bit GOT entry with signed low */
const R_M32R_GOT16_LO = 58;       /* Low 16 bit GOT entry */
const R_M32R_GOTPC_HI_ULO = 59;   /* High 16 bit PC relative offset to GOT with ulow */
const R_M32R_GOTPC_HI_SLO = 60;   /* High 16 bit PC relative offset to GOT with signed low */
const R_M32R_GOTPC_LO = 61;       /* Low 16 bit PC relative offset to GOT */
const R_M32R_GOTOFF_HI_ULO = 62;  /* High 16 bit offset to GOT with ulow */
const R_M32R_GOTOFF_HI_SLO = 63;  /* High 16 bit offset to GOT with signed low */
const R_M32R_GOTOFF_LO = 64;      /* Low 16 bit offset to GOT */
const R_M32R_NUM = 256;           /* Keep this the last entry. */

