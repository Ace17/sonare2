import arch;
import document;
import std.algorithm: map;
import std.array: join;
import std.format;

void cmd_disassemble(Document doc)
{
  auto arch = g_Architectures.get(doc.arch);

  {
    int pc = cast(int)doc.address;
    int i = 0;

    while(i < cast(int)doc.data.length)
    {
      auto instruction = arch.disassemble(doc.data[i .. $], pc);
      const size = instruction.bytes.length;

      if(!size)
        break;

      doc.instructions ~= instruction;

      i += size;
      pc += size;
    }
  }

  doc.symbols[doc.entryPoint] = "entry0";

  int labelCount;

  // basic code xrefs
  foreach(instruction; doc.instructions)
  {
    if(instruction.type == Type.Jump || instruction.type == Type.Call)
    {
      foreach(c; join(map!allConstants(instruction.operands)))
        doc.symbols[c] = format("_%s", labelCount++);
    }
  }
}

ulong[] allConstants(Expr e)
{
  if(auto n = cast(NumberExpr)e)
  {
    return [n.value];
  }
  else if(auto i = cast(IdentifierExpr)e)
  {
    return [];
  }
  else if(auto d = cast(DerefExpr)e)
  {
    return allConstants(d.sub);
  }
  else
  {
    return [];
  }
}

