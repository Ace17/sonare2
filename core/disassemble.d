import arch;
import document;
import std.algorithm: map;
import std.array: join;
import std.format;

void cmd_disassemble(Document doc)
{
  auto arch = g_Architectures.get(doc.arch);
  arch.disassemble(doc);

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

