import arch;
import document;

void cmd_disassemble(Document doc)
{
  auto arch = g_Architectures.get(doc.arch);
  arch.disassemble(doc);
}

