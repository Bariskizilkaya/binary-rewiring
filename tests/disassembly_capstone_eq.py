from capstone import *
from elftools.elf.elffile import ELFFile

ko_file = "./kernel_module/hello.ko"


with open(ko_file, "rb") as f:
    elffile = ELFFile(f)

    # Get .init.text section
    text_section = elffile.get_section_by_name(".init.text")
    code = text_section.data()
    addr = text_section['sh_addr']

    # Load relocations for .init.text
    relocs = {}
    for section in elffile.iter_sections():
        if section.header['sh_type'] in ('SHT_REL', 'SHT_RELA'):
            if elffile.get_section(section['sh_info']).name == ".init.text":
                for rel in section.iter_relocations():
                    sym_idx = rel.entry['r_info_sym']
                    sym = elffile.get_section(section['sh_link']).get_symbol(sym_idx)
                    relocs[rel.entry['r_offset']] = sym.name

    # Init capstone (x86_64)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    print("Disassembly of .init.text with relocations:")
    for insn in md.disasm(code, addr):
        line = "0x%x:\t%-6s\t%s" % (insn.address, insn.mnemonic, insn.op_str)
        # If instruction has relocation
        if insn.address - addr in relocs:
            line += "   ; reloc -> %s" % relocs[insn.address - addr]
        print(line)
