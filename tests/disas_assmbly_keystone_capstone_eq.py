from capstone import *
from keystone import *

# Sample machine code (x86-64)
CODE = b"\x48\x89\xd8\xc3"   # mov rax, rbx; ret

# Step 1: Disassemble with Capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(CODE, 0x1000):
    print("Disassembled:", insn.mnemonic, insn.op_str)
    asm_str = f"{insn.mnemonic} {insn.op_str}".strip()

    # Step 2: Assemble back with Keystone
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, _ = ks.asm(asm_str)

    print("  Re-assembled:", asm_str)
    print("  Bytes:", encoding)