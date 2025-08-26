from keystone import *

ks = Ks(KS_ARCH_X86, KS_MODE_64)

CODE = """
start:
    mov rax, 1
    jmp inject

inject:
    nop
    nop
    jmp middle

middle:
    add rax, 2
    jnz end

end:
    ret
"""

encoding, _ = ks.asm(CODE, as_bytes=True)
print("Machine code:", encoding.hex())