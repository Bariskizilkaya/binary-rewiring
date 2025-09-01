from elftools.elf.elffile import ELFFile

# Open the ELF binary
with open("your_binary.elf", "rb") as f:
    elf = ELFFile(f)

    # Iterate through all sections
    for section in elf.iter_sections():
        print(f"Section: {section.name}")
        print(f"  Type: {section['sh_type']}")
        print(f"  Size: {section['sh_size']} bytes")
        print(f"  Address: {hex(section['sh_addr'])}")

        # If you want the raw data of a section
        data = section.data()
        print(f"  First 16 bytes: {data[:16].hex()}\n")