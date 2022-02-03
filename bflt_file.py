import struct
import sys

# 0 -> 0
# 4 -> 1
# 8 -> 2
# c -> 3

# op 0 is .text halfword fixup. add the base address to the little-endian halfword found at load_addr + 26 bit offset

# op 1 is .text halfword zero, unless the preceeding relocation is of type 3. In that case, set hw @ load_addr + offset 
# to the 26 bit value in the previous reloc. Otherwise (i.e. type 1 by itself), set hw @ load_addr + offset to 0.

# op 2 is .data word (32 bit) pointer fixup. set littl-endian w32 @ load_addr + offset to itself + load_addr

# There might be other relocation op modes that account for offsets that require greater than 26 bits to represent.
# since they must be 2 or 4 byte aligned, could have some kind of shifting thing. There also might be a byte fixup op, 
# haven't seen it though. greater than 26-bit addresses might also just span two or more relocation entries, as with
# the c/4/0 triplets for .text fixups.

# also noteworthy is the fact that if your load address is 0, you only need to parse the c/4/0 triplets to zero
# out high register halfwords.

def get_relocation_fields(reloc: int) -> (int, int):
    operation = reloc >> 26
    offset = reloc & 0x03ffffff
    return (operation, offset)

class BfltFile:
    FLAT_FLAG_RAM = 1
    FLAT_FLAG_GOTPIC = 2
    FLAT_FLAG_GZIP = 4
    FLAT_FLAG_GZDATA = 8
    FLAT_FLAG_KTRACE = 16

    def __init__(self, data):
        self.magic = data[0:4]
        self.rev   = struct.unpack(">I", data[4:8])[0]

        if self.rev == 4:
            self.header_size = 0x40;

        self.entry = struct.unpack(">I", data[8:12])[0]
        self.data_start = struct.unpack(">I", data[12:16])[0]
        self.data_end = struct.unpack(">I", data[16:20])[0]
        self.bss_end = struct.unpack(">I", data[20:24])[0]
        self.stack_size = struct.unpack(">I", data[24:28])[0]
        self.reloc_start = struct.unpack(">I", data[28:32])[0]
        self.reloc_count = struct.unpack(">I", data[32:36])[0]
        self.raw_flags = struct.unpack(">I", data[36:40])[0]
        self.build_date = struct.unpack(">I", data[40:44])[0]
        self.filler = data[44:64]
        self.raw = data
        self.data = data[64:]
        self.load_addr = 0x40

        self.relocations = []
        for i in range(0, self.reloc_count):
            current_reloc_bytes = self.raw[self.reloc_start + (i * 4):self.reloc_start + (i * 4) + 4]
            self.relocations.append(struct.unpack(">I", current_reloc_bytes)[0])
    
    def __repr__(self):
        return f"Magic: {self.magic}\n"+\
        f"bFLT Revision: {self.rev:#010x}\n"+\
            f"Entry (text section): {self.entry:#010x}\n"+\
            f"Data Section: {self.data_start:#010x}\n"+\
            f"BSS Section: {self.data_end:#010x}\n"+\
            f"BSS End: {self.bss_end:#010x}\n"+\
            f"Stack Size: {self.stack_size:#010x}\n"+\
            f"Relocations Start: {self.reloc_start:#010x}\n"+\
            f"Relocations Count: {self.reloc_count:#010x}\n"+\
            self.repr_flags() +\
            f"Build Date: {self.build_date}"

    def repr_flags(self):
        return "Flags:\n"+\
        f'\tFLAT_FLAG_RAM = {self.raw_flags & self.FLAT_FLAG_RAM}\n'+\
        f'\tFLAT_FLAG_GOTPIC = {self.raw_flags & self.FLAT_FLAG_GOTPIC}\n'+\
        f'\tFLAT_FLAG_GZIP = {self.raw_flags & self.FLAT_FLAG_GZIP}\n'+\
        f'\tFLAT_FLAG_GZDATA = {self.raw_flags & self.FLAT_FLAG_GZDATA}\n'+\
        f'\tFLAT_FLAG_KTRACE = {self.raw_flags & self.FLAT_FLAG_KTRACE}\n'

