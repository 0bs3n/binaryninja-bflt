from binaryninja import Architecture, BinaryReader, BinaryView, BinaryWriter, Platform, Architecture, RelocationType
from binaryninja.enums import SectionSemantics, SegmentFlag
from binaryninja import _binaryninjacore as core
from .bflt_file import BfltFile, get_relocation_fields

import struct

class BfltView(BinaryView):
    name = 'bFLT File'

    @staticmethod
    def is_valid_for_data(data):
        if data[0:4] == b'bFLT':
            if data[4:8] != b"\x00\x00\x00\x04":
                print("Only bFLT Revision 4 for Blackfin currently supported.")
                return False
            return True
        return False

    def __init__(self, data):
        """
        Once our view is selected, this method is called to actually create it.
        :param data: the file data
        """
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)

    def init(self):
        self.platform = Platform["linux-blackfin"]
        self.arch = Architecture["blackfin"]
        self.bflt = BfltFile(self.parent_view)
        self.loading_addr = 0x10000000
        self.set_segments_sections()
        self.do_relocations()

        print("init view")
        return True

    def perform_is_executable(self):
        return True

    def perform_is_relocatable(self):
        return True

    def set_segments_sections(self):
        """
        This is a helper function to parse our BS format
        :param data:
        :return:
        """
        

        # Entry point is defined in the header and can be accessed with bflt.entry.
        # this value is relative to the start of the file including the header,
        # so if header_size == 0x40 and entry == 0x44, entry after format parsing
        # will be at 0x04.

        # entry function is a simple _start function from what I've seen, and the final
        # load of R0.H and R0.L before the JUMP.L is the address of the main function.
        # can this be automated? Like how the elf loader knows to define _start, main
        # and all of the helper functions that are standard to elf files

        text_foffset = self.bflt.header_size
        text_start   = self.loading_addr
        text_size    = self.bflt.data_start - self.bflt.header_size

        data_foffset = self.bflt.data_start
        data_start   = text_start + text_size
        data_size    = self.bflt.data_end - self.bflt.data_start

        bss_start    = data_start + data_size
        bss_size     = self.bflt.bss_end - self.bflt.data_end

        code_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
        data_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable   | SegmentFlag.SegmentContainsData | SegmentFlag.SegmentDenyExecute
        bss_flags  = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable   | SegmentFlag.SegmentContainsData | SegmentFlag.SegmentDenyExecute

        self.add_auto_segment(text_start, text_size, text_foffset, text_size, code_flags)
        self.add_auto_section(".text", text_start, text_size, SectionSemantics.ReadOnlyCodeSectionSemantics)

        self.add_auto_segment(data_start, data_size, data_foffset, data_size, data_flags)
        self.add_auto_section(".data", data_start, data_size, SectionSemantics.ReadWriteDataSectionSemantics)

        self.add_auto_segment(bss_start, bss_size, 0, 0, bss_flags)
        self.add_auto_section(".bss", bss_start, bss_size, SectionSemantics.ReadWriteDataSectionSemantics)

        self.add_entry_point(self.loading_addr + (self.bflt.entry - self.bflt.header_size))

    def do_relocations(self):
        global_reloc_offset = 0
        i = 0
        while i < len(self.bflt.relocations):
            ri = core.BNRelocationInfo()

            operation, offset = get_relocation_fields(self.bflt.relocations[i])

            if operation == 3: # c
                global_reloc_offset = offset
                i += 1
                continue

            if operation == 2: # 8
                target = offset 
                target_data = struct.unpack("<I", self.parent_view[target + self.bflt.header_size:target + self.bflt.header_size + 4])[0] + self.loading_addr
                ri.type = 3
                ri.size = 4
                ri.nativeType = 2
                # ri.addend = offset
                ri.target = target_data


            if operation == 1: # 4
                target = offset
                target_data = ((self.loading_addr & 0xffff0000) >> 16) + global_reloc_offset
                ri.type = 3
                ri.size = 2
                ri.nativeType = 1
                # ri.addend = offset
                ri.target = target_data

            if operation == 0: # 0
                target = offset
                target_data = struct.unpack("<H", self.parent_view[target + self.bflt.header_size:target + self.bflt.header_size + 2])[0]
                target_data = target_data + (self.loading_addr & 0xffff)
                ri.type = 3
                ri.size = 2
                ri.nativeType = 0
                # ri.addend = offset
                ri.target = target_data

            # if ri.nativeType == 1:
                # print(f"nativeType: {ri.nativeType}, target_data: {target_data:#x}, address: {ri.address + loading_addr:#x}")
            core.BNDefineRelocation(self.handle, self.arch.handle, ri, target_data, self.loading_addr + target)
            i += 1
