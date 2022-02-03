from binaryninja import Architecture, BinaryReader, BinaryView, BinaryWriter, Platform, Architecture
from binaryninja.enums import SectionSemantics, SegmentFlag
from binaryninja import core as BNCore
from .bflt_file import BfltFile, get_relocation_fields

import struct

class BfltView(BinaryView):
    """
    This is our custom Binary View.
    """
    name = 'bFLT File'

    @classmethod
    def is_valid_for_data(cls, data):
        """
        This function tells Binja whether to use this view for a given file
        """
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
        self.platform = Platform["linux-blackfin"]
        self.architecture = Architecture["blackfin"]
        self.parse_format(data)

    def parse_format(self, data):
        """
        This is a helper function to parse our BS format
        :param data:
        :return:
        """
        loading_addr = 0x10000000
        bflt = BfltFile(data)

        # Entry point is defined in the header and can be accessed with bflt.entry.
        # this value is relative to the start of the file including the header,
        # so if header_size == 0x40 and entry == 0x44, entry after format parsing
        # will be at 0x04.

        # entry function is a simple _start function from what I've seen, and the final
        # load of R0.H and R0.L before the JUMP.L is the address of the main function.
        # can this be automated? Like how the elf loader knows to define _start, main
        # and all of the helper functions that are standard to elf files

        i = 0
        while i < len(bflt.relocations):
            operation, offset = get_relocation_fields(bflt.relocations[i])
            if operation == 3: # c
                target = get_relocation_fields(bflt.relocations[i + 1])[1] + bflt.header_size
                # data[target:target + 2] = struct.pack("<H", offset)
                i += 2
                continue

            if operation == 2: # 8
                target = offset + bflt.header_size
                target_data = struct.unpack("<I", data[target:target + 4])[0]
                # data[target:target + 4] = target_data + loading_addr

            if operation == 1: # 4
                target = offset + bflt.header_size
                target_data = struct.unpack("<H", data[target:target + 2])[0]
                # data[target:target + 2] = 0

            if operation == 0: # 0
                target = offset + bflt.header_size
                target_data = struct.unpack("<H", data[target:target + 2])[0]
                # data[target:target + 2] = target_data + loading_addr

            i += 1

        text_foffset = bflt.header_size
        text_start   = loading_addr
        text_size    = bflt.data_start - bflt.header_size

        data_foffset = bflt.data_start
        data_start   = text_start + text_size
        data_size    = bflt.data_end - bflt.data_start

        bss_start    = data_start + data_size
        bss_size     = bflt.bss_end - bflt.data_end

        code_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
        data_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable   | SegmentFlag.SegmentContainsData | SegmentFlag.SegmentDenyExecute
        bss_flags  = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable   | SegmentFlag.SegmentContainsData | SegmentFlag.SegmentDenyExecute

        self.add_auto_segment(text_start, text_size, text_foffset, text_size, code_flags)
        self.add_auto_section(".text", text_start, text_size, SectionSemantics.ReadOnlyCodeSectionSemantics)

        self.add_auto_segment(data_start, data_size, data_foffset, data_size, data_flags)
        self.add_auto_section(".data", data_start, data_size, SectionSemantics.ReadOnlyDataSectionSemantics)

        self.add_auto_segment(bss_start, bss_size, 0, 0, bss_flags)
        self.add_auto_section(".bss", bss_start, bss_size, SectionSemantics.ReadWriteDataSectionSemantics)

        self.add_entry_point(loading_addr + (bflt.entry - bflt.header_size))
