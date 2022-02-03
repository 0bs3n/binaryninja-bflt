from binaryninja import Architecture, Platform
from .bflt_view import BfltView

blackfin_arch = Architecture["blackfin"]

class uCLinuxPlatform(Platform):
    name = "linux-blackfin"

plat = uCLinuxPlatform(blackfin_arch)
plat.register("linux-blackfin")

plat.default_calling_convention = blackfin_arch.standalone_platform.default_calling_convention
plat.system_call_convention = blackfin_arch.standalone_platform.calling_conventions[1]

BfltView.register()
