"""Mock of ida_nalt."""
import image

BADADDR = 0xFFFFFFFFFFFFFFFF

REF_OFF8 = 0
REF_OFF16 = 1
REF_OFF32 = 2
REF_OFF64 = 3
REFINFO_RVAOFF = 0x20
REFINFO_NOBASE = 0x40

STRTYPE_C = 0
STRTYPE_C_16 = 1
STRTYPE_C_32 = 2


def get_imagebase():
    return image.IMAGE.imagebase


def get_input_file_path():
    return image.IMAGE.input_file


class refinfo_t(object):
    def __init__(self):
        self.flags = 0
        self.target = 0
        self._type = 0

    def init(self, flags):
        self.flags = flags
        return True

    def set_type(self, t):
        self._type = t

    def type(self):
        return self._type


class opinfo_t(object):
    def __init__(self):
        self.ri = refinfo_t()
