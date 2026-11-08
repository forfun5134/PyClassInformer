"""Mock of ida_bytes."""
import image

BADADDR = image.BADADDR

FF_BYTE = 0x00000000
FF_WORD = 0x10000000
FF_DWORD = 0x20000000
FF_QWORD = 0x30000000
FF_DATA = 0x00000400
FF_CODE = 0x00000600
FF_0OFF = 0x00002000
FF_STRLIT = 0x00004000
FF_0NUMD = 0x00000000
FF_0NUMH = 0x00008000

DELIT_SIMPLE = 0
DELIT_EXPAND = 0x01
DELIT_DELNAMES = 0x02
DELIT_NOTRUNC = 0x04
DELIT_NOUNAME = 0x08
DELIT_NOCMT = 0x10


class flags_t(object):
    """Stand-in for IDA's flags_t."""

    def __init__(self, ea):
        self.ea = ea

    def __int__(self):
        return self.ea


def get_full_flags(ea):
    if not isinstance(ea, int):
        return ea
    return flags_t(ea)


def _kind(ea):
    item = image.IMAGE.get_item(ea)
    return item[0] if item else image.KIND_UNKNOWN


def is_code(f):
    return _kind(f.ea) == image.KIND_CODE


def is_data(f):
    return _kind(f.ea) in (image.KIND_DATA, image.KIND_STRUCT)


def is_unknown(f):
    return _kind(f.ea) == image.KIND_UNKNOWN


def is_struct(f):
    return _kind(f.ea) == image.KIND_STRUCT


def is_head(f):
    return _kind(f.ea) != image.KIND_UNKNOWN


def is_qword(f):
    item = image.IMAGE.get_item(f.ea)
    return bool(item and item[0] == image.KIND_DATA and item[1] == 8)


def is_dword(f):
    item = image.IMAGE.get_item(f.ea)
    return bool(item and item[0] == image.KIND_DATA and item[1] == 4)


def is_word(f):
    item = image.IMAGE.get_item(f.ea)
    return bool(item and item[0] == image.KIND_DATA and item[1] == 2)


def is_byte(f):
    item = image.IMAGE.get_item(f.ea)
    return bool(item and item[0] == image.KIND_DATA and item[1] == 1)


def has_xref(f):
    if not isinstance(f, flags_t):
        return False
    return image.IMAGE.has_xref(f.ea)


def get_byte(ea):
    data = image.IMAGE.read(ea, 1)
    return data[0] if data else 0


def get_word(ea):
    return image.IMAGE.read_uint(ea, 2)


def get_dword(ea):
    return image.IMAGE.read_uint(ea, 4)


def get_qword(ea):
    return image.IMAGE.read_uint(ea, 8)


def get_32bit(ea):
    return image.IMAGE.read_uint(ea, 4)


def get_64bit(ea):
    return image.IMAGE.read_uint(ea, 8)


def get_bytes(ea, size, **kwargs):
    data = image.IMAGE.read(ea, size)
    return data


def get_strlit_contents(ea, length, strtype, **kwargs):
    out = bytearray()
    pos = 0
    while True:
        if length != -1 and pos >= length:
            break
        seg = image.IMAGE.get_segment(ea + pos)
        if seg is None or ea + pos >= seg.end_ea:
            break
        c = seg.data[ea + pos - seg.start_ea]
        if c == 0:
            break
        out.append(c)
        pos += 1
    if not out:
        return None
    return bytes(out)


def create_struct(ea, size, tid, use_offsets=True):
    return image.IMAGE.apply_struct(ea, size, tid)


def del_items(ea, flags=DELIT_SIMPLE, nbytes=1, **kwargs):
    image.IMAGE.clear_items(ea, nbytes)
    if flags & DELIT_DELNAMES:
        # DELIT_DELNAMES also wipes the symbols in the range
        for name_ea in [x for x in image.IMAGE.names if ea <= x < ea + nbytes]:
            image.IMAGE.deleted_names.append((name_ea, image.IMAGE.names.pop(name_ea)))
    return True


def next_that(ea, maxea, testf):
    for item_ea in sorted(image.IMAGE.items):
        if item_ea > ea:
            if testf(get_full_flags(item_ea)):
                return item_ea
    return BADADDR


def prev_head(ea, minea=0):
    candidates = [x for x in image.IMAGE.items if x < ea]
    return max(candidates) if candidates else BADADDR


def next_head(ea, maxea=BADADDR):
    candidates = [x for x in image.IMAGE.items if x > ea]
    return min(candidates) if candidates else BADADDR
