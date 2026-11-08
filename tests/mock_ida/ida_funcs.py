"""Mock of ida_funcs."""
import image

FUNC_NORET = 0x00000001
FUNC_FAR = 0x00000002
FUNC_LIB = 0x00000004
FUNC_STATIC = 0x00000008
FUNC_FRAME = 0x00000010
FUNC_USERFAR = 0x00000020
FUNC_HIDDEN = 0x00000040
FUNC_THUNK = 0x00000080
FUNC_BOTTOMBP = 0x00000100
FUNC_LUMINA = 0x00008000


class func_t(object):
    def __init__(self, start_ea, end_ea, flags=0):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.flags = flags

    def __repr__(self):
        return "<func_t %#x>" % self.start_ea


def get_func(ea):
    best = None
    for start, f in image.IMAGE.funcs.items():
        if start <= ea < f.end_ea:
            if best is None or start > best.start_ea:
                best = f
    return best


def get_func_name(ea):
    f = get_func(ea)
    if f is None:
        return None
    return image.IMAGE.get_name(f.start_ea) or "sub_%X" % f.start_ea


def add_func(ea, end=image.BADADDR):
    if get_func(ea) is not None:
        return True
    image.IMAGE.funcs[ea] = func_t(ea, ea + 0x10)
    image.IMAGE.define(ea, image.KIND_CODE, 0x10)
    return True


def update_func(f):
    image.IMAGE.funcs[f.start_ea] = f
    return True


def get_func_qty():
    return len(image.IMAGE.funcs)


def getn_func(n):
    keys = sorted(image.IMAGE.funcs)
    return image.IMAGE.funcs[keys[n]] if 0 <= n < len(keys) else None


def del_func(ea):
    image.IMAGE.funcs.pop(ea, None)
    return True
