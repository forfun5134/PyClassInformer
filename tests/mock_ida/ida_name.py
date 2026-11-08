"""Mock of ida_name."""
import re

import image

SN_NOWARN = 0x0001
SN_NOCHECK = 0x0002
SN_FORCE = 0x0004
SN_PUBLIC = 0x0008
SN_WEAK = 0x0010
SN_NON_PUBLIC = 0x0020
SN_NON_AUTO = 0x0040
SN_NOLIST = 0x0080
SN_NON_PERSISTENT = 0x0100
SN_AUTO_OK = 0x0200
VNT_DEMANGLED = 0x0001


def _auto_name(ea):
    item = image.IMAGE.get_item(ea)
    if item is not None and item[0] == image.KIND_CODE:
        return "sub_%X" % ea
    return "off_%X" % ea


def get_name(ea):
    name = image.IMAGE.get_name(ea)
    if name:
        return name
    return _auto_name(ea)


def get_short_name(ea):
    return get_name(ea)


def set_name(ea, name, flags=0):
    old = image.IMAGE.get_name(ea)
    if old and not (flags & SN_FORCE) and not (flags & SN_NOCHECK):
        return False
    image.IMAGE.set_name(ea, name)
    return True


def demangle_name(name, disable_mask=0, mdem=None):
    """A miniature MSVC demangler: enough for RTTI type descriptors.

    Understands ``??_R0?AVFoo@Bar@@`` -> ``class Bar::Foo `RTTI Type Descriptor'``
    """
    prefix = "??_R0"
    if not name.startswith(prefix):
        return None
    body = name[len(prefix):]
    if not body.startswith("?A") or len(body) < 5:
        return None
    kind = body[2]
    kinds = {"V": "class", "U": "struct", "T": "union", "W": "enum"}
    if kind not in kinds:
        return None
    rest = body[3:]
    if rest.endswith("@@"):
        rest = rest[:-2]
    if not rest or rest.startswith("?$"):
        # template types are not supported by this mini demangler
        return None
    parts = [p for p in rest.split("@") if p]
    parts.reverse()
    return "{} {} `RTTI Type Descriptor'".format(kinds[kind], "::".join(parts))
