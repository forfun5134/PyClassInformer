"""Mock of idautils."""
import image
import ida_xref


class Xref(object):
    def __init__(self, frm, to, xref_type):
        self.frm = frm
        self.to = to
        self.type = xref_type


def XrefsTo(ea, flags=0):
    exact = bool(flags & ida_xref.XREF_EXACT)
    for xref in image.IMAGE.get_xrefs_to(ea):
        if exact and xref.to != ea:
            continue
        yield Xref(xref.frm, xref.to, xref.type)


def XrefsFrom(ea, flags=0):
    for xref in image.IMAGE.xrefs_from.get(ea, []):
        yield Xref(xref.frm, xref.to, xref.type)


def DataRefsTo(ea, flags=0):
    for xref in XrefsTo(ea, flags):
        if xref.type == 1:
            yield xref.frm
