"""A tiny in-memory model of an IDA database.

This is *not* a simulator of IDA: it only implements enough behaviour for the
PyClassInformer modules to run outside of IDA so that their logic can be
tested.  The RTTI handling itself (which is what we want to verify) is pure
arithmetic on these bytes, so the tests are meaningful; the IDAPython call
semantics are approximations and are marked as such in the test report.
"""

import bisect
import struct

BADADDR = 0xFFFFFFFFFFFFFFFF

# item kinds
KIND_UNKNOWN = 0
KIND_CODE = 1
KIND_DATA = 2
KIND_STRUCT = 3


def align_up(value, alignment):
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


class Segment(object):
    def __init__(self, start, size, name, sclass, bitness=2):
        self.start_ea = start
        self.end_ea = start + size
        self.name = name
        self.sclass = sclass
        self.bitness = bitness
        self.data = bytearray(size)

    def is_header_segm(self):
        return False

    def contains(self, ea, size=1):
        return self.start_ea <= ea and ea + size <= self.end_ea

    def __repr__(self):
        return "<Segment %s %#x-%#x>" % (self.name, self.start_ea, self.end_ea)


class Xref(object):
    __slots__ = ("frm", "to", "type")

    def __init__(self, frm, to, xref_type):
        self.frm = frm
        self.to = to
        self.type = xref_type


class Image(object):
    """Fake database: segments, defined items, xrefs, names and functions."""

    def __init__(self, imagebase=0x140000000, bitness=2, input_file=""):
        self.imagebase = imagebase
        self.bitness = bitness
        self.input_file = input_file
        self.segments = []
        self.items = {}          # ea -> [kind, size, tid]
        self.xrefs_from = {}     # frm -> [Xref]
        self.xrefs_to = {}       # to -> [Xref]
        self.names = {}          # ea -> name
        self.funcs = {}          # start_ea -> FakeFunc
        self.struct_applied = {} # tid -> set(ea)
        self.deleted_names = []  # (ea, name) removed by del_items(DELIT_DELNAMES)

    # ------------------------------------------------------------------
    def add_segment(self, start, size, name, sclass, bitness=None):
        seg = Segment(start, size, name, sclass, self.bitness if bitness is None else bitness)
        self.segments.append(seg)
        self.segments.sort(key=lambda s: s.start_ea)
        return seg

    def get_segment(self, ea):
        for seg in self.segments:
            if seg.start_ea <= ea < seg.end_ea:
                return seg
        return None

    def get_segment_by_name(self, name):
        for seg in self.segments:
            if seg.name == name:
                return seg
        return None

    def read(self, ea, size):
        if size <= 0:
            return b""
        seg = self.get_segment(ea)
        if seg is None or not seg.contains(ea, size):
            return None
        off = ea - seg.start_ea
        return bytes(seg.data[off:off + size])

    def write(self, ea, data):
        seg = self.get_segment(ea)
        if seg is None or not seg.contains(ea, len(data)):
            raise ValueError("write outside of the image: %#x" % ea)
        off = ea - seg.start_ea
        seg.data[off:off + len(data)] = data

    def write_uint(self, ea, value, size):
        if size == 8:
            self.write(ea, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))
        elif size == 4:
            self.write(ea, struct.pack("<I", value & 0xFFFFFFFF))
        elif size == 2:
            self.write(ea, struct.pack("<H", value & 0xFFFF))
        else:
            self.write(ea, struct.pack("<B", value & 0xFF))

    def read_uint(self, ea, size):
        data = self.read(ea, size)
        if data is None:
            return 0
        if size == 8:
            return struct.unpack("<Q", data)[0]
        if size == 4:
            return struct.unpack("<I", data)[0]
        if size == 2:
            return struct.unpack("<H", data)[0]
        return data[0]

    def write_string(self, ea, text):
        data = text.encode("utf-8") + b"\x00"
        self.write(ea, data)
        return len(data)

    # ------------------------------------------------------------------
    def define(self, ea, kind, size, tid=BADADDR):
        self.items[ea] = [kind, size, tid]

    def clear_items(self, ea, size):
        for item_ea in [x for x in self.items if ea <= x < ea + size]:
            del self.items[item_ea]

    def get_item(self, ea):
        return self.items.get(ea)

    def next_item(self, ea, max_ea):
        candidates = sorted(x for x in self.items if ea < x <= max_ea)
        return candidates[0] if candidates else BADADDR

    def item_size(self, ea):
        item = self.items.get(ea)
        return item[1] if item else 1

    # ------------------------------------------------------------------
    def add_xref(self, frm, to, xref_type=1):
        xref = Xref(frm, to, xref_type)
        self.xrefs_from.setdefault(frm, []).append(xref)
        self.xrefs_to.setdefault(to, []).append(xref)
        return xref

    def get_xrefs_to(self, ea):
        return list(self.xrefs_to.get(ea, []))

    def has_xref(self, ea):
        """Does the item at ea contain a reference (offset) to something?"""
        return bool(self.xrefs_from.get(ea))

    # ------------------------------------------------------------------
    def set_name(self, ea, name):
        old = self.names.get(ea)
        self.names[ea] = name
        return old

    def get_name(self, ea):
        return self.names.get(ea)

    def apply_struct(self, ea, size, tid):
        self.clear_items(ea, size)
        self.define(ea, KIND_STRUCT, size, tid)
        self.struct_applied.setdefault(tid, set()).add(ea)
        # IDA records a "type xref" from the instance to the type
        self.add_xref(ea, tid, 0)
        return True


#: the database the mock modules operate on (tests replace it)
IMAGE = Image()
