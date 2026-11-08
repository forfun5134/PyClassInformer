"""MSVC RTTI parser for PE binaries (x86, x64, ARM, ARM64).

The parser walks the data sections of a PE file looking for ``vftable``
candidates, validates them through their Complete Object Locator (COL) and
rebuilds the class hierarchy from the Class Hierarchy Descriptor (CHD), the
Base Class Array (BCA) and the Base Class Descriptors (BCD).

The implementation is version agnostic: structure layouts are described by
:mod:`pyclassinformer.ida_compat` and their offsets are computed in Python, so
the parser keeps working even when IDA changes its structure/type API (which
happened in 8.5, 9.0 and - for some helpers - again in 9.5).
"""

import sys

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_name
import ida_nalt

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.ida_compat")
ida_idaapi.require("pyclassinformer.pci_utils")
import pyclassinformer.ida_compat as ida_compat
import pyclassinformer.pci_utils as pci_utils

u = pci_utils.utils.get()

# --------------------------------------------------------------------------
# RTTI constants
# --------------------------------------------------------------------------
# RTTIClassHierarchyDescriptor::attribute
CHD_MULTINH = 0x01      # multiple inheritance
CHD_VIRTINH = 0x02      # virtual inheritance
CHD_AMBIGUOUS = 0x04    # ambiguous inheritance
CHD_FLAGS = (
    (CHD_MULTINH, "M", "MULTINH"),
    (CHD_VIRTINH, "V", "VIRTINH"),
    (CHD_AMBIGUOUS, "A", "AMBIGUOUS"),
)

# RTTIBaseClassDescriptor::attributes
BCD_NOTVISIBLE = 0x00000001          # class is not visible outside the object file
BCD_AMBIGUOUS = 0x00000002           # class is an ambiguous base class
BCD_PRIVORPROTBASE = 0x00000004      # base class is private or protected
BCD_PRIVORPROTINCOMPOBJ = 0x00000008 # class is a private or protected base of an incomplete object
BCD_VBOFCONTOBJ = 0x00000010         # class is a virtual base class of a complete object
BCD_NONPOLYMORPHIC = 0x00000020      # class is a non-polymorphic base class
BCD_HASPCHD = 0x00000040             # pClassDescriptor field is present
BCD_FLAGS = (
    (BCD_NOTVISIBLE, "N", "NOTVISIBLE"),
    (BCD_AMBIGUOUS, "A", "AMBIGUOUS"),
    (BCD_PRIVORPROTBASE, "P", "PRIVORPROTBASE"),
    (BCD_PRIVORPROTINCOMPOBJ, "C", "PRIVORPROTINCOMPOBJ"),
    (BCD_VBOFCONTOBJ, "V", "VBOFCONTOBJ"),
    (BCD_NONPOLYMORPHIC, "n", "NONPOLYMORPHIC"),
    (BCD_HASPCHD, "h", "HASPCHD"),
)

#: names of the CRT helpers that stand for a pure virtual function
PURE_VIRTUAL_SYMBOLS = (
    "_purecall",
    "__cxa_pure_virtual",
    "purecall",
    "_pure_virtual",
    "__purecall",
)

# --------------------------------------------------------------------------
# Structure specifications
# --------------------------------------------------------------------------
TD_NAME = "RTTITypeDescriptor"
CHD_NAME = "RTTIClassHierarchyDescriptor"
BCD_NAME = "RTTIBaseClassDescriptor"
BCA_NAME = "RTTIBaseClassArray"
COL_NAME = "RTTICompleteObjectLocator"

TD_MEMBERS = (
    {"name": "pVFTable", "kind": ida_compat.MEMBER_PTR_FULL},
    {"name": "spare", "kind": ida_compat.MEMBER_PTR_FULL},
    {"name": "name", "kind": ida_compat.MEMBER_STRLIT},
)

CHD_MEMBERS = (
    {"name": "signature", "kind": ida_compat.MEMBER_DWORD},
    {"name": "attribute", "kind": ida_compat.MEMBER_DWORD},
    {"name": "numBaseClasses", "kind": ida_compat.MEMBER_DWORD},
    {"name": "pBaseClassArray", "kind": ida_compat.MEMBER_PTR, "target": BCA_NAME},
)

BCD_MEMBERS = (
    {"name": "pTypeDescriptor", "kind": ida_compat.MEMBER_PTR, "target": TD_NAME},
    {"name": "numContainerBases", "kind": ida_compat.MEMBER_DWORD},
    {"name": "mdisp", "kind": ida_compat.MEMBER_DWORD},
    {"name": "pdisp", "kind": ida_compat.MEMBER_DWORD},
    {"name": "vdisp", "kind": ida_compat.MEMBER_DWORD},
    {"name": "attributes", "kind": ida_compat.MEMBER_DWORD},
    {"name": "pClassDescriptor", "kind": ida_compat.MEMBER_PTR, "target": CHD_NAME},
)

BCA_MEMBERS = (
    {"name": "arrayOfBaseClassDescriptors", "kind": ida_compat.MEMBER_PTR,
     "target": BCD_NAME, "array": True},
)

COL_MEMBERS = [
    {"name": "signature", "kind": ida_compat.MEMBER_DWORD},
    {"name": "offset", "kind": ida_compat.MEMBER_DWORD},
    {"name": "cdOffset", "kind": ida_compat.MEMBER_DWORD},
    {"name": "pTypeDescriptor", "kind": ida_compat.MEMBER_PTR, "target": TD_NAME},
    {"name": "pClassDescriptor", "kind": ida_compat.MEMBER_PTR, "target": CHD_NAME},
]
#: x64 locators carry an extra pointer to themselves
COL_MEMBERS_X64 = COL_MEMBERS + [
    {"name": "pSelf", "kind": ida_compat.MEMBER_PTR, "target": COL_NAME},
]


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def flags_to_short(attributes, table):
    """``MVA`` style short representation of a flag field."""
    return "".join(short for bit, short, _ in table if attributes & bit)


def flags_to_names(attributes, table):
    """``MULTINH|VIRTINH`` style representation of a flag field."""
    return "|".join(name for bit, _, name in table if attributes & bit)


def strip(name):
    """Return the bare class name of a demangled RTTI type descriptor.

    IDA demangles ``??_R0?AVFoo@@`` into ``class Foo `RTTI Type Descriptor'``.
    """
    if not name:
        return name
    s = name.strip()
    for suffix in (" `RTTI Type Descriptor'", "`RTTI Type Descriptor'",
                   " `RTTI Type Descriptor\""):
        if s.endswith(suffix):
            s = s[:-len(suffix)].strip()
            break
    for prefix in ("class ", "struct ", "union ", "enum "):
        if s.startswith(prefix):
            s = s[len(prefix):].strip()
            break
    return s


def demangle_rtti_name(mangled):
    """Demangle the content of an MSVC RTTITypeDescriptor.

    The name stored in the type descriptor is the "type" mangling of the class
    (``.?AVFoo@@``).  IDA can demangle it as a type descriptor symbol
    (``??_R0?AVFoo@@``).  Returns None when the string does not look like a
    MSVC type name at all.
    """
    if not mangled:
        return None

    candidates = []
    if mangled.startswith("."):
        # .?AVFoo@@  ->  ??_R0?AVFoo@@
        candidates.append("??_R0" + mangled[1:])
    candidates.append(mangled)

    for candidate in candidates:
        try:
            demangled = ida_name.demangle_name(candidate, 0)
        except Exception:
            demangled = None
        if demangled:
            return demangled

    # IDA refused to demangle the name (unusual template arguments, unknown
    # compiler version...).  Accept well formed MSVC type names anyway so that
    # the class is not silently dropped.
    if mangled.startswith(".?A"):
        return mangled
    return None


def fallback_type_name(mangled):
    """Best effort class name from a raw MSVC type mangling (``.?AVFoo@Bar@@``)."""
    if not mangled:
        return mangled
    s = mangled
    if s.startswith("."):
        s = s[1:]
    # ?AV = class, ?AU = struct, ?AT = union, ?AW = enum
    if s.startswith("?A") and len(s) > 3:
        s = s[3:]
    if s.endswith("@@"):
        s = s[:-2]
    elif s.endswith("@"):
        s = s[:-1]
    if not s:
        return mangled
    parts = [p for p in s.split("@") if p]
    if parts and parts[0].startswith("?$"):
        # templates cannot be reconstructed reliably here
        return mangled
    parts.reverse()
    return "::".join(parts)


def func_name(ea):
    """Reliable function name for an address."""
    name = None
    try:
        name = ida_funcs.get_func_name(ea)
    except Exception:
        name = None
    if not name:
        try:
            name = ida_name.get_short_name(ea)
        except Exception:
            name = None
    return name


def is_pure_virtual(ea):
    """Return True when the address is one of the CRT's pure call stubs."""
    name = func_name(ea)
    if not name:
        return False
    lowered = name.lower()
    return any(sym in lowered for sym in PURE_VIRTUAL_SYMBOLS)


def signed32(value):
    return u.to_signed32(value)


#: type descriptor cache: ea -> RTTITypeDescriptor.  A type descriptor is
#: shared by every vftable and every base class entry of its class.
_TD_CACHE = {}


# --------------------------------------------------------------------------
# RTTI structures
# --------------------------------------------------------------------------
class RTTIStruc(object):
    """Base class of the RTTI structures.

    The layout (member offsets and size) is computed in Python and is
    therefore always available; applying the layout to the database is a best
    effort step.
    """

    name = None
    tid = ida_idaapi.BADADDR
    size = 0
    offsets = {}
    info = None
    _registered_key = None

    @classmethod
    def get_members(cls):
        raise NotImplementedError

    @classmethod
    def ensure_registered(cls, force=False):
        try:
            key = (ida_nalt.get_input_file_path(), u.x64)
        except Exception:
            key = None
        if (not force and cls.info is not None
                and cls._registered_key is not None
                and cls._registered_key == key):
            return cls.info

        try:
            info = ida_compat.create_struct(cls.name, cls.get_members(), u.x64)
        except Exception as e:
            # Parsing does not depend on the database layout, so fall back to
            # a "layout only" definition and keep going.
            print("[PyClassInformer] Warning: could not create %s (%s)." % (cls.name, e))
            offsets, size = ida_compat.compute_layout(cls.get_members(), u.x64)
            info = ida_compat.StructInfo(cls.name, size, offsets)

        cls.info = info
        cls.tid = info.tid
        cls.size = info.size
        cls.offsets = info.offsets
        cls._registered_key = key if info.applied else None
        return info

    @classmethod
    def moff(cls, member):
        return cls.offsets.get(member, -1)


class RTTITypeDescriptor(RTTIStruc):

    name = TD_NAME

    @classmethod
    def get_members(cls):
        return TD_MEMBERS

    def __init__(self, ea):
        self.class_name = None
        self.demangled = None
        self.mangled = None
        self.ea = ea
        # the name follows the fixed part of the structure
        self.size = type(self).size

        name_off = type(self).moff("name")
        if name_off < 0:
            return

        data = u.get_strlit(ea + name_off)
        if data is None:
            # not a real type descriptor
            return

        try:
            mangled = data.decode("utf-8", "replace")
        except Exception:
            return
        if not mangled:
            return

        demangled = demangle_rtti_name(mangled)
        if not demangled:
            return

        self.mangled = mangled
        self.demangled = demangled
        self.class_name = strip(demangled)
        if self.class_name == demangled:
            # demangling failed, reconstruct a readable name from the mangling
            fallback = fallback_type_name(mangled)
            if fallback:
                self.class_name = fallback

        self.size = type(self).size + len(data) + 1  # + NULL byte

        # apply the structure to the bytes (cosmetic)
        ida_compat.apply_struct(ea, self.size, type(self).info)


def get_type_descriptor(ea):
    """Return (and cache) the type descriptor at ``ea``."""
    td = _TD_CACHE.get(ea)
    if td is None:
        td = RTTITypeDescriptor(ea)
        _TD_CACHE[ea] = td
    return td


class RTTIClassHierarchyDescriptor(RTTIStruc):

    name = CHD_NAME

    CHD_MULTINH = CHD_MULTINH
    CHD_VIRTINH = CHD_VIRTINH
    CHD_AMBIGUOUS = CHD_AMBIGUOUS

    @classmethod
    def get_members(cls):
        return CHD_MEMBERS

    def __init__(self, ea):
        self.ea = ea
        self.sig = 0
        self.attribute = 0
        self.bcaea = ida_idaapi.BADADDR
        self.nb_classes = 0
        self.flags = ""
        self.flag_names = ""
        self.bca = None

        cls = type(self)
        try:
            self.sig = ida_bytes.get_32bit(ea + cls.moff("signature"))
            self.attribute = ida_bytes.get_32bit(ea + cls.moff("attribute"))
            self.nb_classes = ida_bytes.get_32bit(ea + cls.moff("numBaseClasses"))
            self.bcaea = ida_bytes.get_32bit(ea + cls.moff("pBaseClassArray")) + u.x64_imagebase()
        except Exception:
            return

        self.flags = flags_to_short(self.attribute, CHD_FLAGS)
        self.flag_names = flags_to_names(self.attribute, CHD_FLAGS)

        # sanity checks: CHD::signature is always 0, and a hierarchy with no
        # base class makes no sense
        if self.sig != 0 or not (1 <= self.nb_classes <= 0x4000):
            return
        if not u.valid_ptr(self.bcaea):
            return

        ida_compat.apply_struct(ea, cls.size, cls.info)
        self.bca = RTTIBaseClassArray(self.bcaea, self.nb_classes)


class RTTIBaseClassDescriptor(RTTIStruc):

    name = BCD_NAME

    BCD_NOTVISIBLE = BCD_NOTVISIBLE
    BCD_AMBIGUOUS = BCD_AMBIGUOUS
    BCD_PRIVORPROTBASE = BCD_PRIVORPROTBASE
    BCD_PRIVORPROTINCOMPOBJ = BCD_PRIVORPROTINCOMPOBJ
    BCD_VBOFCONTOBJ = BCD_VBOFCONTOBJ
    BCD_NONPOLYMORPHIC = BCD_NONPOLYMORPHIC
    BCD_HASPCHD = BCD_HASPCHD

    @classmethod
    def get_members(cls):
        return BCD_MEMBERS

    def __init__(self, ea):
        self.ea = ea
        self.tdea = ida_idaapi.BADADDR
        self.nb_cbs = 0
        self.mdisp = 0
        self.pdisp = 0
        self.vdisp = 0
        self.attributes = 0
        self.chdea = ida_idaapi.BADADDR
        self.name = None
        self.depth = 0
        self.index = -1
        self.td = None
        self.flag_names = ""

        cls = type(self)
        try:
            self.tdea = ida_bytes.get_32bit(ea + cls.moff("pTypeDescriptor")) + u.x64_imagebase()
            self.nb_cbs = ida_bytes.get_32bit(ea + cls.moff("numContainerBases"))
            self.mdisp = signed32(ida_bytes.get_32bit(ea + cls.moff("mdisp")))
            self.pdisp = signed32(ida_bytes.get_32bit(ea + cls.moff("pdisp")))
            self.vdisp = signed32(ida_bytes.get_32bit(ea + cls.moff("vdisp")))
            self.attributes = ida_bytes.get_32bit(ea + cls.moff("attributes"))
            chdea = ida_bytes.get_32bit(ea + cls.moff("pClassDescriptor")) + u.x64_imagebase()
            self.chdea = chdea if u.valid_ptr(chdea) else ida_idaapi.BADADDR
        except Exception:
            return

        self.flag_names = flags_to_names(self.attributes, BCD_FLAGS)
        ida_compat.apply_struct(ea, cls.size, cls.info)

    @property
    def short_flags(self):
        return flags_to_short(self.attributes, BCD_FLAGS)

    @property
    def pmd(self):
        return "({},{},{})".format(self.mdisp, self.pdisp, self.vdisp)


class RTTIBaseClassArray(RTTIStruc):

    name = BCA_NAME

    @classmethod
    def get_members(cls):
        return BCA_MEMBERS

    def __init__(self, ea, nb_classes):
        self.ea = ea
        # the size depends on the number of base classes of the hierarchy
        self.size = 4 * nb_classes
        self.bases = []
        self.paths = {}
        self.depth = 0

        ida_compat.apply_struct(ea, self.size, type(self).info)

    # Sometimes, mdisp value is not included in COLs' offsets.
    # In that case, use either one of the following:
    #   - in the middle of the BCD's mdisp of a path (for MI with multiple vftables)
    #   - least COL's offset (for other cases such as SI and MI with a single vftable)
    def fix_offset(self, col_offs, curr_path, curr_off):
        # for MI with multiple vftables
        if len(col_offs) > 1:
            if curr_path and curr_path[-1].mdisp in col_offs:
                return curr_path[-1].mdisp
            return curr_off
        # for other cases such as SI and MI with a single vftable
        return sorted(col_offs)[0] if col_offs else curr_off

    def is_path_added(self, curr_path, offset, vi_offs, col):
        # if the offset has negative value, the path will not be added
        if offset < 0:
            return False

        # if the path does not have any VI classes, it will be added.
        if len(vi_offs) == 0:
            return True

        # if the path has a VI class and the path is for the current COL, the path will be added.
        if col.offset in vi_offs:
            # here, it needs to compare the names instead of instances
            # because they are different on each vftable
            if [x.name for x in vi_offs[col.offset]] == [x.name for x in curr_path]:
                return True
        return False

    # calc final offset mainly for VI
    def fix_offset_final(self, col_offs, curr_path, curr_off, vi_offs, col):
        # get first VI class
        found = False
        for bcd in curr_path:
            if bcd.pdisp >= 0:
                found = True
                break

        # for SI and MI
        if len(col_offs) <= 1 or not found:
            return curr_off

        # for VI
        found_col = False
        # get current offset if the current col is already in vi_offs.
        if col.offset in vi_offs:
            curr_off = col.offset
        # if the current col offset is not in vi_offs, the path is not processed yet.
        else:
            for p in vi_offs:
                # check vi_offs table to get the correct offset by comparing the current
                # path and paths in the vi_offs.
                # here, it needs to compare the names instead of instances because they
                # are different on each vftable
                if [x.name for x in vi_offs[p]] == [x.name for x in curr_path]:
                    # sometimes, a class has two or more vftables, and a vfptr is at
                    # its COL's offset but another is not at COL's offsets because of VI.
                    # E.g.
                    # XXXXX::xxx (0,-1,0) -> XXXXX::yyy (0,4,4)
                    # in this case, the current path is necessary on both vftables.
                    # here, a path that is already added in the past will also be added
                    # to another vftable that is not stored in vi_offs yet.
                    if curr_off in col_offs and col.offset != curr_off:
                        pass
                    # otherwise, this path will be skipped adding the current vftable
                    # because it is already processed.
                    else:
                        return -1
                else:
                    # processing the path is the first time.
                    # this path will be added on the current vftable.
                    pass

            # update vi_offs if the offset is empty, processing the path is the first
            # time, or a special case (see above)
            curr_off = col.offset
            vi_offs[col.offset] = curr_path
            found_col = True

        if not found_col:
            if curr_off not in vi_offs:
                print("[PyClassInformer] Warning: current offset {} was not found in vi_offs "
                      "table {}. This should be a virtual inheritance {}."
                      .format(curr_off, {x: [y.name for y in vi_offs[x]] for x in vi_offs},
                              [x.name for x in curr_path]))
        return curr_off

    def parse_bca(self, col, col_offs, vi_offs):
        ea = col.chd.bca.ea
        nb_classes = col.chd.nb_classes

        # parse bca
        for i in range(0, nb_classes):
            bcdoff = ea + i * 4

            # get relevant structures
            bcdea = ida_bytes.get_32bit(bcdoff) + u.x64_imagebase()
            if not u.valid_ptr(bcdea) or (bcdea & 3) != 0:
                print("[PyClassInformer] Warning: invalid RTTIBaseClassDescriptor pointer "
                      "{:#x} in the RTTIBaseClassArray at {:#x}.".format(bcdea, ea))
                continue

            bcd = RTTIBaseClassDescriptor(bcdea)
            bcd.index = i
            if not u.valid_ptr(bcd.tdea):
                print("[PyClassInformer] Warning: invalid RTTITypeDescriptor pointer "
                      "{:#x} in the RTTIBaseClassDescriptor at {:#x}.".format(bcd.tdea, bcdea))
                continue
            td = get_type_descriptor(bcd.tdea)

            if bcd.chdea != ida_idaapi.BADADDR:
                ida_compat.apply_struct(bcd.chdea, RTTIClassHierarchyDescriptor.size,
                                        RTTIClassHierarchyDescriptor.info)

            # add to result and filter out None entries
            if td.class_name:
                bcd.name = strip(td.class_name)
                bcd.td = td
                self.bases.append(bcd)

        # parse hierarchy
        result_paths = {}
        curr_path = []
        n_processed = {}
        curr_off = 0
        for i, bcd in enumerate(self.bases):
            n_processed[bcd.nb_cbs] = 0

            # add BCD to the current path
            curr_path.append(bcd)
            curr_depth = len(curr_path) - 1

            # update the offset for paths of base classes
            curr_off = self.fix_offset(col_offs, curr_path, curr_off)

            # find a path to an offset for multiple inheritance
            if bcd.nb_cbs == 0:
                path = curr_path.copy()

                # get the final offset mainly for VI
                offset = self.fix_offset_final(col_offs, path, curr_off, vi_offs, col)

                # append result according to the obtained offset
                if self.is_path_added(path, offset, vi_offs, col):
                    if offset in result_paths:
                        result_paths[offset].append(path)
                    else:
                        result_paths[offset] = [path]

                # rewind current result for next inheritance
                while True:
                    # compare the number of bases to be processed in the current path with the number processed so far.
                    # if they are matched, the base class must have been processed. So remove it.
                    if curr_path and n_processed.get(curr_path[-1].nb_cbs, 0) == curr_path[-1].nb_cbs:
                        # pop the record of the last bcd from the n_processed. and pop the last bcd itself from the current path.
                        del n_processed[curr_path[-1].nb_cbs]
                        prev_bcd = curr_path.pop()

                        # set the number processed so far to the new tail.
                        if len(curr_path) > 0:
                            n_processed[curr_path[-1].nb_cbs] += prev_bcd.nb_cbs + 1

                    # quit the loop if finished, or no need to unwind for next bcd.
                    if len(curr_path) == 0 or (len(curr_path) > 0 and n_processed[curr_path[-1].nb_cbs] != curr_path[-1].nb_cbs):
                        break

            yield bcd, curr_depth

            # update the base class depth
            self.bases[i].depth = curr_depth

        self.paths = result_paths

        if self.bases and (col.offset not in self.paths or not self.paths[col.offset]):
            print("[PyClassInformer] Warning: Dispatching class hierarchy paths of the BCA at {:#x} "
                  "for {} may be wrong because the paths list for the offset {} is empty. "
                  "The paths will be misclassified as the wrong offset."
                  .format(ea, self.bases[0].name, col.offset))


class RTTICompleteObjectLocator(RTTIStruc):

    name = COL_NAME

    LIBUNK = 0
    LIBLIB = 1
    LIBNOTLIB = 2

    @classmethod
    def get_members(cls):
        return COL_MEMBERS_X64 if u.x64 else COL_MEMBERS

    def __init__(self, ea, vtable):
        self.ea = ea
        self.name = None
        self.chd = None
        self.td = None
        self.offset = 0
        self.cdOffset = 0
        self.sig = 0
        self.tdea = ida_idaapi.BADADDR
        self.chdea = ida_idaapi.BADADDR
        self.selfea = ida_idaapi.BADADDR
        self.vfeas = []
        self.refeas = []
        self.pure_virtual_count = 0
        self.libflag = self.LIBUNK

        cls = type(self)

        # The fields are read before the structure is applied: a candidate that
        # turns out not to be a COL must not modify the database at all.
        try:
            self.sig = ida_bytes.get_32bit(ea + cls.moff("signature"))
            self.offset = ida_bytes.get_32bit(ea + cls.moff("offset"))
            self.cdOffset = ida_bytes.get_32bit(ea + cls.moff("cdOffset"))
            self.tdea = ida_bytes.get_32bit(ea + cls.moff("pTypeDescriptor")) + u.x64_imagebase()
            self.chdea = ida_bytes.get_32bit(ea + cls.moff("pClassDescriptor")) + u.x64_imagebase()
            if u.x64:
                self.selfea = ida_bytes.get_32bit(ea + cls.moff("pSelf")) + u.x64_imagebase()
        except Exception:
            return

        # COL::signature is 0 on x86 and 1 on x64.  Anything else is not a
        # complete object locator.
        if self.sig not in (0, 1) or not u.valid_ptr(self.tdea):
            return

        # get TD to get the class name
        td = get_type_descriptor(self.tdea)
        # validate the COL if the TD has a valid class name or not
        if not td.class_name:
            # if the RTTITypeDescriptor doesn't have a valid name for us to
            # read, then this wasn't a valid RTTICompleteObjectLocator
            return

        if not u.valid_ptr(self.chdea):
            return

        chd = RTTIClassHierarchyDescriptor(self.chdea)
        if chd.bca is None:
            # broken hierarchy descriptor
            return

        # this is a valid COL: apply the structure type to the bytes
        ida_compat.apply_struct(ea, cls.size, cls.info)
        self.td = td
        self.chd = chd

        self.vftable = vtable
        self.col_ptr_ea = vtable - u.PTR_SIZE
        self.vfeas = list(pci_utils.get_vtbl_methods(vtable, u=u))
        self.pure_virtual_count = len([x for x in self.vfeas if is_pure_virtual(x)])

        # set class name
        self.name = strip(self.td.class_name)

        # set vftable name
        self.name_vftable(vtable)

    def name_vftable(self, vtable):
        """Give the vftable a readable name (``vtable__ClassName``).

        IDA usually puts the vftable symbol in front of the first method (the
        slot that holds the RTTI pointer); name that one, and fall back to the
        first method slot for databases that follow the other convention.
        """
        colptr = vtable - u.PTR_SIZE
        try:
            for ea in (colptr, vtable):
                current = ida_name.get_name(ea)
                if current is None:
                    current = ""
                if current == "" or current.startswith("off_") or current.startswith("unk_") \
                        or current.startswith("dword_") or current.startswith("qword_"):
                    ida_name.set_name(ea, "vtable__" + self.name, ida_name.SN_NOWARN)
                    break
        except Exception:
            pass

    # ------------------------------------------------------------------
    # information helpers used by the UI and by the report writer
    # ------------------------------------------------------------------
    @property
    def flags(self):
        return self.chd.flags if self.chd else ""

    @property
    def flag_names(self):
        return self.chd.flag_names if self.chd else ""

    @property
    def nb_bases(self):
        return self.chd.nb_classes if self.chd else 0

    @property
    def bcaea(self):
        return self.chd.bcaea if self.chd else ida_idaapi.BADADDR

    @property
    def bases(self):
        return self.chd.bca.bases if (self.chd and self.chd.bca) else []

    @property
    def paths(self):
        return self.chd.bca.paths if (self.chd and self.chd.bca) else {}

    def get_paths_by_offset(self, offset=None):
        """Hierarchy paths that belong to this vftable's COL offset."""
        if offset is None:
            offset = self.offset
        return self.paths.get(offset, [])

    @property
    def is_abstract(self):
        return self.pure_virtual_count > 0

    def get_hierarchy_order(self):
        """``A -> B -> C`` style description of this vftable's class paths."""
        result = []
        for path in self.get_paths_by_offset():
            result.append(" -> ".join([x.name + " ({},{},{})".format(x.mdisp, x.pdisp, x.vdisp)
                                       for x in path]))
        return ", ".join(result)

    def get_refeas(self):
        """Functions that reference the vftable (possible ctors/dtors)."""
        if self.refeas:
            return list(self.refeas)
        return []


class rtti_parser(object):

    platforms = [ida_idp.PLFM_386, ida_idp.PLFM_ARM]
    #: PE only (ida_ida.f_PE)
    formats = [ida_ida.f_PE]

    # ------------------------------------------------------------------
    @staticmethod
    def prepare(force=False):
        """Refresh the per-database context and register the RTTI structures."""
        global u, _TD_CACHE
        u = pci_utils.utils.get(refresh=True)
        _TD_CACHE = {}
        ida_compat.reset_cache()

        structs = (RTTITypeDescriptor, RTTIClassHierarchyDescriptor,
                   RTTIBaseClassDescriptor, RTTIBaseClassArray,
                   RTTICompleteObjectLocator)
        for struc in structs:
            struc.ensure_registered()
        # the pointer types are fixed up in a second pass so that forward
        # references (CHD -> BCA, COL -> CHD...) can be resolved
        for struc in structs:
            try:
                ida_compat.apply_member_types(struc.info, struc.get_members(), u.x64)
            except Exception:
                pass
        return u

    @staticmethod
    def get_refeas(vtable):
        """Functions that reference the vftable (possible constructors/dtors).

        Compiler generated code references the *start* of the vftable (the
        RTTI pointer in front of the first method), while PyClassInformer
        reports the address of the first method.  Both addresses are checked so
        that no constructor or destructor is missed.
        """
        result = []
        seen = set()
        targets = [vtable]
        if vtable - u.PTR_SIZE > 0:
            targets.append(vtable - u.PTR_SIZE)

        refeas = []
        for target in targets:
            refeas.extend(u.get_data_refs_to(target))

        for refea in refeas:
            try:
                f = ida_funcs.get_func(refea)
            except Exception:
                f = None
            if f is None:
                continue
            if f.start_ea in seen:
                continue
            seen.add(f.start_ea)
            result.append(f.start_ea)
        return sorted(result)

    @staticmethod
    def parse(start, end):
        data_size = end - start

        # for RTTI relevant structures creation
        ida_auto.auto_wait()

        # get COLs with CHDs and TDs
        result = {}
        if data_size <= u.PTR_SIZE:
            return result

        for offset in range(0, data_size - u.PTR_SIZE, u.PTR_SIZE):
            vtable = start + offset
            if not u.is_vtable(vtable):
                continue
            colea = u.get_ptr(vtable - u.PTR_SIZE)
            if not u.within(colea, u.valid_ranges) or (colea & 3) != 0:
                continue
            col = RTTICompleteObjectLocator(colea, vtable)
            # add rcol to the results
            if col.name is not None:
                col.refeas = rtti_parser.get_refeas(vtable)
                result[vtable] = col

        # may be this is a bug on IDA.
        # ida fails to apply a structure type to bytes under some conditions, although
        # create_struct returns True.  To avoid that, apply them again.
        ida_auto.auto_wait()
        rtti_parser.reapply_structs(result)
        ida_auto.auto_wait()

        # parse BCA
        prev_col = None
        vi_offs = {}
        for vtable in result:
            col = result[vtable]
            try:
                col_offs = u.get_col_offs(col, result)
            except Exception:
                col_offs = [col.offset]
            if prev_col and prev_col.name != col.name:
                vi_offs = {}

            # get BCDs
            try:
                for bcd, depth in col.chd.bca.parse_bca(col, col_offs, vi_offs):
                    pass
            except Exception as e:
                print("[PyClassInformer] Warning: parsing the class hierarchy of {} "
                      "at {:#x} failed ({}).".format(col.name, vtable, e))
            prev_col = col

        # may be this is a bug on IDA.
        # ida fails to apply a structure type to bytes under some conditions, although
        # create_struct returns True.  To avoid that, apply them again.
        ida_auto.auto_wait()
        rtti_parser.reapply_structs(result)
        ida_auto.auto_wait()
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def collect_struct_eas(result):
        """Map "struct name" -> {ea: size} of every structure found in ``result``."""
        eas = {
            TD_NAME: {},
            CHD_NAME: {},
            BCA_NAME: {},
            BCD_NAME: {},
            COL_NAME: {},
        }
        for vtable, col in result.items():
            eas[COL_NAME][col.ea] = RTTICompleteObjectLocator.size
            if col.td is not None:
                eas[TD_NAME][col.td.ea] = col.td.size
            if col.chd is not None:
                eas[CHD_NAME][col.chd.ea] = RTTIClassHierarchyDescriptor.size
                bca = col.chd.bca
                if bca is not None:
                    eas[BCA_NAME][bca.ea] = bca.size
                    for bcd in bca.bases:
                        eas[BCD_NAME][bcd.ea] = RTTIBaseClassDescriptor.size
                        if bcd.chdea != ida_idaapi.BADADDR:
                            eas[CHD_NAME][bcd.chdea] = RTTIClassHierarchyDescriptor.size
                        if bcd.td is not None:
                            eas[TD_NAME][bcd.td.ea] = bcd.td.size
        return eas

    @staticmethod
    def reapply_structs(result):
        """Work around IDA occasionally failing to apply a type silently."""
        strucs = {
            TD_NAME: RTTITypeDescriptor,
            CHD_NAME: RTTIClassHierarchyDescriptor,
            BCA_NAME: RTTIBaseClassArray,
            BCD_NAME: RTTIBaseClassDescriptor,
            COL_NAME: RTTICompleteObjectLocator,
        }
        eas = rtti_parser.collect_struct_eas(result)
        for name, entries in eas.items():
            if not entries:
                continue
            struc = strucs[name]
            if struc.info is None or not struc.info.applied:
                continue
            # xrefs to a type == instances of the type in the database
            try:
                applied = set(u.get_refs_to(struc.tid))
            except Exception:
                applied = set()
            missing = [ea for ea in entries if ea not in applied]
            if not missing:
                continue
            for ea in missing:
                ida_compat.apply_struct(ea, entries[ea], struc.info, force=True)

    # ------------------------------------------------------------------
    @staticmethod
    def summarize(result):
        """Return a dictionary of statistics about the parsed RTTI data."""
        summary = {
            "vftables": 0,
            "classes": 0,
            "class_names": 0,
            "vfuncs": 0,
            "unique_vfuncs": 0,
            "pure_virtual": 0,
            "abstract_classes": 0,
            "ref_funcs": 0,
            "multiple_inheritance": 0,
            "virtual_inheritance": 0,
            "ambiguous_inheritance": 0,
            "library_classes": 0,
            "user_classes": 0,
            "no_hierarchy": 0,
        }
        names = set()
        vfuncs = set()
        refs = set()
        abstract = set()
        mi = set()
        vi = set()
        ambiguous = set()
        libs = set()
        users = set()
        no_hierarchy = set()
        for vtable, col in result.items():
            summary["vftables"] += 1
            names.add(col.name)
            if col.libflag == col.LIBLIB:
                libs.add(col.name)
            else:
                # LIBNOTLIB, or not determined yet (set_libflag not run)
                users.add(col.name)
            summary["vfuncs"] += len(col.vfeas)
            summary["pure_virtual"] += col.pure_virtual_count
            if col.pure_virtual_count:
                abstract.add(col.name)
            vfuncs.update(col.vfeas)
            refs.update(col.refeas)

            if col.chd is None or not col.bases:
                no_hierarchy.add(col.name)
                continue
            if col.chd.attribute & CHD_MULTINH:
                mi.add(col.name)
            if col.chd.attribute & CHD_VIRTINH:
                vi.add(col.name)
            if col.chd.attribute & CHD_AMBIGUOUS:
                ambiguous.add(col.name)

        summary["multiple_inheritance"] = len(mi)
        summary["virtual_inheritance"] = len(vi)
        summary["ambiguous_inheritance"] = len(ambiguous)
        summary["library_classes"] = len(libs)
        summary["user_classes"] = len(users)
        summary["abstract_classes"] = len(abstract)
        summary["no_hierarchy"] = len(no_hierarchy)
        summary["classes"] = len(names)
        summary["class_names"] = len(names)
        summary["unique_vfuncs"] = len(vfuncs)
        summary["ref_funcs"] = len(refs)
        return summary

    @staticmethod
    def format_summary(summary):
        """Human readable version of :meth:`summarize`'s result."""
        keys = [
            ("vftables", "vftables"),
            ("classes", "classes (unique names)"),
            ("vfuncs", "virtual method slots"),
            ("unique_vfuncs", "unique virtual methods"),
            ("pure_virtual", "pure virtual slots"),
            ("abstract_classes", "abstract classes"),
            ("ref_funcs", "functions referring to vftables"),
            ("user_classes", "user (non library) classes"),
            ("library_classes", "library classes"),
            ("multiple_inheritance", "multiple inheritance"),
            ("virtual_inheritance", "virtual inheritance"),
            ("ambiguous_inheritance", "ambiguous inheritance"),
            ("no_hierarchy", "classes without hierarchy info"),
        ]
        return "\n".join("  {:<42} {}".format(label, summary.get(key, 0))
                         for key, label in keys)

    # ------------------------------------------------------------------
    @staticmethod
    def render(result, verbose=False):
        """Return the textual RTTI report (what :meth:`show` prints)."""
        out = []
        add = out.append
        for vtable in result:
            col = result[vtable]
            add("vtable at : " + hex(vtable))
            add("  COL at {:#x}: {} {} {} {} {:#x} {:#x}{}".format(
                col.ea, col.name, col.sig, col.offset, col.cdOffset,
                col.tdea, col.chdea,
                " " + hex(col.selfea) if col.selfea != ida_idaapi.BADADDR else ""))

            if col.td is not None:
                add("    TD  at {:#x}: {}{}".format(
                    col.td.ea, col.td.demangled,
                    " (%s)" % col.td.mangled if col.td.mangled else ""))

            if col.chd is not None:
                add("    CHD at {:#x}: {:#x} {}{} {} {:#x}".format(
                    col.chd.ea, col.chd.sig,
                    col.chd.flags,
                    " (%s)" % col.chd.flag_names if col.chd.flag_names else "",
                    col.chd.nb_classes, col.chd.bcaea))

                # get BCDs
                for bcd in col.bases:
                    add("    {}BCD at {:#x}: {} {} {:#x} {} {}{}{}".format(
                        " " * bcd.depth * 2, bcd.ea, bcd.name, bcd.pmd, bcd.tdea,
                        bcd.nb_cbs, bcd.attributes,
                        " (%s)" % bcd.flag_names if bcd.flag_names else "",
                        " " + hex(bcd.chdea) if bcd.chdea != ida_idaapi.BADADDR else ""))

            if not verbose:
                continue

            # virtual methods (the chooser shows a summary of them)
            if col.vfeas:
                add("    virtual methods ({}):".format(len(col.vfeas)))
                for ea in col.vfeas:
                    pure = " [pure]" if is_pure_virtual(ea) else ""
                    add("      {:#x}  {}{}".format(ea, func_name(ea) or "?", pure))

            if col.refeas:
                add("    functions referring to the vftable ({}):".format(len(col.refeas)))
                for ea in col.refeas:
                    add("      {:#x}  {}".format(ea, func_name(ea) or "?"))

        return "\n".join(out) + ("\n" if out else "")

    @staticmethod
    def show(result, verbose=False):
        """Print the parsed RTTI information to the Output window.

        ``verbose`` also lists the virtual methods and the functions that
        refer to each vftable (possible constructors / destructors).
        """
        text = rtti_parser.render(result, verbose=verbose)
        if text:
            sys.stdout.write(text)
        return text

    @staticmethod
    def render_summary(result, elapsed=None):
        """Return the summary of the parsed RTTI data (what :meth:`show_summary`
        prints)."""
        summary = rtti_parser.summarize(result)
        out = [
            "",
            "=" * 78,
            "PyClassInformer summary",
            "=" * 78,
            "  {:<42} {}".format("architecture", "x64" if u.x64 else "x86"),
            "  {:<42} {}".format("image base", hex(ida_nalt.get_imagebase())),
            "  {:<42} {}".format("scanned ranges", ", ".join(
                "{:#x}-{:#x}".format(s, e) for s, e in u.valid_ranges) or "-"),
            rtti_parser.format_summary(summary),
        ]
        if elapsed is not None:
            out.append("  {:<42} {:.2f}s".format("elapsed", elapsed))
        out.append("=" * 78)
        return "\n".join(out) + "\n"

    @staticmethod
    def show_summary(result, elapsed=None):
        text = rtti_parser.render_summary(result, elapsed=elapsed)
        sys.stdout.write(text)
        return text

    @staticmethod
    def is_binary_allowed():
        if ida_idp.ph.id not in rtti_parser.platforms:
            print("[PyClassInformer] Warning: The platform is not supported ({:#x}). "
                  "This only supports x86, x64, ARM and ARM64.".format(ida_idp.ph.id))
            return False
        if ida_ida.inf_get_filetype() not in rtti_parser.formats:
            import ida_loader
            print("[PyClassInformer] Warning: The binary format is not supported ({}). "
                  "This only supports PE.".format(ida_loader.get_file_type_name()))
            return False
        return True

    @staticmethod
    def run(alldata=False, icon=-1):
        result = {}

        # check if the binary you loaded is valid or not.
        if not rtti_parser.is_binary_allowed():
            return result

        # refresh the per database context and the RTTI structure definitions
        rtti_parser.prepare()

        # find vftables with relevant structures
        if u.rdata and not alldata:
            result = rtti_parser.parse(u.rdata.start_ea, u.rdata.end_ea)
        # if .rdata was not found, try multiple data segments
        else:
            # expand ranges to check to all data
            u.update_valid_ranges()

            # get all data segments' results
            for seg in pci_utils.utils.get_data_segments():
                result.update(rtti_parser.parse(seg.start_ea, seg.end_ea))
        return result
