"""Compatibility helpers shared by the PyClassInformer modules.

PyClassInformer tries to support IDA Pro 7.4 and later, but the IDAPython API
changed a lot between those releases:

  * IDA 8.5  : ida_struct / ida_enum started to move into ida_typeinf
  * IDA 9.0  : ida_struct / ida_enum were removed completely.  A "struct id"
               is now a plain type id (tid) handled by ida_typeinf
  * IDA 9.2  : IDA switched from PyQt5 to PySide6
  * IDA 9.3  : ida_kernwin.get_chooser_rows() may crash with GCRF_ALL on some
               chooser states
  * IDA 9.5  : Qt 6.12, XrefsTo() also reports pointers to Thumb functions
               (see ida_xref.XREF_EXACT), and add_struc_member() returns
               ida_typeinf.TERR_* codes

The helpers below isolate those differences.  Most importantly, RTTI
structures are described here by a small, version independent specification:

    members = [
        {"name": "pTypeDescriptor", "kind": MEMBER_PTR, "target": "RTTITypeDescriptor"},
        ...
    ]

The byte offsets of the members are computed in Python, so *parsing never
depends on IDA's structure layout*.  Applying the structure to the database
is a best effort cosmetic step: if the struct/type API is unavailable or
changed, the parser keeps working and the user only loses the nice listing.
"""

import idc
import ida_bytes
import ida_idaapi
import ida_nalt
import ida_typeinf

# --------------------------------------------------------------------------
# Member kinds used by the RTTI structure description
# --------------------------------------------------------------------------
#: A 4 byte integer (signature, offset, cdOffset, numBaseClasses, mdisp, ...)
MEMBER_DWORD = 0
#: A pointer stored as an image base relative value on x64 (4 bytes) and as an
#: absolute pointer on x86 (4 bytes as well).
MEMBER_PTR = 1
#: A real pointer sized pointer on both x86 and x64 (8 bytes on IDA64).
MEMBER_PTR_FULL = 2
#: A zero sized member that represents the NUL terminated name that follows
#: the fixed part of RTTITypeDescriptor.
MEMBER_STRLIT = 3

_MEMBER_SIZE_X86 = {
    MEMBER_DWORD: 4,
    MEMBER_PTR: 4,
    MEMBER_PTR_FULL: 4,
    MEMBER_STRLIT: 0,
}
_MEMBER_SIZE_X64 = {
    MEMBER_DWORD: 4,
    MEMBER_PTR: 4,
    MEMBER_PTR_FULL: 8,
    MEMBER_STRLIT: 0,
}


# --------------------------------------------------------------------------
# Version detection
# --------------------------------------------------------------------------
def get_ida_version():
    """Return the IDA version as a ``(major, minor)`` tuple.

    ``ida_idaapi.IDA_SDK_VERSION`` is the SDK the user's IDAPython was built
    against (760 for 7.6, 900 for 9.0, 950 for 9.5).  It is preferred over
    ``get_kernel_version()`` because the latter returns a string.
    """
    ver = getattr(ida_idaapi, "IDA_SDK_VERSION", None)
    try:
        ver = int(ver)
    except (TypeError, ValueError):
        ver = 0
    if ver > 0:
        return (ver // 100, (ver % 100) // 10)

    # very old or exotic builds: fall back to the kernel version string
    try:
        import ida_kernwin
        parts = [int(x) for x in ida_kernwin.get_kernel_version().split(".")]
        return (parts[0], parts[1] if len(parts) > 1 else 0)
    except Exception:
        return (0, 0)


IDA_VERSION = get_ida_version()
#: IDA 9.0 removed ida_struct / ida_enum and made structures plain types
IS_IDA_9_OR_LATER = IDA_VERSION >= (9, 0)
#: IDA 9.5 ships Qt 6.12 and reports Thumb function pointers in XrefsTo()
IS_IDA_95_OR_LATER = IDA_VERSION >= (9, 5)

try:
    import ida_struct
    #: True on IDA <= 8.4 (the module was removed in IDA 9.0)
    HAS_IDA_STRUCT = ida_struct is not None
except ImportError:
    ida_struct = None
    HAS_IDA_STRUCT = False


def has_module(name):
    """Return True if the given ``ida_*`` module can be imported."""
    try:
        __import__(name)
        return True
    except ImportError:
        return False


# --------------------------------------------------------------------------
# Cross references
# --------------------------------------------------------------------------
#: IDA 9.5 added ida_xref.XREF_EXACT.  With it, XrefsTo() no longer reports
#: pointers to Thumb/MIPS16 functions (function address + 1) as references to
#: the function.  Older versions do not have the flag, hence 0.
XREF_EXACT = getattr(__import__("ida_xref"), "XREF_EXACT", 0)


def xref_flags(base_flags=0, exact=True):
    """Return xref flags with ``XREF_EXACT`` added when it is available."""
    if exact:
        return base_flags | XREF_EXACT
    return base_flags


def get_imagebase():
    return ida_nalt.get_imagebase()


# --------------------------------------------------------------------------
# Structures / types
# --------------------------------------------------------------------------
class StructInfo(object):
    """Description of a structure that PyClassInformer relies on.

    ``offsets`` is computed in Python from the spec and therefore is always
    available, even when applying the layout to the database failed.
    """

    __slots__ = ("name", "tid", "size", "offsets", "backend", "applied")

    def __init__(self, name, size, offsets, tid=ida_idaapi.BADADDR, backend="none"):
        self.name = name
        self.size = size
        self.offsets = offsets
        self.tid = tid
        self.backend = backend
        #: True when the type is known to IDA (so it can be applied to bytes)
        self.applied = tid != ida_idaapi.BADADDR

    def offset(self, member, default=None):
        return self.offsets.get(member, default)

    def __bool__(self):
        return self.size > 0

    __nonzero__ = __bool__

    def __repr__(self):
        return "<StructInfo %s size=%d tid=%s backend=%s>" % (
            self.name, self.size, self.tid, self.backend)


def compute_layout(members, x64):
    """Compute member offsets and the struct size from a member spec."""
    sizes = _MEMBER_SIZE_X64 if x64 else _MEMBER_SIZE_X86
    offsets = {}
    offset = 0
    for m in members:
        offsets[m["name"]] = offset
        offset += sizes[m["kind"]]
    return offsets, offset


def _tinfo_by_name(name):
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, name):
        return tif
    return None


def _udm_index(tif, member_name):
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return -1
    for i, udm in enumerate(udt):
        if udm.name == member_name:
            return i
    return -1


def _ptr_to(tif_target, ptr32=False, array=False):
    """Build ``target *``, ``target *__ptr32`` or an array of them."""
    if ptr32:
        ptd = ida_typeinf.ptr_type_data_t()
        ptd.obj_type = tif_target
        ptd.taptr_bits = ida_typeinf.TAPTR_PTR32
        result = ida_typeinf.tinfo_t()
        if not result.create_ptr(ptd):
            return None
    else:
        result = ida_typeinf.tinfo_t()
        if not result.create_ptr(tif_target):
            return None
    if array:
        arr = ida_typeinf.tinfo_t()
        if arr.create_array(result):
            return arr
    return result


def _void_tinfo():
    return ida_typeinf.tinfo_t(ida_typeinf.BT_VOID)


def _set_member_type(tif, member_name, target_name, x64, array=False, full_ptr=False):
    """Give a pointer member a proper pointer type and offset representation."""
    idx = _udm_index(tif, member_name)
    if idx < 0:
        return False

    target = None
    if target_name:
        target = _tinfo_by_name(target_name)
    if target is None:
        target = _void_tinfo()

    ptr32 = x64 and not full_ptr
    new_type = _ptr_to(target, ptr32=ptr32, array=array)
    if new_type is None:
        return False

    repr_t = None
    try:
        if x64 and not full_ptr:
            # the member stores an image base relative value
            repr_t = build_val_repr(
                ida_typeinf.FRB_OFFSET, ida_nalt.REF_OFF64 | ida_nalt.REFINFO_RVAOFF)
        elif not x64:
            repr_t = build_val_repr(ida_typeinf.FRB_OFFSET, ida_nalt.REF_OFF32)
    except Exception:
        repr_t = None

    try:
        if not tif.set_udm_type(idx, new_type, 0, repr_t):
            return False
    except Exception:
        # older IDA versions do not accept a value representation here; the
        # type itself is still worth applying
        try:
            if not tif.set_udm_type(idx, new_type):
                return False
        except Exception:
            return False
    return True


def build_val_repr(vtype=ida_typeinf.FRB_OFFSET, flags=ida_nalt.REF_OFF64):
    """Create a ``value_repr_t`` for offset style members (IDA 8.x and later)."""
    vrepr = ida_typeinf.value_repr_t()
    vrepr.set_vtype(vtype)
    vrepr.ri.init(flags)
    return vrepr


def _save_tinfo(tif, name):
    """Persist changes made to a named type.  Returns True on success."""
    try:
        if hasattr(ida_typeinf, "TERR_OK"):
            return tif.set_named_type(None, name, ida_typeinf.NTF_REPLACE) == ida_typeinf.TERR_OK
        return bool(tif.set_named_type(None, name, ida_typeinf.NTF_REPLACE))
    except Exception:
        return False


def _create_struct_legacy(name, members, x64):
    """Create the structure with the idc structure API (IDA 7.x - 9.5)."""
    for api in ("add_struc", "add_struc_member", "get_struc_id"):
        if not hasattr(idc, api):
            return None

    old = idc.get_struc_id(name)
    if old != ida_idaapi.BADADDR:
        idc.del_struc(old)

    sid = idc.add_struc(ida_idaapi.BADADDR, name, False)
    if sid == ida_idaapi.BADADDR:
        return None

    ptr_type = ida_bytes.FF_QWORD if x64 else ida_bytes.FF_DWORD
    ptr_size = 8 if x64 else 4

    for m in members:
        kind = m["kind"]
        mname = m["name"]
        if kind == MEMBER_DWORD:
            idc.add_struc_member(sid, mname, ida_idaapi.BADADDR,
                                 ida_bytes.FF_DATA | ida_bytes.FF_DWORD, -1, 4)
        elif kind == MEMBER_PTR_FULL:
            idc.add_struc_member(sid, mname, ida_idaapi.BADADDR,
                                 ida_bytes.FF_DATA | ptr_type, -1, ptr_size)
        elif kind == MEMBER_PTR:
            idc.add_struc_member(sid, mname, ida_idaapi.BADADDR,
                                 ida_bytes.FF_DATA | ida_bytes.FF_DWORD | ida_bytes.FF_0OFF,
                                 -1, 4)
        elif kind == MEMBER_STRLIT:
            try:
                idc.add_struc_member(sid, mname, ida_idaapi.BADADDR,
                                     ida_bytes.FF_DATA | ida_bytes.FF_STRLIT,
                                     ida_nalt.STRTYPE_C, 0)
            except Exception:
                # a zero sized member is only cosmetic
                pass

    try:
        size = idc.get_struc_size(sid)
    except Exception:
        size = 0
    return sid, size


def _create_struct_typeinf(name, members, x64):
    """Create the structure with ida_typeinf only (works when idc's structure
    wrappers are missing, e.g. in some IDA 9.x/idllib configurations)."""
    if not hasattr(ida_typeinf, "udt_type_data_t"):
        return None

    tif = ida_typeinf.tinfo_t()
    udt = ida_typeinf.udt_type_data_t()
    if not tif.create_udt(udt, ida_typeinf.BTF_STRUCT):
        return None

    offsets, size = compute_layout(members, x64)
    sizes = _MEMBER_SIZE_X64 if x64 else _MEMBER_SIZE_X86
    for m in members:
        if m["kind"] == MEMBER_STRLIT:
            continue
        msize = sizes[m["kind"]]
        udm = ida_typeinf.udm_t()
        udm.name = m["name"]
        udm.offset = offsets[m["name"]] * 8
        udm.size = msize * 8
        udm.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32 if msize == 4
                                       else ida_typeinf.BTF_INT64)
        if not tif.add_udm(udm, ida_typeinf.ETF_MAY_DESTROY | ida_typeinf.ETF_FORCENAME):
            return None

    tid = ida_idaapi.BADADDR
    try:
        if tif.set_named_type(None, name, ida_typeinf.NTF_REPLACE):
            tid = tif.get_tid()
    except Exception:
        tid = ida_idaapi.BADADDR
    return tid, size


#: IDA 7.x-9.5 still ship the idc structure wrappers, which are the most
#: battle tested way to create a structure.  Tests flip this to exercise the
#: pure ida_typeinf backend that is used when the wrappers are unavailable.
PREFER_LEGACY_STRUCT_API = True


def _existing_struct_matches(name, offsets, size):
    """Is the type ``name`` already defined with the layout we expect?"""
    tif = _tinfo_by_name(name)
    if tif is None or not tif.is_struct():
        return None
    try:
        if tif.get_size() != size:
            return None
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return None
        existing = {}
        for udm in udt:
            existing[udm.name] = udm.offset // 8
    except Exception:
        return None
    for member_name, member_offset in offsets.items():
        if member_name not in existing or existing[member_name] != member_offset:
            return None
    try:
        return tif.get_tid()
    except Exception:
        return None


def create_struct(name, members, x64, prefer_legacy=None):
    """Create (or recreate) a RTTI structure and return a :class:`StructInfo`.

    The returned offsets always come from :func:`compute_layout`, so a failure
    to create the type in the database is not fatal for the RTTI parser.
    """
    if prefer_legacy is None:
        prefer_legacy = PREFER_LEGACY_STRUCT_API

    offsets, size = compute_layout(members, x64)

    info = StructInfo(name, size, offsets)

    # reuse a compatible type that is already there (a previous run, or a type
    # the user created).  This keeps the database stable across runs.
    tid = _existing_struct_matches(name, offsets, size)
    if tid is not None and tid != ida_idaapi.BADADDR:
        info.tid = tid
        info.applied = True
        info.backend = "existing"
        apply_member_types(info, members, x64)
        return info
    backends = []
    if prefer_legacy:
        backends = [_create_struct_legacy, _create_struct_typeinf]
    else:
        backends = [_create_struct_typeinf, _create_struct_legacy]

    for creator in backends:
        try:
            result = creator(name, members, x64)
        except Exception as e:
            print("[PyClassInformer] Warning: creating the type %s failed (%s)." % (name, e))
            result = None
        if not result:
            continue
        tid, db_size = result
        if tid == ida_idaapi.BADADDR or tid is None:
            continue
        if db_size and db_size != size:
            # The database layout must not influence parsing, but a mismatch
            # means that this backend did not create what we asked for - try
            # the next one.
            print("[PyClassInformer] Note: %s was created with size %d instead of %d."
                  % (name, db_size, size))
            continue
        info.tid = tid
        info.applied = True
        info.backend = "legacy" if creator is _create_struct_legacy else "typeinf"
        break

    # Give pointer members a proper pointer type.  Purely cosmetic, so all
    # failures are ignored.
    apply_member_types(info, members, x64)
    return info


def apply_member_types(info, members, x64):
    """Fix up the member types of a structure (pointers, offsets).

    This is a cosmetic step: PyClassInformer computes the byte offsets of the
    members in Python, so a failure here only affects how the structure is
    rendered in the listing.

    Call it again after all RTTI structures have been created; the structures
    reference each other (COL -> CHD -> BCA -> BCD -> TD), so forward
    references can only be resolved in a second pass.
    """
    if info is None or not members:
        return False
    tif = _tinfo_by_name(info.name)
    if tif is None:
        return False

    for m in members:
        if m["kind"] not in (MEMBER_PTR, MEMBER_PTR_FULL):
            continue
        _set_member_type(tif, m["name"], m.get("target"), x64,
                         array=m.get("array", False),
                         full_ptr=(m["kind"] == MEMBER_PTR_FULL))
    _save_tinfo(tif, info.name)
    return True


#: ea -> (size, tid) of the structures that were already applied
_APPLIED = {}


def reset_cache():
    """Forget which structures were applied (called for every new database)."""
    _APPLIED.clear()


def apply_struct(ea, size, info, force=False):
    """Apply the structure ``info`` to the bytes at ``ea``.

    ``size`` may be larger than the declared structure size (used for
    RTTITypeDescriptor, whose name follows the fixed part).
    """
    if not info or not info.applied or size <= 0:
        return False
    if not force and _APPLIED.get(ea) == (size, info.tid):
        # already done: applying a type twice is expensive and pointless
        return True
    try:
        ida_bytes.del_items(ea, ida_bytes.DELIT_DELNAMES, size)
    except Exception:
        pass
    try:
        if ida_bytes.create_struct(ea, size, info.tid):
            _APPLIED[ea] = (size, info.tid)
            return True
    except Exception:
        pass
    # ida_bytes.create_struct() is a thin wrapper around apply_tinfo(); use the
    # type API directly when it refuses to work (seen on some IDA versions).
    try:
        tif = ida_typeinf.tinfo_t()
        if tif.get_type_by_tid(info.tid):
            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                _APPLIED[ea] = (size, info.tid)
                return True
    except Exception:
        pass
    return False


def get_struct_tid(name):
    """Return the type/struct id of ``name`` or BADADDR."""
    try:
        tid = idc.get_struc_id(name)
        if tid != ida_idaapi.BADADDR:
            return tid
    except Exception:
        pass
    tif = _tinfo_by_name(name)
    if tif is not None:
        try:
            return tif.get_tid()
        except Exception:
            pass
    return ida_idaapi.BADADDR
