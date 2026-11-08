"""Mock of ida_typeinf.

Implements just enough of the type API for the RTTI structures:
create_udt()/add_udm()/set_udm_type()/set_named_type()/get_named_type() and the
udt/udm containers.  The semantics follow the documented IDAPython behaviour
(offsets and sizes are expressed in *bits* for udm_t).
"""
import image
import structstore

BADADDR = structstore.BADADDR

# type constants (values are arbitrary but unique)
BT_UNK = 0x00
BT_VOID = 0x01
BT_INT8 = 0x02
BT_INT16 = 0x03
BT_INT32 = 0x04
BT_INT64 = 0x05
BT_INT128 = 0x06
BTF_INT = BT_INT32
BTF_INT8 = BT_INT8
BTF_INT16 = BT_INT16
BTF_INT32 = BT_INT32
BTF_INT64 = BT_INT64
BTF_STRUCT = 0x100
BTF_UNION = 0x101

_RAW_SIZES = {
    BT_VOID: 0,
    BT_INT8: 8,
    BT_INT16: 16,
    BT_INT32: 32,
    BT_INT64: 64,
    BT_INT128: 128,
}

TAPTR_PTR32 = 0x01
TAPTR_PTR64 = 0x02

NTF_REPLACE = 0x0001
NTF_MAKE_UNIQUE = 0x0002
NTF_NO_DUP = 0x0004

ETF_MAY_DESTROY = 0x01
ETF_FORCENAME = 0x02
ETF_AUTONAME = 0x04

TERR_OK = 0
TERR_BAD_NAME = 1
TERR_BAD_TYPE = 2

TINFO_DEFINITE = 0x01
TINFO_GUESSED = 0x02

FRB_OFFSET = 0
FRB_NUMB = 1
FRB_NUMO = 2

STRMEM_NAME = 0x01
STRMEM_TYPE = 0x02


def _ptr_bytes():
    return 8 if image.IMAGE.bitness == 2 else 4


class value_repr_t(object):
    def __init__(self):
        self.vtype = -1
        self.ri = None

    def set_vtype(self, vtype):
        self.vtype = vtype
        return True

    def get_vtype(self):
        return self.vtype


class ptr_type_data_t(object):
    def __init__(self):
        self.obj_type = None
        self.taptr_bits = 0


class udm_t(object):
    def __init__(self):
        self.name = ""
        self.offset = 0     # in bits
        self.size = 0       # in bits
        self.type = None
        self.repr = value_repr_t()

    def set_value_repr(self, vrepr):
        self.repr = vrepr
        return True

    def is_varmember(self):
        return False

    def __repr__(self):
        return "<udm_t %s @%d size=%d>" % (self.name, self.offset, self.size)


class udt_type_data_t(object):
    def __init__(self):
        self.members = []

    def __len__(self):
        return len(self.members)

    def __iter__(self):
        return iter(self.members)

    def __getitem__(self, idx):
        return self.members[idx]

    def append(self, udm):
        self.members.append(udm)

    def size(self):
        return len(self.members)


class tinfo_t(object):
    def __init__(self, arg=None, tid=BADADDR):
        self.kind = "void"
        self.size_bits = 0
        self.obj = None
        self.name = None
        self.members = []      # [{name, offset(bits), size(bits), type, repr}]
        self._tid = BADADDR

        if isinstance(arg, tinfo_t):
            self._copy_from(arg)
        elif isinstance(arg, int) and not isinstance(arg, bool):
            self.kind = "int"
            self.size_bits = _RAW_SIZES.get(arg, 32)
        elif isinstance(arg, str):
            self._parse_decl(arg)
        if tid != BADADDR:
            self.get_type_by_tid(tid)

    # ------------------------------------------------------------------
    def _copy_from(self, other):
        self.kind = other.kind
        self.size_bits = other.size_bits
        self.obj = other.obj
        self.name = other.name
        self.members = [dict(m) for m in other.members]
        self._tid = other._tid

    def _parse_decl(self, decl):
        decl = decl.strip()
        if decl in ("void",):
            self.kind = "void"
        elif decl.endswith("*"):
            self.kind = "ptr"
            self.obj = tinfo_t("void")
            self.size_bits = _ptr_bytes() * 8
        else:
            self.kind = "int"
            self.size_bits = 32

    # ------------------------------------------------------------------
    def create_udt(self, udt, btf=BTF_STRUCT, **kwargs):
        self.kind = "udt"
        self.members = []
        self.size_bits = 0
        if isinstance(udt, udt_type_data_t):
            for udm in udt:
                self.members.append({"name": udm.name, "offset": udm.offset,
                                     "size": udm.size, "type": udm.type, "repr": None})
        return True

    def add_udm(self, udm, etf_flags=0):
        self.members.append({"name": udm.name, "offset": udm.offset,
                             "size": udm.size, "type": udm.type,
                             "repr": getattr(udm, "repr", None)})
        return True

    def set_udm_type(self, idx, mtif, etf_flags=0, repr=None):
        if idx < 0 or idx >= len(self.members):
            return False
        member = self.members[idx]
        member["type"] = mtif
        try:
            member["size"] = mtif.size_bits
        except AttributeError:
            pass
        if repr is not None:
            member["repr"] = repr
        return True

    def set_udm_repr(self, idx, vrepr):
        if 0 <= idx < len(self.members):
            self.members[idx]["repr"] = vrepr
            return True
        return False

    def get_udt_details(self, udt):
        if self.kind != "udt":
            return False
        udt.members = []
        for member in self.members:
            udm = udm_t()
            udm.name = member["name"]
            udm.offset = member["offset"]
            udm.size = member["size"]
            udm.type = member["type"]
            if member.get("repr") is not None:
                udm.repr = member["repr"]
            udt.append(udm)
        return True

    def find_udm(self, udm, strmem_flags=0):
        for i, member in enumerate(self.members):
            if member["name"] == udm.name:
                return i
        return -1

    def get_udt_nmembers(self):
        return len(self.members) if self.kind == "udt" else -1

    # ------------------------------------------------------------------
    def create_ptr(self, obj, **kwargs):
        if isinstance(obj, ptr_type_data_t):
            target = obj.obj_type
            taptr_bits = obj.taptr_bits
        else:
            target = obj
            taptr_bits = 0
        self.kind = "ptr"
        self.obj = target
        # "*__ptr32" is a four byte pointer even in a 64 bit database
        if taptr_bits & TAPTR_PTR32:
            self.size_bits = 32
        else:
            self.size_bits = _ptr_bytes() * 8
        self.taptr_bits = taptr_bits
        return True

    def create_array(self, obj, nelems=0):
        self.kind = "array"
        self.obj = obj
        self.size_bits = 0
        return True

    def is_ptr(self):
        return self.kind == "ptr"

    def is_array(self):
        return self.kind == "array"

    def is_struct(self):
        return self.kind == "udt"

    def is_union(self):
        return False

    def get_size(self):
        if self.kind == "udt":
            end = 0
            for member in self.members:
                end = max(end, member["offset"] + member["size"])
            return (end + 7) // 8
        if self.kind == "ptr":
            return _ptr_bytes()
        if self.kind == "array":
            return 0
        return (self.size_bits + 7) // 8

    def get_unpadded_size(self):
        return self.get_size()

    def get_tid(self):
        if self._tid != BADADDR:
            return self._tid
        if self.name:
            return structstore.get_tid(self.name)
        return BADADDR

    # ------------------------------------------------------------------
    def set_named_type(self, til, name, ntf_flags=0):
        # replacing an existing name keeps its tid, like IDA does
        entry = structstore.get_by_name(name)
        if entry is None:
            tid = structstore.new_struct(name)
        else:
            tid = entry["tid"]
        structstore.STRUCTS[name]["members"] = [{
            "name": m["name"],
            "offset": m["offset"] // 8,
            "size": m["size"] // 8,
            "type": m["type"],
        } for m in self.members]
        self.name = name
        self._tid = tid
        return TERR_OK

    def get_named_type(self, til, name, btf_flags=0):
        entry = structstore.get_by_name(name)
        if entry is None:
            return False
        self._load_entry(name, entry)
        return True

    def get_type_by_tid(self, tid):
        entry = structstore.get_by_tid(tid)
        if entry is None:
            return False
        for name, value in structstore.STRUCTS.items():
            if value is entry:
                self._load_entry(name, entry)
                return True
        return False

    def _load_entry(self, name, entry):
        self.kind = "udt"
        self.name = name
        self._tid = entry["tid"]
        self.members = []
        for member in entry["members"]:
            self.members.append({
                "name": member["name"],
                "offset": member["offset"] * 8,
                "size": member["size"] * 8,
                "type": member.get("type"),
                "repr": None,
            })

    def rename_type(self, name):
        return True

    # ------------------------------------------------------------------
    def get_type_cmt(self):
        entry = structstore.get_by_name(self.name) if self.name else None
        return entry.get("cmt", "") if entry else ""

    def set_type_cmt(self, cmt, is_regcmt=False, etf_flags=0):
        # real IDA returns a tinfo_code_t (TERR_OK == 0 on success)
        entry = structstore.get_by_name(self.name) if self.name else None
        if entry is None:
            return TERR_BAD_TYPE
        entry["cmt"] = cmt or ""
        return TERR_OK

    def __repr__(self):
        return "<tinfo_t %s %s size=%s>" % (self.kind, self.name, self.get_size())


def get_named_type_tid(name):
    """Mock of the IDA 9.x replacement for ida_struct.get_struc_id()."""
    return structstore.get_tid(name)


def apply_tinfo(ea, tif, flags=0):
    if tif is None:
        return False
    tid = tif.get_tid()
    if tid == BADADDR:
        return False
    return image.IMAGE.apply_struct(ea, tif.get_size() or 1, tid)


def parse_decls(til, decls, printer=None, hti_flags=0):
    return 0
