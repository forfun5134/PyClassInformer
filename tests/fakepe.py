"""Builds a synthetic MSVC RTTI layout inside the mock IDA image.

The generated layout follows the real MSVC rules:

  * RTTITypeDescriptor   : [pVFTable][spare][name]  (pVFTable/spare are full
                           pointers; the name is the type mangling)
  * RTTICompleteObjectLocator : RVAs on x64, absolute pointers on x86
  * RTTIClassHierarchyDescriptor : signature/attribute/numBaseClasses/pBCA
  * RTTIBaseClassArray   : array of pointers/RVAs to the BCDs
  * RTTIBaseClassDescriptor : pTD, numContainerBases, mdisp, pdisp, vdisp,
                              attributes, pCHD
  * vftable              : [pointer to the COL][method pointers...]

The class hierarchy of the BCA is emitted in the depth first order that MSVC
uses (class, its first base and that base's bases, then the next base...).
"""

import image
from image import Image, align_up, KIND_CODE, KIND_DATA


def mangle_type(name, kind="V"):
    """Mangle a class name the way MSVC stores it in a TypeDescriptor."""
    parts = [p for p in name.split("::")]
    parts.reverse()
    return ".?A" + kind + "@".join(parts) + "@@"


class Allocator(object):
    def __init__(self, start, end):
        self.cur = start
        self.end = end

    def alloc(self, size, alignment=4):
        ea = align_up(self.cur, alignment)
        if ea + size > self.end:
            raise RuntimeError("out of space: need %#x bytes at %#x" % (size, ea))
        self.cur = ea + size
        return ea


class RTTIImage(object):
    """Builds the image, keeps the expected results for the tests."""

    def __init__(self, x64=True, input_file="C:/samples/fake.exe"):
        if x64:
            imagebase = 0x140000000
            bitness = 2
            self.ptr_size = 8
        else:
            imagebase = 0x400000
            bitness = 1
            self.ptr_size = 4

        self.x64 = x64
        self.ptr_size = 8 if x64 else 4
        self.imagebase = imagebase
        self.img = Image(imagebase=imagebase, bitness=bitness, input_file=input_file)

        self.text = self.img.add_segment(imagebase + 0x1000, 0x2000, ".text", "CODE")
        self.rdata = self.img.add_segment(imagebase + 0x3000, 0x6000, ".rdata", "DATA")
        self.data = self.img.add_segment(imagebase + 0x9000, 0x1000, ".data", "DATA")

        self.text_alloc = Allocator(self.text.start_ea, self.text.end_ea)
        self.data_alloc = Allocator(self.rdata.start_ea, self.rdata.end_ea)

        #: when False, functions are left unnamed (IDA would show sub_XXX)
        self.name_functions = True
        self.expected = {"vftables": {}, "classes": {}}
        self.td_eas = {}
        self.func_eas = {}

    # ------------------------------------------------------------------
    def use(self):
        """Make this image the active mock database."""
        image.IMAGE = self.img
        return self

    def rva(self, ea):
        if self.x64:
            return ea - self.imagebase
        return ea

    def read_uint(self, ea, size):
        return self.img.read_uint(ea, size)

    # ------------------------------------------------------------------
    def add_function(self, name, size=0x10):
        ea = self.text_alloc.alloc(size, 0x10)
        self.img.define(ea, KIND_CODE, size)
        if self.name_functions:
            self.img.set_name(ea, name)
        import ida_funcs
        self.img.funcs[ea] = ida_funcs.func_t(ea, ea + size)
        self.func_eas[name] = ea
        return ea

    def _define_offset(self, ea, target, size=None):
        """Define a pointer/offset slot and its xref."""
        size = size or self.ptr_size
        self.img.define(ea, KIND_DATA, size)
        self.img.add_xref(ea, target, 1)
        return ea

    # ------------------------------------------------------------------
    def build(self, classes, extra_purecall=True):
        """Create the RTTI of ``classes`` and return the expected results.

        ``classes`` is a list of dicts:
            {"name": "Dog", "bases": ["Animal"], "chd_flags": 0,
             "vftables": [{"offset": 0, "methods": ["Dog::v1"]}]}
        """
        img = self.img

        # collect every type name (classes and bases)
        names = []
        for cls in classes:
            if cls["name"] not in names:
                names.append(cls["name"])
            for base in cls.get("bases", []):
                if base not in names:
                    names.append(base)

        # ---- type descriptors ----------------------------------------
        header = 16 if self.x64 else 8
        for name in names:
            mangled = mangle_type(name)
            size = header + len(mangled) + 1
            ea = self.data_alloc.alloc(align_up(size, 4))
            img.write_uint(ea, 0, self.ptr_size)                 # pVFTable
            img.write_uint(ea + self.ptr_size, 0, self.ptr_size)  # spare
            img.write_string(ea + header, mangled)
            self.td_eas[name] = ea

        # ---- per class hierarchy -------------------------------------
        class_info = {}
        for cls in classes:
            name = cls["name"]
            entries = [name] + list(cls.get("bases", []))
            # BCA layout: the class itself, then every base in order
            chd_ea = self.data_alloc.alloc(16)
            bca_ea = self.data_alloc.alloc(4 * len(entries))
            bcd_eas = [self.data_alloc.alloc(28) for _ in entries]
            class_info[name] = {"chd": chd_ea, "bca": bca_ea, "bcds": bcd_eas,
                                "entries": entries, "flags": cls.get("chd_flags", 0)}

        for cls in classes:
            name = cls["name"]
            info = class_info[name]
            # CHD
            img.write_uint(info["chd"], 0, 4)                        # signature
            img.write_uint(info["chd"] + 4, info["flags"], 4)        # attribute
            img.write_uint(info["chd"] + 8, len(info["entries"]), 4)  # numBaseClasses
            img.write_uint(info["chd"] + 12, self.rva(info["bca"]), 4)  # pBaseClassArray
            self.img.add_xref(info["chd"] + 12, info["bca"], 1)

            # BCA
            for i, bcd_ea in enumerate(info["bcds"]):
                img.write_uint(info["bca"] + i * 4, self.rva(bcd_ea), 4)
                self.img.add_xref(info["bca"] + i * 4, bcd_ea, 1)

            # BCDs
            for i, entry in enumerate(info["entries"]):
                bcd_ea = info["bcds"][i]
                nb_cbs = 0
                if i == 0:
                    nb_cbs = len(info["entries"]) - 1
                img.write_uint(bcd_ea, self.rva(self.td_eas[entry]), 4)   # pTypeDescriptor
                img.write_uint(bcd_ea + 4, nb_cbs, 4)                    # numContainerBases
                # mdisp/pdisp/vdisp describe the position of the base class
                mdisp, pdisp, vdisp = self._pmd(cls, entry)
                img.write_uint(bcd_ea + 8, mdisp & 0xFFFFFFFF, 4)        # mdisp
                img.write_uint(bcd_ea + 12, pdisp & 0xFFFFFFFF, 4)       # pdisp
                img.write_uint(bcd_ea + 16, vdisp & 0xFFFFFFFF, 4)       # vdisp
                img.write_uint(bcd_ea + 20, 0x40, 4)                     # attributes (HASPCHD)
                img.write_uint(bcd_ea + 24, self.rva(info["chd"]), 4)    # pClassDescriptor

        # ---- vftables -------------------------------------------------
        for cls in classes:
            name = cls["name"]
            info = class_info[name]
            for vt in cls.get("vftables", []):
                col_ea = self.data_alloc.alloc(24 if self.x64 else 20, self.ptr_size)
                col_ptr_ea = self.data_alloc.alloc(self.ptr_size * (len(vt["methods"]) + 1),
                                                   self.ptr_size)
                vtable_ea = col_ptr_ea + self.ptr_size

                # COL
                img.write_uint(col_ea, 1 if self.x64 else 0, 4)          # signature
                img.write_uint(col_ea + 4, vt.get("offset", 0), 4)       # offset
                img.write_uint(col_ea + 8, vt.get("cd_offset", 0), 4)    # cdOffset
                img.write_uint(col_ea + 12, self.rva(self.td_eas[name]), 4)   # pTypeDescriptor
                img.write_uint(col_ea + 16, self.rva(info["chd"]), 4)        # pClassDescriptor
                if self.x64:
                    img.write_uint(col_ea + 20, self.rva(col_ea), 4)         # pSelf
                self.img.add_xref(col_ea + 12, self.td_eas[name], 1)
                self.img.add_xref(col_ea + 16, info["chd"], 1)

                # [0] = pointer to the COL, [1..] = method pointers
                img.write_uint(col_ptr_ea, col_ea if not self.x64 else col_ea, self.ptr_size)
                self._define_offset(col_ptr_ea, col_ea)

                method_eas = []
                for i, method in enumerate(vt["methods"]):
                    slot = vtable_ea + i * self.ptr_size
                    if method.startswith("@data"):
                        # a slot that does not point to code (e.g. a pointer to
                        # a data structure): the method walk must stop here
                        target = vt.get("data_target", self.rdata.start_ea)
                        img.write_uint(slot, target, self.ptr_size)
                        self._define_offset(slot, target)
                        continue
                    fea = self.func_eas.get(method)
                    if fea is None:
                        fea = self.add_function(method)
                    method_eas.append(fea)
                    img.write_uint(slot, fea, self.ptr_size)
                    self._define_offset(slot, fea)

                # a constructor that stores the vftable pointer (references the
                # COL slot, like the real compiler generated code)
                ctor_ea = self.add_function("{}::ctor".format(name.split("::")[-1]))
                self.img.add_xref(ctor_ea, col_ptr_ea, 1)

                self.expected["vftables"][vtable_ea] = {
                    "class": name,
                    "col": col_ea,
                    "col_ptr": col_ptr_ea,
                    "offset": vt.get("offset", 0),
                    "cd_offset": vt.get("cd_offset", 0),
                    "methods": method_eas,
                    "ctor": ctor_ea,
                    "bases": list(cls.get("bases", [])),
                    "flags": cls.get("chd_flags", 0),
                    "chd": info["chd"],
                    "bca": info["bca"],
                    "td": self.td_eas[name],
                }

            self.expected["classes"][name] = {
                "td": self.td_eas[name],
                "chd": info["chd"],
                "bca": info["bca"],
                "bases": list(cls.get("bases", [])),
                "flags": cls.get("chd_flags", 0),
            }

        if extra_purecall:
            # "_purecall" is the CRT helper that MSVC puts in the vftable slot
            # of a pure virtual method
            self.add_function("_purecall")

        self.data_alloc.cur = align_up(self.data_alloc.cur, 8)
        return self.expected

    # ------------------------------------------------------------------
    def _pmd(self, cls, entry):
        """Return the (mdisp, pdisp, vdisp) of a base class in a hierarchy."""
        if entry == cls["name"]:
            return (0, -1, 0)
        bases = cls.get("bases", [])
        if entry in bases:
            index = bases.index(entry)
            # single inheritance: the base is at offset 0
            if len(bases) == 1:
                return (0, -1, 0)
            # multiple inheritance: each base has its own subobject
            return (8 * index, -1, 0)
        # indirect base
        return (0, -1, 0)

    # ------------------------------------------------------------------
    def add_bogus_rtti(self):
        """Add a fake COL whose signature is invalid (must be ignored)."""
        ea = self.data_alloc.alloc(20, self.ptr_size)
        self.img.write_uint(ea, 0xDEADBEEF, 4)
        col_ptr_ea = self.data_alloc.alloc(self.ptr_size * 2, self.ptr_size)
        self.img.write_uint(col_ptr_ea, ea, self.ptr_size)
        self._define_offset(col_ptr_ea, ea)
        vtable_ea = col_ptr_ea + self.ptr_size
        fea = self.add_function("bogus_method")
        self.img.write_uint(vtable_ea, fea, self.ptr_size)
        self._define_offset(vtable_ea, fea)
        return vtable_ea
