"""Annotate the database with the parsed RTTI information.

Renaming the vftable and the virtual methods already helps, but the most useful
place for this information is right where it is used:

- the vftable pointer slot and every virtual method slot get a comment, so the
  ``.rdata`` view explains itself;
- the instructions that reference a vftable (the possible constructors and
  destructors) get a comment, which Hex-Rays shows inside the pseudocode of the
  function;
- the functions that reference a vftable get a function comment, and so do the
  virtual methods ("virtual method of Foo"), which Hex-Rays shows above the
  pseudocode;
- the five RTTI structures get a type comment, so they are documented in the
  Local Types view.

Comments created by the user are never overwritten: a comment is only replaced
when it already starts with :data:`PREFIX` (which makes repeated runs
idempotent).
"""

import ida_bytes
import ida_funcs
import ida_idaapi

ida_idaapi.require("pyclassinformer.ida_compat")
ida_idaapi.require("pyclassinformer.msvc_rtti")
ida_idaapi.require("pyclassinformer.pci_utils")
import pyclassinformer.ida_compat as ida_compat
import pyclassinformer.msvc_rtti as msvc_rtti
import pyclassinformer.pci_utils as pci_utils

#: every comment this module creates starts with this prefix
PREFIX = "[PyClassInformer]"

#: documentation of the RTTI structures (put in the Local Types view)
TYPE_COMMENTS = (
    ("RTTITypeDescriptor",
     "MSVC RTTI type descriptor (pVFTable, spare, name). The name is the "
     "mangled type of the class, e.g. .?AVFoo@@."),
    ("RTTIClassHierarchyDescriptor",
     "MSVC RTTI class hierarchy descriptor (signature, attributes, number of "
     "base classes, pointer to the base class array). The attributes say "
     "whether the hierarchy uses multiple/virtual/ambiguous inheritance."),
    ("RTTIBaseClassDescriptor",
     "MSVC RTTI base class descriptor (type descriptor, number of contained "
     "bases, mdisp/pdisp/vdisp, attributes, class hierarchy descriptor). "
     "mdisp/pdisp/vdisp describe the position of the base class subobject."),
    ("RTTIBaseClassArray",
     "MSVC RTTI base class array: one pointer per base class, in the order of "
     "a depth first walk of the hierarchy (image base relative on x64)."),
    ("RTTICompleteObjectLocator",
     "MSVC RTTI complete object locator (signature, offset, cdOffset, type "
     "descriptor, class hierarchy descriptor, self pointer on x64). One "
     "locator exists per vftable; 'offset' is the position of the vftable in "
     "the class."),
)


# --------------------------------------------------------------------------
def _compose(text):
    return PREFIX + " " + text


def is_our_comment(text):
    return bool(text) and text.startswith(PREFIX)


def _plural(count, singular, plural=None):
    if count == 1:
        return "{} {}".format(count, singular)
    if plural is None:
        plural = singular + "s"
    return "{} {}".format(count, plural)


def _count(counters, key):
    counters[key] = counters.get(key, 0) + 1


# --------------------------------------------------------------------------
# low level helpers
# --------------------------------------------------------------------------
def set_code_comment(ea, text, counters=None):
    """Set a comment on the item at ``ea`` (shown in the disassembly/pseudocode).

    Returns False when a comment of the user is already there.
    """
    if counters is None:
        counters = {}
    cmt = _compose(text)
    try:
        old = ida_bytes.get_cmt(ea, False) or ""
    except Exception:
        old = ""
    if old == cmt:
        return True
    if old and not is_our_comment(old):
        _count(counters, "skipped")
        return False
    try:
        ida_bytes.set_cmt(ea, cmt, False)
    except Exception:
        return False
    _count(counters, "comments")
    return True


def set_func_comment(funcea, text, counters=None):
    """Set the non repeatable comment of a function (shown above its pseudocode)."""
    if counters is None:
        counters = {}
    cmt = _compose(text)
    try:
        func = ida_funcs.get_func(funcea)
        if func is None:
            return False
        old = ida_funcs.get_func_cmt(func, False) or ""
    except Exception:
        return False
    if old == cmt:
        return True
    if old and not is_our_comment(old):
        _count(counters, "skipped")
        return False
    try:
        ida_funcs.set_func_cmt(func, cmt, False)
    except Exception:
        return False
    _count(counters, "func_comments")
    return True


def set_type_comment(name, text, counters=None):
    """Set the comment of the named type ``name`` (Local Types view)."""
    if counters is None:
        counters = {}
    cmt = _compose(text)
    tif = ida_compat.get_named_tinfo(name)
    if tif is None:
        return False
    try:
        old = tif.get_type_cmt() or ""
    except Exception:
        old = ""
    if old == cmt:
        return True
    if old and not is_our_comment(old):
        _count(counters, "skipped")
        return False
    try:
        # set_type_cmt() returns a tinfo_code_t (TERR_OK is 0, not False)
        if not ida_compat.terr_ok(tif.set_type_cmt(cmt)):
            return False
        # persist it (set_type_cmt only changes the in memory type)
        if not ida_compat.save_type(tif, name):
            return False
    except Exception:
        return False
    _count(counters, "type_comments")
    return True


# --------------------------------------------------------------------------
# the annotation itself
# --------------------------------------------------------------------------
def annotate(result, funcs=True, code=True, slots=True, types=True):
    """Annotate the database for the parsed RTTI data in ``result``.

    ``funcs`` adds function comments, ``code`` adds item comments (vftable
    pointer, locator, type descriptor, vftable reference), ``slots`` adds a
    comment per virtual method slot and ``types`` documents the RTTI
    structures.  Returns a dictionary of counters.
    """
    counters = {}
    if not result:
        return counters

    u = pci_utils.utils.get()
    ptr_size = u.PTR_SIZE

    #: function address -> the roles it plays ("virtual method of X", ...)
    roles = {}

    def add_role(funcea, text):
        roles.setdefault(funcea, [])
        if text not in roles[funcea]:
            roles[funcea].append(text)

    for vtable, col in result.items():
        if code:
            # the locator and the type descriptor themselves
            set_code_comment(col.ea, "complete object locator of {} (offset {:#x}, {})".format(
                col.name, col.offset, _plural(col.nb_bases, "base class", "base classes")), counters)
            if col.tdea != ida_idaapi.BADADDR:
                set_code_comment(col.tdea, "type descriptor of {}".format(col.name), counters)

            # the slot in front of the vftable holds the RTTI pointer
            set_code_comment(col.col_ptr_ea, "vftable of {} ({})".format(
                col.name, _plural(len(col.vfeas), "virtual method")), counters)

            # the instructions that load the vftable address (ctors/dtors)
            for refea in getattr(col, "refaddrs", []):
                set_code_comment(refea, "vftable of {} (constructor/destructor "
                                 "candidate)".format(col.name), counters)

        if slots:
            for i, vfea in enumerate(col.vfeas):
                set_code_comment(vtable + i * ptr_size, "{} vtable slot {}: {}".format(
                    col.name, i, msvc_rtti.func_name(vfea) or hex(vfea)), counters)

        if funcs:
            for vfea in col.vfeas:
                add_role(vfea, "virtual method of {}".format(col.name))
            for refea in col.refeas:
                add_role(refea, "possible constructor/destructor of {}".format(col.name))

    if funcs:
        # a function can be a virtual method of a class and a constructor
        # candidate of another one: one comment lists both roles
        for funcea, texts in roles.items():
            set_func_comment(funcea, "; ".join(texts), counters)

    if types:
        for name, text in TYPE_COMMENTS:
            set_type_comment(name, text, counters)

    return counters


def format_counters(counters):
    """Human readable one line summary of an :func:`annotate` result."""
    if not counters:
        return ""
    return ("added {} comments ({} functions, {} types); {} existing comments "
            "left untouched".format(counters.get("comments", 0),
                                    counters.get("func_comments", 0),
                                    counters.get("type_comments", 0),
                                    counters.get("skipped", 0)))
