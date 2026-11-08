"""Machine readable and human readable exports of the parsed RTTI data.

Everything in this module is UI independent (except for the file dialog in
:func:`export`), so it can be used from scripts::

    import pyclassinformer.pyclassinformer as pci
    result = pci.run_pci(config=None)          # or use rtti_parser.run()
    pyclassinformer.pci_report.export(result, "/tmp/report.json")

The JSON/CSV layouts are described in the README.
"""

import csv
import io
import json
import os
import time

import ida_idaapi
import ida_nalt

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.pci_utils")
ida_idaapi.require("pyclassinformer.msvc_rtti")
import pyclassinformer.pci_utils as pci_utils
import pyclassinformer.msvc_rtti as msvc_rtti

#: bumped whenever the JSON/CSV layout changes incompatibly
FORMAT_VERSION = 1

#: the result of the last run, used by the export actions
LAST_RESULT = {"result": None, "time": None}

#: Columns of the main chooser.  ``chcol`` is the ida_kernwin.Choose.CHCOL_*
#: suffix used by the chooser; the same order is used for the CSV export.
COLUMNS = (
    {"key": "vftable", "title": "Vftable", "width": 10, "chcol": "EA"},
    {"key": "methods", "title": "Methods", "width": 4, "chcol": "DEC"},
    {"key": "flags", "title": "Flags", "width": 4, "chcol": "PLAIN"},
    {"key": "type", "title": "Type", "width": 30, "chcol": "PLAIN"},
    {"key": "hierarchy", "title": "Hierarchy", "width": 40, "chcol": "PLAIN"},
    {"key": "offset", "title": "Offset", "width": 4, "chcol": "HEX"},
    {"key": "hierarchy_order", "title": "Hierarchy Order", "width": 40, "chcol": "PLAIN"},
    {"key": "bases", "title": "Bases", "width": 4, "chcol": "DEC"},
    {"key": "pure", "title": "Pure", "width": 4, "chcol": "DEC"},
    {"key": "refs", "title": "Ctors", "width": 4, "chcol": "DEC"},
    {"key": "lib", "title": "Lib", "width": 4, "chcol": "PLAIN"},
    {"key": "col", "title": "COL", "width": 10, "chcol": "EA"},
    {"key": "td", "title": "TD", "width": 10, "chcol": "EA"},
    {"key": "chd", "title": "CHD", "width": 10, "chcol": "EA"},
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def get_utils():
    return pci_utils.utils.get()


def sorted_vftables(result):
    """Deterministic iteration order: by class name, then by vftable address."""
    return [ea for ea, _ in sorted(result.items(), key=lambda kv: (kv[1].name or "", kv[0]))]


def hierarchy_summary(col, data, u=None):
    """``Foo: Bar, Baz;`` style description of the base classes of a vftable."""
    if u is None:
        u = get_utils()
    try:
        bases = u.get_col_bases(col, data)
    except Exception:
        bases = []

    result = "{}: ".format(col.name)
    if len(bases) > 0:
        # replace the class name with the first BCD's class name if they are
        # different from each other.  It occurs when the class is multiple
        # inheritance with multiple vftables
        i = 1
        if bases[0].name != col.name:
            result = "{}: ".format(bases[0].name)

        # get the result related to the offset of the COL
        result += ", ".join([x.name for x in bases][i:]) + ";" if len(bases) > 1 else ""
    return result


def hierarchy_order(col):
    """``A (0,-1,0) -> B (0,0,0)`` style description of the hierarchy paths."""
    result = []
    try:
        paths = col.get_paths_by_offset()
    except Exception:
        paths = []
    for path in paths:
        result.append(" -> ".join([x.name + " ({},{},{})".format(x.mdisp, x.pdisp, x.vdisp)
                                   for x in path]))
    return ", ".join(result)


def row_values(col, data, u=None, vftable=None):
    """Return the display strings of one vftable, in :data:`COLUMNS` order."""
    if u is None:
        u = get_utils()
    values = {
        "vftable": hex(vftable) if vftable is not None else "",
        "methods": "{}".format(len(col.vfeas)),
        "flags": col.flags,
        "type": col.name,
        "hierarchy": hierarchy_summary(col, data, u),
        "offset": hex(col.offset),
        "hierarchy_order": hierarchy_order(col),
        "bases": "{}".format(col.nb_bases),
        "pure": "{}".format(col.pure_virtual_count),
        "refs": "{}".format(len(col.refeas)),
        "lib": "lib" if col.libflag == col.LIBLIB else ("user" if col.libflag == col.LIBNOTLIB else ""),
        "col": hex(col.ea),
        "td": hex(col.tdea),
        "chd": hex(col.chdea),
    }
    return [values[c["key"]] for c in COLUMNS]


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------
def vftable_to_dict(col, vtable, data, u=None):
    if u is None:
        u = get_utils()

    d = {
        "vftable": vtable,
        "class": col.name,
        "col": col.ea,
        "signature": col.sig,
        "offset": col.offset,
        "cd_offset": col.cdOffset,
        "self": col.selfea if col.selfea != ida_idaapi.BADADDR else None,
        "type_descriptor": {
            "ea": col.tdea,
            "mangled": col.td.mangled if col.td else None,
            "demangled": col.td.demangled if col.td else None,
        },
        "class_hierarchy_descriptor": None,
        "flags": col.flags,
        "flag_names": [name for bit, _, name in msvc_rtti.CHD_FLAGS
                       if col.chd and col.chd.attribute & bit],
        "attributes": col.chd.attribute if col.chd else 0,
        "num_base_classes": col.nb_bases,
        "library": col.libflag == col.LIBLIB,
        "abstract": col.is_abstract,
        "pure_virtual_methods": col.pure_virtual_count,
        "methods": [{"ea": ea, "name": msvc_rtti.func_name(ea) or "",
                     "pure": msvc_rtti.is_pure_virtual(ea)} for ea in col.vfeas],
        "referers": [{"ea": ea, "name": msvc_rtti.func_name(ea) or ""} for ea in col.refeas],
        "hierarchy": [],
    }

    if col.chd is not None:
        d["class_hierarchy_descriptor"] = {
            "ea": col.chd.ea,
            "signature": col.chd.sig,
            "attributes": col.chd.attribute,
            "base_class_array": col.chd.bcaea,
        }

    # hierarchy paths that belong to this vftable
    for path in col.get_paths_by_offset():
        d["hierarchy"].append([{
            "class": bcd.name,
            "ea": bcd.ea,
            "depth": bcd.depth,
            "mdisp": bcd.mdisp,
            "pdisp": bcd.pdisp,
            "vdisp": bcd.vdisp,
            "attributes": bcd.attributes,
            "flag_names": [name for bit, _, name in msvc_rtti.BCD_FLAGS
                           if bcd.attributes & bit],
        } for bcd in path])

    # every hierarchy path of the class (may contain other vftables' paths)
    if col.chd is not None and col.chd.bca is not None:
        d["all_hierarchy_paths"] = []
        for offset in sorted(col.chd.bca.paths):
            for path in col.chd.bca.paths[offset]:
                d["all_hierarchy_paths"].append({
                    "offset": offset,
                    "path": [bcd.name for bcd in path],
                })
    return d


def build_json(result):
    """Return the JSON representation of ``result`` as a string."""
    summary = msvc_rtti.rtti_parser.summarize(result)
    u = get_utils()
    doc = {
        "tool": "PyClassInformer",
        "format_version": FORMAT_VERSION,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_file": _get_input_file_name(),
        "imagebase": _imagebase(),
        "architecture": "x64" if u.x64 else "x86",
        "summary": summary,
        "vftables": [vftable_to_dict(result[ea], ea, result, u)
                     for ea in sorted_vftables(result)],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False)


def _imagebase():
    try:
        return ida_nalt.get_imagebase()
    except Exception:
        return 0


def _get_input_file_name():
    try:
        return ida_nalt.get_input_file_path() or ""
    except Exception:
        return ""


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------
def build_csv(result):
    """Return the CSV representation of ``result`` as a string."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([c["title"] for c in COLUMNS])
    u = get_utils()
    for ea in sorted_vftables(result):
        writer.writerow(row_values(result[ea], result, u, vftable=ea))
    return buf.getvalue()


# --------------------------------------------------------------------------
# text
# --------------------------------------------------------------------------
def build_text(result, summary=True):
    """Return the full textual report (the same text printed to the Output
    window) as a string."""
    parts = []
    if summary:
        parts.append(msvc_rtti.rtti_parser.render_summary(result))
    parts.append(msvc_rtti.rtti_parser.render(result))
    return "".join(parts)


# --------------------------------------------------------------------------
# writing
# --------------------------------------------------------------------------
def _default_name(fmt):
    base = _get_input_file_name()
    if base:
        base = os.path.splitext(os.path.basename(base))[0]
    else:
        base = "rtti"
    return "{}_pci.{}".format(base, fmt)


def write(path, result, fmt=None):
    """Write a report to ``path``.  ``fmt`` is derived from the extension."""
    if fmt is None:
        fmt = os.path.splitext(path)[1].lstrip(".").lower() or "json"
    fmt = fmt.lower()
    if fmt == "json":
        data = build_json(result).encode("utf-8")
        with open(path, "wb") as f:
            f.write(data)
    elif fmt in ("csv",):
        # utf-8-sig so that Excel detects the encoding
        data = build_csv(result).encode("utf-8-sig")
        with open(path, "wb") as f:
            f.write(data)
    elif fmt in ("txt", "text", "md"):
        data = build_text(result).encode("utf-8")
        with open(path, "wb") as f:
            f.write(data)
    else:
        raise ValueError("unsupported report format: {}".format(fmt))
    return path


def export(result, path=None, fmt=None):
    """Export ``result``.

    When ``path`` is None an "ask file" dialog is displayed.  Returns the path
    of the written file, or None when the user canceled / the export failed.
    """
    import ida_kernwin

    if not result:
        print("[PyClassInformer] Nothing to export: no RTTI data.")
        return None

    if path is None:
        if fmt:
            default = _default_name(fmt)
            filters = "*.{}".format(fmt)
        else:
            default = _default_name("json")
            filters = "*.json;*.csv;*.txt"
        path = ida_kernwin.ask_file(1, default, filters)
        if not path:
            return None

    try:
        write(path, result, fmt)
    except Exception as e:
        print("[PyClassInformer] Failed to export the report to {}: {}".format(path, e))
        return None
    print("[PyClassInformer] Report exported to {}".format(path))
    return path


def remember(result):
    """Store the result of the latest run so the export actions can use it."""
    LAST_RESULT["result"] = result
    LAST_RESULT["time"] = time.time()


def export_last(path=None, fmt=None):
    """Export the report of the last run."""
    result = LAST_RESULT.get("result")
    if not result:
        print("[PyClassInformer] Nothing to export: run PyClassInformer first.")
        return None
    return export(result, path=path, fmt=fmt)
