import time
import traceback

import ida_idaapi
import ida_kernwin

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.msvc_rtti")
ida_idaapi.require("pyclassinformer.pci_config")
ida_idaapi.require("pyclassinformer.pci_chooser")
ida_idaapi.require("pyclassinformer.method_classifier")
ida_idaapi.require("pyclassinformer.lib_classes_checker")
ida_idaapi.require("pyclassinformer.get_func_colors")
ida_idaapi.require("pyclassinformer.pci_report")
ida_idaapi.require("pyclassinformer.pci_annotate")
import pyclassinformer.msvc_rtti as msvc_rtti
import pyclassinformer.pci_config as pci_config
import pyclassinformer.pci_chooser as pci_chooser
import pyclassinformer.method_classifier as method_classifier
import pyclassinformer.lib_classes_checker as lib_classes_checker
import pyclassinformer.get_func_colors as get_func_colors
import pyclassinformer.pci_report as pci_report
import pyclassinformer.pci_annotate as pci_annotate


def _warn(message, e=None):
    print("[PyClassInformer] Warning: {}".format(message))
    if e is not None:
        print("[PyClassInformer]          {}: {}".format(type(e).__name__, e))
        traceback.print_exc()


def parse_rtti(config=None):
    """Parse the RTTI of the current database and return the result.

    This is the entry point for scripts that only need the parsing result.
    """
    if config is None:
        config = pci_config.pci_config()
    return msvc_rtti.rtti_parser.run(alldata=config.alldata)


def run_pci(config=None, icon=-1, export=None):
    """Run PyClassInformer on the current database.

    ``export`` is an optional path of a report file (``.json``, ``.csv`` or
    ``.txt``).  For compatibility, the function returns the Method Classifier
    tree (or None).  The parsed data is available through
    ``pyclassinformer.pci_report.LAST_RESULT["result"]``.
    """
    start = time.time()
    print("Starting PyClassInformer")
    if config is None:
        config = pci_config.pci_config()

    # find vftables with relevant structures
    result = {}
    try:
        result = msvc_rtti.rtti_parser.run(alldata=config.alldata, icon=icon)
    except Exception as e:
        _warn("RTTI parsing failed.", e)

    # show results
    tree = None
    if not result:
        # do not let the export actions report the data of a previous run
        pci_report.remember(None)
        print("Nothing found. RTTI might be disabled or it is not a Windows C++ program.")
        print("Done")
        return tree

    pci_report.remember(result)

    # classify library/user classes first: the summary and the coloring of the
    # list depend on it
    try:
        lib_classes_checker.set_libflag(result)
    except Exception as e:
        _warn("detecting known library classes failed.", e)

    # comment the vftables, the ctors/dtors (they show up in the pseudocode)
    # and the RTTI structures
    if getattr(config, "annotate", False):
        try:
            counters = pci_annotate.annotate(result)
            text = pci_annotate.format_counters(counters)
            if text:
                print("PyClassInformer: " + text + ".")
        except Exception as e:
            _warn("adding the RTTI comments failed.", e)

    if getattr(config, "rtti", True):
        try:
            msvc_rtti.rtti_parser.show(result, verbose=getattr(config, "verbose", False))
        except Exception as e:
            _warn("printing the parsed RTTI information failed.", e)

    if getattr(config, "summary", True):
        try:
            msvc_rtti.rtti_parser.show_summary(result, elapsed=time.time() - start)
        except Exception as e:
            _warn("printing the summary failed.", e)

    gen_func_color, lib_func_color = 0xffffffff, 0xffffffe9
    try:
        gen_func_color, lib_func_color = get_func_colors.get_gen_lib_func_colors()
    except Exception as e:
        _warn("obtaining the function colors failed.", e)

    try:
        pci_chooser.show_pci_chooser_t(result, icon=icon,
                                       libcolor=lib_func_color, defcolor=gen_func_color)
    except Exception as e:
        _warn("creating the result list failed.", e)

    try:
        tree = method_classifier.method_classifier(result, config=config, icon=icon)
    except Exception as e:
        _warn("the extra analysis failed.", e)

    # dock the tree next to the functions
    if tree:
        try:
            # On IDA 9.0, if the tree widget is directly docked in the same tab,
            # the Functions subview freezes. I think it is a bug.
            # To avoid it, once create it as a floating widget, then dock it to
            # the Functions subview.
            ida_kernwin.set_dock_pos(tree.title, None, ida_kernwin.DP_FLOATING)
            ida_kernwin.set_dock_pos(tree.title, 'Functions', ida_kernwin.DP_TAB)
        except Exception as e:
            _warn("docking the Method Classifier failed.", e)

    # report export (optional)
    if export is None and getattr(config, "export_report", False):
        export = True
    if export:
        try:
            if export is True:
                pci_report.export(result, fmt="json")
            else:
                pci_report.export(result, export)
        except Exception as e:
            _warn("exporting the report failed.", e)

    print("Done")
    return tree


def main():
    run_pci()


if __name__ == '__main__':
    main()
