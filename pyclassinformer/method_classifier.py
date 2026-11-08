import ida_idaapi
import ida_funcs
import ida_name
import idautils

try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

tree_categorize = True
try:
    import ida_dirtree
    ida_dirtree.dirtree_t.find_entry
# For IDA 7.4 and 7.5
except ModuleNotFoundError:
    tree_categorize = False
# For IDA 7.6
except AttributeError:
    tree_categorize = False

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.pci_utils")
ida_idaapi.require("pyclassinformer.pci_config")
if tree_categorize:
    ida_idaapi.require("pyclassinformer.mc_tree")
    ida_idaapi.require("pyclassinformer.dirtree_utils")
    import pyclassinformer.mc_tree as mc_tree
    import pyclassinformer.dirtree_utils as dirtree_utils
import pyclassinformer.pci_utils as pci_utils
import pyclassinformer.pci_config as pci_config


def get_ref_funcs(data, vftable_ea):
    """Functions that refer to the vftable.

    ``rtti_parser`` already collected them while parsing; fall back to the
    xrefs of the vftable when the information is missing (e.g. when a caller
    passes data produced by an older version).
    """
    col = data[vftable_ea]
    refeas = getattr(col, "refeas", None)
    if refeas:
        return list(refeas)

    result = []
    seen = set()
    for refea in idautils.DataRefsTo(vftable_ea):
        f = ida_funcs.get_func(refea)
        if f is None or f.start_ea in seen:
            continue
        seen.add(f.start_ea)
        result.append(f.start_ea)
    return result


def change_dir_of_ctors_dtors(paths, data, dirtree):
    path_prefix = "/classes/"
    moved = 0

    # move virtual functions to its class folder
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue

        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name

        for funcea in get_ref_funcs(data, vftable_ea):
            func_name = ida_funcs.get_func_name(funcea)
            if func_name is None:
                continue
            # make a directory with a class name
            dst_path = path_prefix + class_name + "/possible ctors or dtors/"
            dirtree.mkdir(dst_path)

            # if the vfunc is at the top level, move it into the vftables folder.
            func_path = "/" + func_name

            # get the func path in the dir tree.
            dirtree_path = dirtree_utils.get_abs_path_by_inode(dirtree, funcea)

            # check if the function is at the top level or not.
            if func_path == dirtree_path:
                dirtree.rename(func_path, dst_path)
                moved += 1
    return moved


def change_dir_of_vfuncs(paths, data, dirtree):
    path_prefix = "/classes/"
    moved = 0

    # move virtual functions to its class folder
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue

        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name
        vfunc_eas = data[vftable_ea].vfeas

        # make a directory with a class name
        dst_path = path_prefix + class_name + "/virtual methods/"
        dirtree.mkdir(dst_path)

        # move virtual functions into the class name folder
        for vfea in vfunc_eas:
            func_name = ida_funcs.get_func_name(vfea)

            # sometimes, a function is not form of a function.
            # try to fix it or skip it
            if func_name is None:
                ida_funcs.add_func(vfea)
                f = ida_funcs.get_func(vfea)
                if f is None:
                    print("Warning: a virtual method at {:#x} in {} is not a function and "
                          "failed to add it as a function. Skipping...".format(vfea, class_name))
                    continue

                # get func name again after creating a function
                func_name = ida_funcs.get_func_name(vfea)
                if func_name is None:
                    print("Warning: the func name of the virtual method at {:#x} in {} could not "
                          "be obtained. Skipping...".format(vfea, class_name))
                    continue

            # if the vfunc is at the top level, move it into the class folder.
            func_path = "/" + func_name

            # get the func path in the dir tree.
            dirtree_path = dirtree_utils.get_abs_path_by_inode(dirtree, vfea)

            # check if the function is at the top level or not.
            if func_path == dirtree_path:
                dirtree.rename(func_path, dst_path)
                moved += 1

        # just create directories for rest of classes
        for bcd in path[1:]:
            dst_path = path_prefix + bcd.name
            dirtree.mkdir(dst_path)
    return moved


def rename_func(ea, prefix="", fn="", is_lib=False):
    func_name = ida_funcs.get_func_name(ea)

    # if a virtual method is not a valid function, skip it
    if func_name is None:
        return False

    renamed = False
    # rename the function name if it is a dummy name
    if func_name.startswith("sub_") or func_name.startswith("unknown_"):
        # change the function name to the specific name
        if fn:
            func_name = fn
        if ida_name.set_name(ea, prefix + func_name, ida_name.SN_NOCHECK | ida_name.SN_FORCE):
            renamed = True

    # add FUNC_LIB to make ida recognize the function as a part of static linked libraries
    if is_lib:
        f = ida_funcs.get_func(ea)
        if f is not None and not f.flags & ida_funcs.FUNC_LIB:
            f.flags |= ida_funcs.FUNC_LIB
            ida_funcs.update_func(f)
    return renamed


def rename_vftable_ref_funcs(paths, data, counters=None):
    if counters is None:
        counters = {}
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        col = data[vftable_ea]

        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name

        # check the class is a part of standard library classes such as STL and MFC
        is_lib = (col.libflag == col.LIBLIB)

        # get the func eas that refer to vftables and rename them
        for funcea in get_ref_funcs(data, vftable_ea):
            if rename_func(funcea, class_name.split("<")[0] + "::",
                           "possible_ctor_or_dtor", is_lib=is_lib):
                counters["ctors"] = counters.get("ctors", 0) + 1


def rename_funcs(func_eas, prefix="", is_lib=False):
    renamed = 0
    for ea in func_eas:
        if rename_func(ea, prefix, is_lib=is_lib):
            renamed += 1
    return renamed


def rename_vfuncs(paths, data, counters=None):
    if counters is None:
        counters = {}
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        col = data[vftable_ea]

        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name
        vfunc_eas = data[vftable_ea].vfeas

        # check the class is a part of standard library classes such as STL and MFC
        is_lib = (col.libflag == col.LIBLIB)

        counters["vfuncs"] = counters.get("vfuncs", 0) + rename_funcs(
            vfunc_eas, class_name.split("<")[0] + "::", is_lib=is_lib)


def get_base_classes(data):
    paths = {}
    for vftable_ea in data:
        # get COL
        col = data[vftable_ea]

        # get relevant BCDs mainly for multiple inheritance
        base_classes = pci_utils.utils.get().get_col_bases(col, data)

        # reverse the path because the path is reverse ordered.
        base_classes.reverse()
        paths[vftable_ea] = base_classes

    # sort the results by the class name and base class length
    return {x: paths[x] for x in sorted(sorted(paths, key=lambda key: [x.name for x in paths[key]]),
                                        key=lambda key: len(paths[key]))}


def method_classifier(data, config=None, icon=-1):
    if config is None:
        config = pci_config.pci_config()

    # check config values to execute or not
    if not config.exana and not config.mvvm and not config.mvcd and not config.rnvm and not config.rncd:
        return None

    # get base classes
    paths = get_base_classes(data)

    counters = {}
    # rename virtual methods in vftables
    if config.rnvm:
        rename_vfuncs(paths, data, counters)

    # rename functions that refer to vftables because they are constructors or destructors
    if config.rncd:
        rename_vftable_ref_funcs(paths, data, counters)

    tree = None
    moved_vfuncs = 0
    moved_ctors = 0
    if tree_categorize:
        # get dirtree and move vfuncs to their class directories
        for dirtype in [ida_dirtree.DIRTREE_FUNCS, ida_dirtree.DIRTREE_NAMES]:
            dirtree = ida_dirtree.get_std_dirtree(dirtype)
            if config.mvvm:
                moved_vfuncs += change_dir_of_vfuncs(paths, data, dirtree)
            if config.mvcd:
                moved_ctors += change_dir_of_ctors_dtors(paths, data, dirtree)

        # display dir tree
        if config.exana:
            tree = mc_tree.show_mc_tree_t(data, paths, icon=icon)
    else:
        print("Warning: Your IDA does not have ida_dirtree or find_entry in dirtree_t. "
              "Skip creating dirs for classes and moving functions into them.")

    if counters or moved_vfuncs or moved_ctors:
        print("PyClassInformer: renamed {} virtual methods and {} possible constructors or "
              "destructors; moved {} entries in Functions/Names.".format(
                  counters.get("vfuncs", 0), counters.get("ctors", 0),
                  moved_vfuncs + moved_ctors))

    return tree
