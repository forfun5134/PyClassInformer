import ida_kernwin
import ida_funcs
import ida_idaapi

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.qtutils")
import pyclassinformer.qtutils as qtutils

DEFAULT_GEN_COLOR = 0xffffffff
DEFAULT_LIB_COLOR = 0xffffffe9
DEFAULT_LIB_COLOR_DARK = 0xff685328


def get_chooser_data(chooser="Functions"):
    """Return the rows of the Functions chooser (IDA 8.4 or later)."""
    cri = ida_kernwin.chooser_row_info_vec_t()
    ida_kernwin.get_chooser_rows(cri, chooser, 0)
    if cri.size() == 0:
        # for IDA 9.3
        # The version might have a bug and it crashes when calling
        # get_chooser_rows with GCRF_ALL
        # To avoid that, return None if the first line returns empty.
        return None
    ida_kernwin.get_chooser_rows(cri, chooser, ida_kernwin.GCRF_ALL)
    return cri


def get_func_color(cri, f):
    if f is None:
        return -1
    for r in cri:
        try:
            # the third column of the Functions chooser is the address
            fea = int(r.texts[2], 16)
        except (ValueError, IndexError, TypeError):
            continue
        if fea == f.start_ea:
            return r.attrs.color
    return -1


def get_libfunc():
    for n in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(n)
        if f.flags & ida_funcs.FUNC_LIB:
            return f
    return None


def get_genfunc():
    for n in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(n)
        if not f.flags & ida_funcs.FUNC_LIB and not f.flags & ida_funcs.FUNC_LUMINA and not f.flags & ida_funcs.FUNC_THUNK:
            return f
    return None


def get_gen_lib_func_colors():
    """Return the colors IDA uses for user and library functions."""
    cri = None
    try:
        # IDA 8.4 or later only has chooser_row_info_vec_t and get_chooser_rows
        cri = get_chooser_data()
    except AttributeError:
        cri = None
    except Exception:
        cri = None

    gen_func_color = -1
    lib_func_color = -1

    if cri is not None:
        try:
            gen_func_color = get_func_color(cri, get_genfunc())
        except Exception:
            gen_func_color = -1
        try:
            lib_func_color = get_func_color(cri, get_libfunc())
        except Exception:
            lib_func_color = -1

    # if something is wrong, set default colors
    if gen_func_color < 0:
        gen_func_color = DEFAULT_GEN_COLOR
    if lib_func_color < 0:
        lib_func_color = DEFAULT_LIB_COLOR
        dark = False
        # check if dark mode is enabled or not
        try:
            dark = qtutils.dark_mode_checker_t.is_dark_mode()
        except Exception:
            pass
        # set the default dark mode color on IDA
        if dark:
            lib_func_color = DEFAULT_LIB_COLOR_DARK

    return gen_func_color, lib_func_color


#print([hex(x) for x in get_gen_lib_func_colors()])
