"""Mock of ida_idaapi for offline tests (behaves like IDA 9.5)."""
import importlib
import sys

BADADDR = 0xFFFFFFFFFFFFFFFF
IDA_SDK_VERSION = 950

PLUGIN_MULTI = 0x0001
PLUGIN_DRAW = 0x0002
PLUGIN_FIX = 0x0004
PLUGIN_PROC = 0x0008


def get_kernel_version():
    return "9.5"


class plugin_t(object):
    flags = 0
    comment = ""
    wanted_name = ""
    wanted_hotkey = ""
    help = ""

    def init(self):
        return 0

    def run(self, arg):
        return None

    def term(self):
        return None


class plugmod_t(object):
    def run(self, arg):
        return None


LOADED = []


def require(modulename, package=None):
    """Import a module and expose it in the caller's namespace.

    IDAPython's require() reloads the module when the file changed and makes
    the module available under its plain name in the caller's globals (that is
    how `ida_idaapi.require("pkg.sub"); pkg.sub.foo()` works).
    """
    mod = importlib.import_module(modulename, package)
    top = modulename.split(".")[0]
    frame = sys._getframe(1)
    frame.f_globals[top] = sys.modules[top]
    LOADED.append(modulename)
    return mod
