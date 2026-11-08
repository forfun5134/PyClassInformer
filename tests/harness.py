"""Shared helpers for the offline PyClassInformer tests."""

import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# mock ida_* modules must win over everything else
MOCK_DIR = os.path.join(HERE, "mock_ida")
for path in (MOCK_DIR, HERE, ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)


def reset_modules():
    """Forget the state that IDAPython would keep between databases."""
    import structstore
    import image

    structstore.reset()
    image.IMAGE = image.Image()

    import pyclassinformer.ida_compat as ida_compat
    import pyclassinformer.pci_utils as pci_utils
    import pyclassinformer.msvc_rtti as msvc_rtti
    import pyclassinformer.lib_classes_checker as libchk
    import pyclassinformer.pci_report as pci_report
    import ida_kernwin

    pci_report.LAST_RESULT["result"] = None
    pci_report.LAST_RESULT["time"] = None
    del ida_kernwin.CHOSERS[:]
    del ida_kernwin.MENU_ATTACHMENTS[:]
    del ida_kernwin.TOOLBAR_ATTACHMENTS[:]
    del ida_kernwin.POPUP_ATTACHMENTS[:]
    del ida_kernwin.MESSAGES[:]
    del ida_kernwin.DOCK_CALLS[:]

    import idc
    if hasattr(idc, "JUMPED"):
        del idc.JUMPED[:]

    ida_compat.PREFER_LEGACY_STRUCT_API = True
    pci_utils.utils._instances.clear()
    libchk._checker = None

    for struc in (msvc_rtti.RTTITypeDescriptor, msvc_rtti.RTTIClassHierarchyDescriptor,
                  msvc_rtti.RTTIBaseClassDescriptor, msvc_rtti.RTTIBaseClassArray,
                  msvc_rtti.RTTICompleteObjectLocator):
        struc.info = None
        struc.tid = image.BADADDR
        struc.size = 0
        struc.offsets = {}
        struc._registered_key = None


def build(classes, x64=True, extra_setup=None, use=True, input_file=None,
          name_functions=True):
    """Build a synthetic image and make it the active database."""
    import fakepe

    reset_modules()
    img = fakepe.RTTIImage(x64=x64,
                           input_file=input_file or "C:/samples/test_%s.exe" % ("x64" if x64 else "x86"))
    img.name_functions = name_functions
    expected = img.build(classes)
    if extra_setup is not None:
        extra_setup(img)
    if use:
        img.use()
    return img, expected


def parse(img, alldata=True, force_typeinf=False):
    """Run the RTTI parser on the active image."""
    import pyclassinformer.ida_compat as ida_compat
    import pyclassinformer.msvc_rtti as msvc_rtti

    ida_compat.PREFER_LEGACY_STRUCT_API = not force_typeinf
    if img is not None:
        img.use()
    return msvc_rtti.rtti_parser.run(alldata=alldata)


def capture_stdout(func, *args, **kwargs):
    """Run ``func`` and return (result, output)."""
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        result = func(*args, **kwargs)
    finally:
        sys.stdout = old
    return result, buf.getvalue()


def quiet(func, *args, **kwargs):
    return capture_stdout(func, *args, **kwargs)[0]


SI_CLASSES = [
    {"name": "Animal", "bases": [], "vftables": [
        {"offset": 0, "methods": ["Animal::speak", "Animal::eat"]}]},
    {"name": "Dog", "bases": ["Animal"], "vftables": [
        {"offset": 0, "methods": ["Dog::speak", "Dog::fetch"]}]},
]

MI_CLASSES = [
    {"name": "Base1", "bases": [], "vftables": [{"offset": 0, "methods": ["Base1::a"]}]},
    {"name": "Base2", "bases": [], "vftables": [{"offset": 0, "methods": ["Base2::b"]}]},
    {"name": "Derived", "bases": ["Base1", "Base2"], "chd_flags": 1, "vftables": [
        {"offset": 0, "methods": ["Derived::a1", "Derived::x"]},
        {"offset": 8, "methods": ["Derived::b1"]}]},
]
