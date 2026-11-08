"""Tests of the helper modules (ida_compat, pci_utils, qtutils, lib classes)."""

import unittest

import harness


class TestIDACompat(unittest.TestCase):

    def setUp(self):
        harness.reset_modules()

    def test_version(self):
        import pyclassinformer.ida_compat as ida_compat
        self.assertEqual(ida_compat.IDA_VERSION, (9, 5))
        self.assertTrue(ida_compat.IS_IDA_9_OR_LATER)
        self.assertTrue(ida_compat.IS_IDA_95_OR_LATER)
        # the mock does not ship ida_struct, exactly like IDA 9.x
        self.assertFalse(ida_compat.HAS_IDA_STRUCT)

    def test_xref_exact_flag_is_used_when_available(self):
        import pyclassinformer.ida_compat as ida_compat
        import ida_xref
        self.assertEqual(ida_compat.XREF_EXACT, ida_xref.XREF_EXACT)
        self.assertEqual(ida_compat.xref_flags(0), ida_xref.XREF_EXACT)
        self.assertEqual(ida_compat.xref_flags(1), 1 | ida_xref.XREF_EXACT)
        self.assertEqual(ida_compat.xref_flags(0, exact=False), 0)

    def test_as_text_accepts_bytes_and_str(self):
        """IDA 9.0 made the string getters return str; older ones return bytes."""
        import pyclassinformer.ida_compat as ida_compat
        self.assertEqual(ida_compat.as_text(b"CODE"), "CODE")
        self.assertEqual(ida_compat.as_text("CODE"), "CODE")
        self.assertEqual(ida_compat.as_text(None), "")
        self.assertEqual(ida_compat.as_text(None, "x"), "x")
        self.assertEqual(ida_compat.as_text(7), "7")

    def test_struct_layouts_for_both_bitnesses(self):
        import pyclassinformer.msvc_rtti as msvc_rtti
        import pyclassinformer.ida_compat as ida_compat

        expectations = [
            (msvc_rtti.TD_MEMBERS, True, 16),
            (msvc_rtti.TD_MEMBERS, False, 8),
            (msvc_rtti.CHD_MEMBERS, True, 16),
            (msvc_rtti.CHD_MEMBERS, False, 16),
            (msvc_rtti.BCD_MEMBERS, True, 28),
            (msvc_rtti.BCD_MEMBERS, False, 28),
            (msvc_rtti.COL_MEMBERS, True, 20),
            (msvc_rtti.COL_MEMBERS, False, 20),
            (msvc_rtti.COL_MEMBERS_X64, True, 24),
        ]
        for members, x64, size in expectations:
            offsets, computed = ida_compat.compute_layout(members, x64)
            self.assertEqual(computed, size, (members[0]["name"], x64))
            self.assertEqual(sorted(offsets), sorted(m["name"] for m in members))

    def test_create_struct_creates_the_named_type(self):
        import pyclassinformer.msvc_rtti as msvc_rtti
        import pyclassinformer.ida_compat as ida_compat
        import structstore

        for prefer_legacy in (True, False):
            structstore.reset()
            ida_compat.PREFER_LEGACY_STRUCT_API = prefer_legacy
            info = ida_compat.create_struct(msvc_rtti.COL_NAME, msvc_rtti.COL_MEMBERS_X64, True)
            self.assertTrue(info.applied)
            self.assertEqual(info.size, 24)
            self.assertEqual(info.offset("offset"), 4)
            self.assertNotEqual(structstore.get_by_name(msvc_rtti.COL_NAME), None)
            self.assertEqual(structstore.struct_size(msvc_rtti.COL_NAME), 24)

    def test_default_backend_follows_the_documented_guidance(self):
        """tinfo_t.create_udt()/add_udm() from IDA 9.0 on, idc wrappers before."""
        import pyclassinformer.msvc_rtti as msvc_rtti
        import pyclassinformer.ida_compat as ida_compat
        import structstore

        ida_compat.PREFER_LEGACY_STRUCT_API = None
        structstore.reset()
        info = ida_compat.create_struct(msvc_rtti.COL_NAME, msvc_rtti.COL_MEMBERS_X64, True)
        self.assertEqual(info.backend, "typeinf")
        self.assertEqual(info.size, 24)

        # simulate IDA 8.4, where ida_struct still existed and was preferred
        saved = (ida_compat.IS_IDA_9_OR_LATER, ida_compat.IDA_VERSION)
        try:
            ida_compat.IS_IDA_9_OR_LATER = False
            ida_compat.IDA_VERSION = (8, 4)
            structstore.reset()
            info = ida_compat.create_struct(msvc_rtti.COL_NAME, msvc_rtti.COL_MEMBERS_X64, True)
            self.assertEqual(info.backend, "legacy")
            self.assertEqual(info.size, 24)
        finally:
            ida_compat.IS_IDA_9_OR_LATER, ida_compat.IDA_VERSION = saved

    def test_a_compatible_type_is_reused(self):
        import pyclassinformer.msvc_rtti as msvc_rtti
        import pyclassinformer.ida_compat as ida_compat

        first = ida_compat.create_struct(msvc_rtti.BCD_NAME, msvc_rtti.BCD_MEMBERS, True)
        second = ida_compat.create_struct(msvc_rtti.BCD_NAME, msvc_rtti.BCD_MEMBERS, True)
        self.assertEqual(first.tid, second.tid)
        self.assertEqual(second.backend, "existing")

    def test_terr_ok(self):
        """terr_t values must not be read as booleans (TERR_OK == 0)."""
        import pyclassinformer.ida_compat as ida_compat
        self.assertTrue(ida_compat.terr_ok(True))
        self.assertFalse(ida_compat.terr_ok(False))
        self.assertTrue(ida_compat.terr_ok(0))     # TERR_OK
        self.assertFalse(ida_compat.terr_ok(1))    # an error

    def test_typeinf_backend_survives_a_terr_style_return(self):
        """IDA may return a terr_t (0 == OK) instead of a bool."""
        import pyclassinformer.msvc_rtti as msvc_rtti
        import pyclassinformer.ida_compat as ida_compat
        import ida_typeinf
        import structstore

        original = ida_typeinf.tinfo_t.set_named_type

        def terr_style(self, til, name, ntf_flags=0):
            original(self, til, name, ntf_flags)
            return 0     # TERR_OK

        try:
            ida_typeinf.tinfo_t.set_named_type = terr_style
            structstore.reset()
            ida_compat.PREFER_LEGACY_STRUCT_API = False
            info = ida_compat.create_struct(msvc_rtti.CHD_NAME, msvc_rtti.CHD_MEMBERS, True)
            self.assertEqual(info.backend, "typeinf")
            self.assertTrue(info.applied)
            self.assertEqual(structstore.struct_size(msvc_rtti.CHD_NAME), 16)
        finally:
            ida_typeinf.tinfo_t.set_named_type = original

    def test_get_struct_tid(self):
        import pyclassinformer.msvc_rtti as msvc_rtti
        import pyclassinformer.ida_compat as ida_compat
        info = ida_compat.create_struct(msvc_rtti.TD_NAME, msvc_rtti.TD_MEMBERS, True)
        self.assertEqual(ida_compat.get_struct_tid(msvc_rtti.TD_NAME), info.tid)
        self.assertEqual(ida_compat.get_struct_tid("does_not_exist"), ida_compat.ida_idaapi.BADADDR)

    def test_apply_struct_ignores_invalid_info(self):
        import pyclassinformer.ida_compat as ida_compat
        info = ida_compat.StructInfo("nope", 4, {"a": 0})
        self.assertFalse(ida_compat.apply_struct(0x1000, 4, info))
        self.assertFalse(ida_compat.apply_struct(0x1000, 0, None))


class TestPCIUtils(unittest.TestCase):

    def setUp(self):
        self.img, self.expected = harness.build(harness.SI_CLASSES, x64=True)
        import pyclassinformer.pci_utils as pci_utils
        self.pci_utils = pci_utils
        self.u = pci_utils.utils.get(refresh=True)

    def test_get_strlit(self):
        info = list(self.expected["vftables"].values())[0]
        td_ea = info["td"] + 16
        self.assertEqual(self.u.get_strlit(td_ea), b".?AVAnimal@@")
        self.assertEqual(self.u.get_strlen(td_ea), len(b".?AVAnimal@@"))
        self.assertIsNone(self.u.get_strlit(0))

    def test_utils_instance_is_cached_per_database(self):
        self.assertIs(self.pci_utils.utils.get(), self.u)
        other, _ = harness.build(harness.SI_CLASSES, x64=False)
        u2 = self.pci_utils.utils.get()
        self.assertIsNot(u2, self.u)
        self.assertFalse(u2.x64)

    def test_is_vtable(self):
        for ea, info in self.expected["vftables"].items():
            self.assertTrue(self.u.is_vtable(ea))
            # the RTTI pointer slot in front of the vftable is not a vftable
            self.assertFalse(self.u.is_vtable(info["col_ptr"]))
            # an address inside the vftable is not the vftable start
            self.assertFalse(self.u.is_vtable(ea + self.u.PTR_SIZE))

    def test_get_vtbl_methods_stops_at_non_code(self):
        classes = [{"name": "Weird", "bases": [], "vftables": [
            {"offset": 0, "methods": ["Weird::a", "@data", "Weird::b"]}]}]
        img, expected = harness.build(classes, x64=True)
        u = self.pci_utils.utils.get(refresh=True)
        ea = list(expected["vftables"])[0]
        self.assertEqual(list(self.pci_utils.get_vtbl_methods(ea, u=u)),
                         [img.func_eas["Weird::a"]])

    def test_thumb_bit_is_cleared_on_arm32(self):
        self.u.is_arm32 = True
        self.assertEqual(self.u.normalize_code_ptr(0x1001), 0x1000)
        self.assertEqual(self.u.normalize_code_ptr(0x1000), 0x1000)
        self.u.is_arm32 = False
        self.assertEqual(self.u.normalize_code_ptr(0x1001), 0x1001)

    def test_to_signed32(self):
        self.assertEqual(self.u.to_signed32(0xFFFFFFFF), -1)
        self.assertEqual(self.u.to_signed32(0x80000000), -0x80000000)
        self.assertEqual(self.u.to_signed32(8), 8)

    def test_in_text_and_valid_ptr(self):
        self.assertTrue(self.u.in_text(self.img.text.start_ea))
        self.assertFalse(self.u.in_text(self.img.rdata.start_ea))
        self.assertTrue(self.u.valid_ptr(self.img.rdata.start_ea))
        self.assertFalse(self.u.valid_ptr(0))
        self.assertFalse(self.u.valid_ptr(0xFFFFFFFFFFFFFFFF))


class TestBytesTolerance(unittest.TestCase):
    """The plugin must not depend on str vs bytes of the string getters."""

    def setUp(self):
        self.img, self.expected = harness.build(harness.SI_CLASSES, x64=True)

    def test_bytes_segment_class_is_understood(self):
        import ida_segment
        import pyclassinformer.pci_utils as pci_utils
        u = pci_utils.utils.get()
        orig = ida_segment.get_segm_class
        ida_segment.get_segm_class = lambda seg: orig(seg).encode("ascii")
        try:
            self.assertTrue(list(u.get_data_segments()))
            self.assertIsNotNone(u._get_code_segment())
        finally:
            ida_segment.get_segm_class = orig

    def test_bytes_procname_gives_the_architecture(self):
        import ida_ida
        import pyclassinformer.pci_report as pci_report
        orig = ida_ida.inf_get_procname
        ida_ida.inf_get_procname = lambda: b"metapc"
        try:
            self.assertEqual(pci_report._architecture(), "x64")
        finally:
            ida_ida.inf_get_procname = orig


class TestQTUils(unittest.TestCase):

    def test_no_qt_available(self):
        # the test environment has no Qt bindings: every helper must degrade
        # gracefully instead of raising ImportError
        import pyclassinformer.qtutils as qtutils
        self.assertFalse(qtutils.can_use_qt())
        self.assertEqual(qtutils.get_qver(), (0, 0))
        self.assertIsNone(qtutils.get_widget(None))
        self.assertIsNone(qtutils.get_widget(0x1234))
        self.assertIsNone(qtutils.get_qmain_window(None))
        self.assertIsNone(qtutils.find_toolbar(None, "x"))
        self.assertFalse(qtutils.set_toobar_visible(None, "x"))
        self.assertFalse(qtutils.dark_mode_checker_t.is_dark_mode())
        self.assertIsNone(qtutils.dark_mode_checker_t.get_main_window())
        self.assertEqual(qtutils.dark_mode_checker_t.get_bgcolor(w=None), -1)
        self.assertTrue(qtutils.dark_mode_checker_t._is_dark_mode(0x00202020))
        self.assertFalse(qtutils.dark_mode_checker_t._is_dark_mode(0x00F0F0F0))

    def test_binding_order_follows_the_ida_version(self):
        # IDA 9.2+ is built with PySide6, older versions use PyQt5.  The
        # matching binding must win, otherwise wrapping an IDA widget breaks.
        import pyclassinformer.qtutils as qtutils
        self.assertEqual(qtutils.ida_sdk_version(), 950)
        self.assertIsNone(qtutils._import_qt())

        calls = []
        original_pyside, original_pyqt5, original_sdk = (
            qtutils._import_pyside6, qtutils._import_pyqt5, qtutils.ida_sdk_version)

        def fake_pyside():
            calls.append("pyside6")
            return ("pyside6",)

        def fake_pyqt5():
            calls.append("pyqt5")
            return ("pyqt5",)

        try:
            qtutils._import_pyside6 = fake_pyside
            qtutils._import_pyqt5 = fake_pyqt5
            qtutils.ida_sdk_version = lambda: 950
            self.assertEqual(qtutils._import_qt(), ("pyside6",))
            qtutils.ida_sdk_version = lambda: 910
            self.assertEqual(qtutils._import_qt(), ("pyqt5",))
            # the other binding is only used when the preferred one is missing
            qtutils._import_pyside6 = lambda: (_ for _ in ()).throw(ImportError())
            self.assertEqual(qtutils._import_qt(), ("pyqt5",))
        finally:
            qtutils._import_pyside6 = original_pyside
            qtutils._import_pyqt5 = original_pyqt5
            qtutils.ida_sdk_version = original_sdk


class TestLibClasses(unittest.TestCase):

    def setUp(self):
        harness.reset_modules()
        import pyclassinformer.lib_classes_checker as libchk
        self.libchk = libchk
        self.checker = libchk.get_checker()

    def test_known_classes(self):
        self.assertTrue(self.checker.is_class_lib("std::vector<int>"))
        self.assertTrue(self.checker.is_class_lib("std::"))
        self.assertTrue(self.checker.is_class_lib("CWinApp"))
        self.assertTrue(self.checker.is_class_lib("ATL::CImage"))
        self.assertFalse(self.checker.is_class_lib("CSimpleTextApp"))
        self.assertFalse(self.checker.is_class_lib(""))
        self.assertFalse(self.checker.is_class_lib(None))

    def test_template_arguments_are_ignored(self):
        # the base name is checked as well, so an entry of the "=" list also
        # matches when it is instantiated with template arguments
        self.assertTrue(self.checker.is_class_lib("CWinApp<Foo>"))

    def test_rules_are_loaded_once(self):
        self.assertIs(self.libchk.get_checker(), self.checker)

    def test_set_libflag(self):
        img, expected = harness.build(harness.SI_CLASSES, x64=True)
        result = harness.quiet(harness.parse, img)
        self.libchk.set_libflag(result)
        for col in result.values():
            self.assertEqual(col.libflag, col.LIBNOTLIB)

    def test_missing_rules_file(self):
        checker = self.libchk.lib_classes_checker_t("/does/not/exist.json")
        self.assertFalse(checker.is_class_lib("CWinApp"))


class TestGetFuncColors(unittest.TestCase):

    def test_default_colors(self):
        harness.reset_modules()
        import pyclassinformer.get_func_colors as gfc
        gen, lib = gfc.get_gen_lib_func_colors()
        self.assertIsInstance(gen, int)
        self.assertIsInstance(lib, int)
        self.assertNotEqual(gen, lib)


class TestPluginEntry(unittest.TestCase):

    def setUp(self):
        harness.reset_modules()
        import importlib
        import sys
        root = harness.ROOT
        if root not in sys.path:
            sys.path.insert(0, root)
        self.plugin = importlib.import_module("pyclassinformer_plugin")

    def test_plugin_can_be_created(self):
        plugin = self.plugin.PLUGIN_ENTRY()
        self.assertEqual(plugin.wanted_name, "PyClassInformer")
        flags = plugin.init()
        self.assertIsNotNone(flags)
        import ida_kernwin
        self.assertIn("pyclassinformer:execute", ida_kernwin.ACTIONS)
        self.assertIn("Edit/Plugins/", [m[0] for m in ida_kernwin.MENU_ATTACHMENTS])
        plugin.term()

    def test_term_without_init_is_harmless(self):
        """IDA deletes the plugin object even when the load failed."""
        plugin = self.plugin.PLUGIN_ENTRY()
        plugin.term()                      # nothing was registered yet

    def test_menu_icon_is_updated_by_action_name(self):
        """update_action_icon() takes the action name, not the menu path."""
        import ida_kernwin
        hook = self.plugin.pci_plugin_t.register_icon()
        del ida_kernwin.UPDATED_ICONS[:]
        hook.updated_actions()
        self.assertEqual(ida_kernwin.UPDATED_ICONS, [("pyclassinformer:execute",
                                                       self.plugin.pci_plugin_t.act_icon)])

    def test_double_term_is_harmless(self):
        plugin = self.plugin.PLUGIN_ENTRY()
        plugin.init()
        plugin.term()
        plugin.term()

    def test_plugin_can_be_reloaded(self):
        plugin = self.plugin.PLUGIN_ENTRY()
        plugin.init()
        plugin.term()
        plugin2 = self.plugin.PLUGIN_ENTRY()
        self.assertIsNotNone(plugin2.init())
        import ida_kernwin
        # the action is registered exactly once after a reload
        self.assertEqual(
            [a for a in ida_kernwin.ACTIONS if a == "pyclassinformer:execute"],
            ["pyclassinformer:execute"])
        self.assertEqual(
            len([m for m in ida_kernwin.MENU_ATTACHMENTS
                 if m[1] == "pyclassinformer:execute"]), 1)
        plugin2.term()


if __name__ == "__main__":
    unittest.main()
