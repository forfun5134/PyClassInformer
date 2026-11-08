"""Tests of the UI layers: result chooser, method classifier and tree."""

import os
import shutil
import tempfile
import unittest

import harness


def classes_mixed():
    return [
        {"name": "Dog", "bases": [], "vftables": [
            {"offset": 0, "methods": ["Dog::a", "Dog::b"]}]},
        {"name": "std::vector", "bases": [], "vftables": [
            {"offset": 0, "methods": ["vector::c"]}]},
    ]


class TestChooser(unittest.TestCase):

    def setUp(self):
        self.img, self.expected = harness.build(harness.SI_CLASSES, x64=True)
        self.output = []
        harness.quiet(self._run)

    def _run(self):
        import pyclassinformer.pyclassinformer as pci
        import pyclassinformer.pci_config as pci_config
        pci.run_pci(config=pci_config.pci_config(rtti=False, summary=False))

    def test_chooser_created(self):
        import ida_kernwin
        choosers = [c for c in ida_kernwin.CHOSERS if c.title.startswith("[PyClassInformer]")]
        self.assertEqual(len(choosers), 1)
        chooser = choosers[0]
        self.assertEqual(chooser.title, "[PyClassInformer] 2 vftables")
        self.assertEqual(chooser.OnGetSize(), 2)
        self.assertEqual(len(chooser.cols), len(__import__("pyclassinformer.pci_report",
                                                          fromlist=["COLUMNS"]).COLUMNS))

    def test_rows(self):
        import ida_kernwin
        import pyclassinformer.pci_report as pci_report
        chooser = [c for c in ida_kernwin.CHOSERS if c.title.startswith("[PyClassInformer]")][0]
        row = chooser.OnGetLine(0)
        self.assertEqual(row[0], hex(pci_report.sorted_vftables(chooser.data)[0]))
        self.assertEqual(row[1], "2")                       # methods
        self.assertEqual(row[3], "Animal")                  # type
        self.assertEqual(row[5], "0x0")                     # offset
        self.assertEqual(row[10], "user")                   # lib/user

    def test_navigation_and_ea(self):
        import ida_kernwin
        import idc
        chooser = [c for c in ida_kernwin.CHOSERS if c.title.startswith("[PyClassInformer]")][0]
        ea = chooser.OnGetEA(0)
        self.assertEqual(ea, chooser.data[ea].vftable)
        del idc.JUMPED[:]
        chooser.OnSelectLine([0])
        self.assertEqual(idc.JUMPED, [ea])

    def test_library_coloring(self):
        import ida_kernwin
        img, expected = harness.build(classes_mixed(), x64=True)
        harness.quiet(self._run)
        chooser = [c for c in ida_kernwin.CHOSERS if c.title.startswith("[PyClassInformer]")][-1]
        colors = {}
        for i in range(chooser.OnGetSize()):
            colors[chooser.data[chooser.OnGetEA(i)].name] = chooser.OnGetLineAttr(i)[0]
        self.assertEqual(colors["std::vector"], chooser.libcolor)
        self.assertEqual(colors["Dog"], chooser.defcolor)
        self.assertNotEqual(chooser.libcolor, chooser.defcolor)

    def test_export_actions_are_available(self):
        import ida_kernwin
        import pyclassinformer.pci_chooser as pci_chooser
        for name, _, _ in pci_chooser.EXPORT_ACTIONS:
            self.assertIn(name, ida_kernwin.ACTIONS)
        chooser = [c for c in ida_kernwin.CHOSERS if c.title.startswith("[PyClassInformer]")][0]
        del ida_kernwin.POPUP_ATTACHMENTS[:]
        chooser.OnPopup(None, 0)
        attached = [a[2] for a in ida_kernwin.POPUP_ATTACHMENTS]
        self.assertIn("pyclassinformer:export_json", attached)

    def test_backwards_compatible_helpers(self):
        import ida_kernwin
        chooser = [c for c in ida_kernwin.CHOSERS if c.title.startswith("[PyClassInformer]")][0]
        ea = chooser.OnGetEA(0)
        self.assertTrue(chooser.get_hierarychy(chooser.data, ea).startswith("Animal"))
        self.assertIsInstance(chooser.get_hierarychy_order(chooser.data, ea), str)


class TestRunPCI(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="pci_ui_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_export_after_run(self):
        img, expected = harness.build(harness.SI_CLASSES, x64=True)
        path = os.path.join(self.tmpdir, "out.json")
        harness.quiet(self._run_with_export, path)
        self.assertTrue(os.path.isfile(path))

    def _run_with_export(self, path):
        import pyclassinformer.pyclassinformer as pci
        import pyclassinformer.pci_config as pci_config
        pci.run_pci(config=pci_config.pci_config(rtti=True, summary=True), export=path)

    def test_summary_and_verbose_output(self):
        img, expected = harness.build(harness.SI_CLASSES, x64=True)
        import pyclassinformer.pyclassinformer as pci
        import pyclassinformer.pci_config as pci_config
        _, output = harness.capture_stdout(
            pci.run_pci, config=pci_config.pci_config(rtti=True, summary=True, verbose=True))
        self.assertIn("PyClassInformer summary", output)
        self.assertIn("virtual methods (2)", output)
        self.assertIn("functions referring to the vftable", output)

    def test_stale_result_is_forgotten(self):
        """A run that finds nothing must clear the result of the previous run."""
        import pyclassinformer.pci_report as pci_report
        import pyclassinformer.pyclassinformer as pci

        img, expected = harness.build(harness.SI_CLASSES, x64=True)
        harness.quiet(pci.run_pci)
        self.assertTrue(pci_report.LAST_RESULT["result"])

        # a database without RTTI
        harness.build([], x64=True)
        result, output = harness.capture_stdout(pci.run_pci)
        self.assertIsNone(result)
        self.assertFalse(pci_report.LAST_RESULT["result"])
        self.assertIsNone(pci_report.export_last(path=os.path.join(self.tmpdir, "stale.json")))

    def test_nothing_found(self):
        img, expected = harness.build([], x64=True)
        import pyclassinformer.pyclassinformer as pci
        result, output = harness.capture_stdout(pci.run_pci)
        self.assertIsNone(result)
        self.assertIn("Nothing found", output)

    def test_run_returns_tree(self):
        img, expected = harness.build(harness.SI_CLASSES, x64=True)
        tree = harness.quiet(self._run_default)
        self.assertIsNotNone(tree)
        self.assertEqual(tree.title, "[MethodClassifier]")

    def _run_default(self):
        import pyclassinformer.pyclassinformer as pci
        return pci.run_pci()


class TestMethodClassifier(unittest.TestCase):

    def test_renaming(self):
        img, expected = harness.build(classes_mixed(), x64=True, name_functions=False)
        result = harness.quiet(harness.parse, img)
        import pyclassinformer.lib_classes_checker as libchk
        libchk.set_libflag(result)
        import pyclassinformer.method_classifier as mc
        import pyclassinformer.pci_config as pci_config
        harness.quiet(mc.method_classifier, result,
                      config=pci_config.pci_config())

        import ida_funcs
        for ea, col in result.items():
            for vfea in col.vfeas:
                name = ida_funcs.get_func_name(vfea)
                self.assertTrue(name.startswith(col.name.split("<")[0] + "::"), name)
            for funcea in col.refeas:
                self.assertTrue(ida_funcs.get_func_name(funcea).startswith(
                    col.name.split("<")[0] + "::"))

    def test_func_lib_flag(self):
        img, expected = harness.build(classes_mixed(), x64=True, name_functions=False)
        result = harness.quiet(harness.parse, img)
        import pyclassinformer.lib_classes_checker as libchk
        libchk.set_libflag(result)
        import pyclassinformer.method_classifier as mc
        import pyclassinformer.pci_config as pci_config
        harness.quiet(mc.method_classifier, result, config=pci_config.pci_config())

        import ida_funcs
        for ea, col in result.items():
            for vfea in col.vfeas:
                f = ida_funcs.get_func(vfea)
                if col.name.startswith("std::"):
                    self.assertTrue(f.flags & ida_funcs.FUNC_LIB, col.name)
                else:
                    self.assertFalse(f.flags & ida_funcs.FUNC_LIB, col.name)

    def test_disabled_config_does_nothing(self):
        img, expected = harness.build(classes_mixed(), x64=True, name_functions=False)
        result = harness.quiet(harness.parse, img)
        import pyclassinformer.method_classifier as mc
        import pyclassinformer.pci_config as pci_config
        tree = harness.quiet(mc.method_classifier, result,
                             config=pci_config.pci_config(exana=False, mvvm=False, mvcd=False,
                                                          rnvm=False, rncd=False))
        self.assertIsNone(tree)

    def test_get_base_classes_sorted(self):
        img, expected = harness.build(harness.MI_CLASSES, x64=True)
        result = harness.quiet(harness.parse, img)
        import pyclassinformer.method_classifier as mc
        paths = mc.get_base_classes(result)
        self.assertEqual(set(paths), set(result))
        for ea, path in paths.items():
            # the path is reversed: top-most base first, the class of the
            # vftable (or the base subobject that owns it) last
            self.assertTrue(path)
        derived = {result[ea].offset: [b.name for b in path]
                   for ea, path in paths.items() if result[ea].name == "Derived"}
        self.assertEqual(derived[0][-1], "Derived")
        self.assertEqual(derived[8][-1], "Base2")


class TestMethodTree(unittest.TestCase):

    def setUp(self):
        self.img, self.expected = harness.build(harness.MI_CLASSES, x64=True)
        self.result = harness.quiet(harness.parse, self.img)
        import pyclassinformer.method_classifier as mc
        import pyclassinformer.pci_config as pci_config
        self.tree = harness.quiet(mc.method_classifier, self.result,
                                  config=pci_config.pci_config())

    def _rows(self):
        return [self.tree.OnGetLine(i) for i in range(self.tree.OnGetSize())]

    def test_tree_has_items(self):
        rows = self._rows()
        self.assertTrue(any(r[1].startswith("vtable__") for r in rows))
        self.assertTrue(any("COL at" in r[1] for r in rows))
        self.assertTrue(any("TD at" in r[1] for r in rows))
        self.assertTrue(any("CHD at" in r[1] for r in rows))

    def test_rtti_items_point_to_the_structures(self):
        rows = self._rows()
        eas = {r[0] for r in rows}
        for info in self.expected["vftables"].values():
            self.assertIn(hex(info["td"]), eas)
            self.assertIn(hex(info["chd"]), eas)

    def test_no_duplicated_folder(self):
        """The tree must not contain 'virtual methods/virtual methods/'."""
        for dirpath, _ in self.tree.dirspec.inodes:
            self.assertFalse(dirpath.endswith("virtual methods/virtual methods/"), dirpath)

    def test_col_item_points_to_the_locator(self):
        rows = self._rows()
        eas = {r[0] for r in rows}
        for col in self.result.values():
            self.assertIn("COL at {:#x}".format(col.ea), [r[1] for r in rows])
            self.assertIn(hex(col.ea), eas)

    def test_bcd_items_are_reachable(self):
        """Every base class descriptor of the hierarchy is a jumpable item."""
        rows = self._rows()
        texts = {r[1]: r[0] for r in rows}
        bcds = [bcd for col in self.result.values() for bcd in col.bases]
        self.assertTrue(bcds)
        for bcd in bcds:
            key = "BCD at {:#x}".format(bcd.ea)
            self.assertIn(key, texts)
            self.assertEqual(texts[key], hex(bcd.ea))

    def test_chd_item_counts_the_hierarchy_entries(self):
        rows = [r[1] for r in self._rows()]
        derived = [text for text in rows if text.startswith("CHD at")]
        self.assertTrue(any("(3 entries)" in text for text in derived), derived)
        self.assertTrue(any("(1 entry)" in text for text in derived), derived)

    def test_ea_column_is_the_last_field(self):
        for i in range(self.tree.OnGetSize()):
            self.assertEqual(self.tree.OnGetEA(i), self.tree.items[i][-1])

    def test_dirtree_can_be_walked_recursively(self):
        """dirtree_utils.get_full_paths() must find every item of the tree."""
        import pyclassinformer.dirtree_utils as dirtree_utils
        paths = [path for path, de, cur in
                 dirtree_utils.get_full_paths(self.tree.dirtree, recurse=True)]
        self.assertEqual(sorted(paths), sorted(self.tree.dirtree.entries))
        for folder in ("virtual methods/", "vftable/", "RTTI/"):
            self.assertTrue(any(folder in path for path in paths), folder)
        # the items are files, so a non recursive walk from the root finds none
        self.assertEqual(list(dirtree_utils.get_full_paths(self.tree.dirtree)), [])

    def test_item_can_be_located_by_inode(self):
        """dirtree_utils.get_abs_path_by_inode()/get_parent_dir_by_inode()."""
        import pyclassinformer.dirtree_utils as dirtree_utils
        dirpath, name = self.tree.dirspec.inodes[0]
        inode = self.tree.dirspec.get_inode(dirpath, name)
        abs_path = dirtree_utils.get_abs_path_by_inode(self.tree.dirtree, inode)
        self.assertTrue(abs_path.endswith("/" + name), abs_path)
        self.assertEqual(dirtree_utils.get_parent_dir_by_inode(self.tree.dirtree, inode),
                         dirpath.rstrip("/"))


class TestDirtreeMoves(unittest.TestCase):
    """Moving the functions into class folders (mvvm/mvcd, IDA 7.7 or later)."""

    def _run(self, **kwargs):
        img, expected = harness.build(harness.SI_CLASSES, x64=True)
        import pyclassinformer.pyclassinformer as pci
        import pyclassinformer.pci_config as pci_config
        _, output = harness.capture_stdout(
            pci.run_pci, config=pci_config.pci_config(rnvm=True, rncd=True, **kwargs))
        return img, harness.quiet(harness.parse, img), output

    def test_virtual_methods_are_moved_into_the_class_folder(self):
        img, result, output = self._run(mvvm=True, mvcd=False, exana=False)
        import ida_dirtree
        import pyclassinformer.dirtree_utils as dirtree_utils
        tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        paths = {path for path, de, cur in dirtree_utils.get_full_paths(tree, recurse=True)}
        self.assertIn("/classes/Animal/virtual methods/Animal::speak", paths)
        self.assertIn("/classes/Dog/virtual methods/Dog::fetch", paths)
        # 4 virtual methods are moved in both the Functions and the Names tree
        self.assertIn("moved 8 entries", output)

    def test_ctors_are_moved_into_their_own_folder(self):
        img, result, output = self._run(mvvm=False, mvcd=True, exana=False)
        import ida_dirtree
        import pyclassinformer.dirtree_utils as dirtree_utils
        tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        paths = {path for path, de, cur in dirtree_utils.get_full_paths(tree, recurse=True)}
        self.assertIn("/classes/Animal/possible ctors or dtors/Animal::ctor", paths)
        self.assertIn("moved 4 entries", output)

    def test_moves_are_idempotent(self):
        """A second run must not move the same function again."""
        img, expected = harness.build(harness.MI_CLASSES, x64=True)
        import pyclassinformer.pyclassinformer as pci
        harness.capture_stdout(pci.run_pci)
        _, output = harness.capture_stdout(pci.run_pci)
        self.assertIn("moved 0 entries", output)

    def test_nothing_is_moved_without_the_option(self):
        img, result, output = self._run(mvvm=False, mvcd=False, exana=False)
        import ida_dirtree
        import pyclassinformer.dirtree_utils as dirtree_utils
        tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        paths = [path for path, de, cur in dirtree_utils.get_full_paths(tree, recurse=True)]
        self.assertFalse([p for p in paths if p.startswith("/classes/")], paths)


if __name__ == "__main__":
    unittest.main()
