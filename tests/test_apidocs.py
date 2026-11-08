"""Audit of the IDAPython surface the plugin relies on.

The offline harness cannot run IDA, so a typo in an API name
(``ida_bytes.set_cmts()``) or the use of a module that IDA 9.0 removed can only
be caught by *something* that knows the API.  `tests/mock_ida` is that
something: every ``ida_xxx.name`` reference of the plugin is checked against
the mock, which models the documented IDAPython 9.5 surface.  The mock is
therefore also a declaration of which APIs the plugin is allowed to use.

The names that cannot be checked this way are listed explicitly below, with the
reason (they are legacy APIs used only behind a version/``hasattr`` guard, or
they are attributes the mock models differently).
"""

import ast
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.join(os.path.dirname(HERE), "pyclassinformer")
MOCK_DIR = os.path.join(HERE, "mock_ida")

if MOCK_DIR not in sys.path:  # the mock must be importable for the checks below
    sys.path.insert(0, MOCK_DIR)

#: modules that may be referenced but that the mock does not model at all.
#: ida_struct/ida_enum were removed in IDA 9.0 and are only imported inside a
#: try block (see ida_compat.HAS_IDA_STRUCT).
UNMODELLED_MODULES = {"ida_struct", "ida_enum"}

#: per module allow list: names the mock intentionally does not provide.
ALLOWED = {
    # the legacy structure API is only used when hasattr(idc, ...) says so;
    # idc itself is modelled, so this is normally empty
    "idc": set(),
}

#: the mock's own modules (they are not part of IDAPython)
MOCK_ONLY = {"image", "structstore", "harness", "fakepe"}


def plugin_sources():
    for name in sorted(os.listdir(PLUGIN_DIR)):
        if name.endswith(".py"):
            path = os.path.join(PLUGIN_DIR, name)
            with open(path) as f:
                yield name, path, f.read()


def ida_modules():
    """The IDAPython modules the mock models."""
    mods = set()
    for name in os.listdir(MOCK_DIR):
        if name.endswith(".py") and name.startswith("ida_"):
            mods.add(name[:-3])
    mods.update(("idc", "idautils"))
    return mods


def attribute_refs(source):
    """Yield (module, attribute, lineno) for every ``module.attribute``.

    Strings and comments are ignored (this is an AST walk, not a text search).
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            yield node.value.id, node.attr, node.lineno


class TestApiSurface(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.modules = ida_modules()

    def test_the_mock_models_the_ida_modules(self):
        for mod in ("ida_bytes", "ida_funcs", "ida_kernwin", "ida_typeinf",
                    "ida_dirtree", "ida_xref", "ida_nalt", "ida_segment",
                    "ida_name", "ida_ida", "ida_idp", "ida_auto", "ida_loader",
                    "ida_idaapi", "idc", "idautils"):
            self.assertIn(mod, self.modules, mod)

    def test_every_referenced_api_exists(self):
        import importlib
        problems = []
        for filename, path, source in plugin_sources():
            for mod, attr, lineno in attribute_refs(source):
                if mod not in self.modules:
                    continue
                allowed = ALLOWED.get(mod, set())
                if attr in allowed:
                    continue
                module = importlib.import_module(mod)
                if not hasattr(module, attr):
                    problems.append("{}:{}: {}.{}".format(filename, lineno, mod, attr))
        self.assertEqual(problems, [], "\n".join(problems))

    def test_no_removed_module_is_used(self):
        """IDA 9.0 removed ida_struct/ida_enum: they may only be imported
        inside a ``try`` block so that the plugin still loads."""
        for filename, path, source in plugin_sources():
            tree = ast.parse(source)
            for node in ast.walk(tree):
                for name in _imported_modules(node):
                    if name not in UNMODELLED_MODULES:
                        continue
                    self.assertTrue(_in_try(tree, node),
                                    "{}:{}: {} must be imported inside a try block".format(
                                        filename, node.lineno, name))

    def test_version_guarded_modules_are_never_imported_at_top_level(self):
        """ida_xref/ida_segment/... may be imported lazily; this only makes
        sure the plugin does not hard-require a module that older IDA lacks."""
        for filename, path, source in plugin_sources():
            tree = ast.parse(source)
            for node in tree.body:  # top level only
                for name in _imported_modules(node):
                    self.assertNotIn(name, UNMODELLED_MODULES,
                                     "{}:{}: top level import of {}".format(
                                         filename, node.lineno, name))


def _imported_modules(node):
    if isinstance(node, ast.Import):
        return [alias.name.split(".")[0] for alias in node.names]
    if isinstance(node, ast.ImportFrom) and node.module:
        return [node.module.split(".")[0]]
    return []


def _in_try(tree, target):
    """True if ``target`` sits inside a ``try`` block of ``tree``."""
    parent = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    node = target
    while node in parent:
        node = parent[node]
        if isinstance(node, ast.Try):
            return True
    return False


class TestDocumentedConstants(unittest.TestCase):
    """Constants whose value the plugin depends on must be the documented ones."""

    def test_choose_flags(self):
        import ida_kernwin
        # used in pci_chooser/mc_tree; the mock documents the 9.5 values
        for name in ("CH_MULTI", "CH_ATTRS", "CH_HAS_DIRTREE", "CH_TM_FULL_TREE",
                     "CH_NON_PERSISTED_TREE", "CH_RENAME_IS_EDIT"):
            self.assertTrue(hasattr(ida_kernwin, name), name)

    def test_the_method_classifier_requests_the_documented_tree_flag(self):
        """IDA 9.5 presents a tree through CH_HAS_DIRTREE + OnGetDirTree()."""
        import ida_kernwin
        import pyclassinformer.mc_tree as mc_tree
        self.assertEqual(mc_tree.TREE_FLAGS & ida_kernwin.CH_HAS_DIRTREE,
                         ida_kernwin.CH_HAS_DIRTREE)
        # the legacy bit is kept for older IDA versions, it must not be lost
        self.assertTrue(mc_tree.TREE_FLAGS & ida_kernwin.CH_TM_FULL_TREE)
        self.assertTrue(hasattr(mc_tree.mc_tree_t, "OnGetDirTree"))
        self.assertTrue(hasattr(mc_tree.mc_tree_t, "OnIndexToInode"))

    def test_obsolete_flag_names_are_still_accepted(self):
        """_kernwin_flag() falls back to the OBSOLETE_* spelling."""
        import ida_kernwin
        import pyclassinformer.mc_tree as mc_tree
        self.assertEqual(mc_tree._kernwin_flag("CH_HAS_DIRTREE"),
                         ida_kernwin.CH_HAS_DIRTREE)
        self.assertEqual(mc_tree._kernwin_flag("NO_SUCH_FLAG", 7), 7)

    def test_chooser_row_flags(self):
        import ida_kernwin
        for name in ("GCRF_ALL", "GCRF_HEADER", "GCRF_SELECTION", "GCRF_CURRENT"):
            self.assertTrue(hasattr(ida_kernwin, name), name)

    def test_column_types_are_resolved_through_the_helper(self):
        """CHCOL_* values differ between IDA versions: always use chcol()."""
        import ida_kernwin
        import pyclassinformer.mc_tree as mc_tree
        import pyclassinformer.pci_chooser as pci_chooser
        self.assertEqual(mc_tree.chcol("EA"), ida_kernwin.Choose.CHCOL_EA)
        self.assertEqual(pci_chooser.chcol("FNAME"), ida_kernwin.Choose.CHCOL_FNAME)
        for filename, path, source in plugin_sources():
            # a bare "ida_kernwin.CHCOL_xxx" would freeze the value of the
            # IDA version the plugin was written on
            self.assertNotIn("ida_kernwin.CHCOL_", source,
                             "{}: use ida_kernwin.chcol() instead".format(filename))

    def test_dirtree_flags(self):
        import ida_dirtree
        self.assertEqual(ida_dirtree.DIRTREE_FUNCS, 1)
        self.assertEqual(ida_dirtree.DIRTREE_NAMES, 2)

    def test_xref_flags(self):
        import ida_xref
        self.assertTrue(hasattr(ida_xref, "XREF_DATA"))
        self.assertTrue(hasattr(ida_xref, "XREF_EXACT"))

    def test_ida_version(self):
        import ida_idaapi
        self.assertEqual(ida_idaapi.IDA_SDK_VERSION, 950)


if __name__ == "__main__":
    unittest.main()
