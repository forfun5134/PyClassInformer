"""Tests of the database annotations (comments / type comments).

The comments are what the analyst sees in the disassembly and, more
importantly, in the pseudocode of the constructors, the destructors and the
virtual methods.  The mock database records them, so their exact content,
their idempotence and the "never overwrite a user comment" rule can be
checked without IDA.
"""

import unittest

import harness


class AnnotationBase(unittest.TestCase):

    def setUp(self):
        self.img, self.expected = harness.build(harness.SI_CLASSES, x64=True)
        self.result = harness.quiet(harness.parse, self.img)
        import image
        self.db = image.IMAGE
        self.cmts = self.db.cmts
        self.func_cmts = self.db.func_cmts
        import pyclassinformer.pci_annotate as pci_annotate
        self.ann = pci_annotate

    def comments(self):
        return [self.cmts[key] for key in sorted(self.cmts)]

    def func_comments(self):
        return [self.func_cmts[key] for key in sorted(self.func_cmts)]


class TestComments(AnnotationBase):

    def test_all_comment_kinds_are_created(self):
        counters = self.ann.annotate(self.result)
        self.assertEqual(counters.get("skipped", 0), 0)
        self.assertGreater(counters["comments"], 0)
        self.assertGreater(counters["func_comments"], 0)
        self.assertEqual(counters["type_comments"], len(self.ann.TYPE_COMMENTS))

    def test_every_comment_starts_with_the_prefix(self):
        self.ann.annotate(self.result)
        self.assertTrue(self.cmts)
        for text in self.comments() + self.func_comments():
            self.assertTrue(text.startswith(self.ann.PREFIX), text)
        for _, text in self.ann.TYPE_COMMENTS:
            self.assertFalse(text.startswith(self.ann.PREFIX))  # the prefix is added

    def test_vtable_slot_comments_name_the_class_and_the_method(self):
        self.ann.annotate(self.result)
        texts = self.comments()
        self.assertIn("[PyClassInformer] Animal vtable slot 0: Animal::speak", texts)
        self.assertIn("[PyClassInformer] Dog vtable slot 1: Dog::fetch", texts)
        # the slot address is the address of the pointer inside the vftable
        animal = [ea for ea, info in self.expected["vftables"].items()
                  if info["class"] == "Animal" and info["offset"] == 0][0]
        self.assertIn("[PyClassInformer] Animal vtable slot 1: Animal::eat",
                      self.cmts.get((animal + 8, False), ""))

    def test_ctor_dtor_reference_is_commented(self):
        """The instruction that loads the vftable is commented (shows in pseudocode)."""
        self.ann.annotate(self.result)
        self.assertIn("[PyClassInformer] vftable of Animal (constructor/destructor candidate)",
                      self.comments())
        self.assertIn("[PyClassInformer] possible constructor/destructor of Animal",
                      self.func_comments())

    def test_virtual_methods_get_a_function_comment(self):
        self.ann.annotate(self.result)
        self.assertIn("[PyClassInformer] virtual method of Animal", self.func_comments())
        self.assertIn("[PyClassInformer] virtual method of Dog", self.func_comments())

    def test_rtti_structures_are_documented(self):
        self.ann.annotate(self.result)
        import pyclassinformer.ida_compat as ida_compat
        for name, text in self.ann.TYPE_COMMENTS:
            tif = ida_compat.get_named_tinfo(name)
            self.assertIsNotNone(tif, name)
            cmt = tif.get_type_cmt()
            self.assertTrue(cmt.startswith(self.ann.PREFIX), cmt)
            self.assertIn(text[:20], cmt)

    def test_plural(self):
        self.assertEqual(self.ann._plural(1, "base class", "base classes"), "1 base class")
        self.assertEqual(self.ann._plural(2, "base class", "base classes"), "2 base classes")
        self.assertEqual(self.ann._plural(2, "virtual method"), "2 virtual methods")


class TestIdempotence(AnnotationBase):

    def test_running_twice_does_not_duplicate(self):
        self.ann.annotate(self.result)
        before = dict(self.cmts)
        n_func = len(self.func_cmts)
        counters = self.ann.annotate(self.result)
        self.assertEqual(self.cmts, before)
        self.assertEqual(len(self.func_cmts), n_func)
        self.assertEqual(sum(counters.values()), 0, counters)
        self.assertEqual(self.ann.format_counters(counters), "")
        self.assertEqual(len(set(self.comments())), len(before))

    def test_user_comments_are_never_overwritten(self):
        """A comment written by the analyst wins over ours."""
        import ida_bytes
        animal = [ea for ea, info in self.expected["vftables"].items()
                  if info["class"] == "Animal" and info["offset"] == 0][0]
        slot = animal + 8
        ida_bytes.set_cmt(slot, "my own note", False)
        counters = self.ann.annotate(self.result)
        self.assertEqual(self.cmts.get((slot, False)), "my own note")
        self.assertEqual(counters.get("skipped"), 1)
        # ...and our comment on the other slots is still there
        self.assertTrue(self.cmts.get((animal, False), "").startswith(self.ann.PREFIX))

    def test_user_function_comment_is_kept(self):
        import ida_funcs
        method = self.result[[ea for ea, col in self.result.items()
                              if col.name == "Animal"][0]].vfeas[0]
        ida_funcs.set_func_cmt(ida_funcs.get_func(method), "user comment", False)
        counters = self.ann.annotate(self.result)
        self.assertEqual(self.func_cmts.get((method, False)), "user comment")
        self.assertEqual(counters.get("skipped"), 1)

    def test_user_type_comment_is_kept(self):
        import pyclassinformer.ida_compat as ida_compat
        tif = ida_compat.get_named_tinfo("RTTITypeDescriptor")
        tif.set_type_cmt("mine")
        self.ann.annotate(self.result)
        self.assertEqual(tif.get_type_cmt(), "mine")
        tif.set_type_cmt("")


class TestRoles(AnnotationBase):

    def test_one_comment_lists_every_role(self):
        """A function that is a method of one class and a ctor of another."""
        import types
        col = types.SimpleNamespace(name="Foo", ea=0, offset=0, nb_bases=1,
                                    tdea=0xFFFFFFFF, col_ptr_ea=0, vfeas=[],
                                    refeas=[], refaddrs=[])
        other = types.SimpleNamespace(name="Bar", ea=0, offset=0, nb_bases=1,
                                      tdea=0xFFFFFFFF, col_ptr_ea=0, vfeas=[],
                                      refeas=[], refaddrs=[])
        shared = self.result[[ea for ea, c in self.result.items() if c.name == "Animal"][0]].vfeas[0]
        col.vfeas = [shared]
        other.refeas = [shared]
        counters = self.ann.annotate({0x1000: col, 0x2000: other}, code=False,
                                     slots=False, types=False)
        self.assertEqual(self.func_cmts.get((shared, False)),
                         "[PyClassInformer] virtual method of Foo; "
                         "possible constructor/destructor of Bar")
        self.assertEqual(counters.get("func_comments"), 1)


class TestOptions(AnnotationBase):

    def test_only_types(self):
        counters = self.ann.annotate(self.result, funcs=False, code=False,
                                     slots=False, types=True)
        self.assertEqual(self.cmts, {})
        self.assertEqual(self.func_cmts, {})
        self.assertEqual(counters.get("type_comments"), len(self.ann.TYPE_COMMENTS))

    def test_only_functions(self):
        counters = self.ann.annotate(self.result, funcs=True, code=False,
                                     slots=False, types=False)
        self.assertEqual(self.cmts, {})
        self.assertTrue(self.func_cmts)
        self.assertNotIn("type_comments", counters)

    def test_nothing_enabled(self):
        counters = self.ann.annotate(self.result, funcs=False, code=False,
                                     slots=False, types=False)
        self.assertEqual(counters, {})
        self.assertEqual(self.cmts, {})

    def test_empty_result(self):
        self.assertEqual(self.ann.annotate(None), {})
        self.assertEqual(self.ann.annotate({}), {})


class TestRunPCI(unittest.TestCase):

    def test_annotate_is_on_by_default(self):
        img, expected = harness.build(harness.SI_CLASSES, x64=True)
        import image
        import pyclassinformer.pyclassinformer as pci
        import pyclassinformer.pci_config as pci_config
        self.assertTrue(pci_config.pci_config().annotate)
        _, output = harness.capture_stdout(pci.run_pci,
                                          config=pci_config.pci_config(summary=True))
        self.assertIn("added", output)
        self.assertIn("comments", output)
        self.assertTrue(image.IMAGE.cmts)

    def test_annotate_can_be_disabled(self):
        img, expected = harness.build(harness.SI_CLASSES, x64=True)
        import image
        import pyclassinformer.pyclassinformer as pci
        import pyclassinformer.pci_config as pci_config
        _, output = harness.capture_stdout(
            pci.run_pci, config=pci_config.pci_config(annotate=False))
        self.assertEqual(image.IMAGE.cmts, {})
        self.assertEqual(image.IMAGE.func_cmts, {})
        self.assertNotIn("comments", output)

    def test_comments_use_the_final_function_names(self):
        """The annotation runs after the renaming, so it shows the new names."""
        img, expected = harness.build(harness.SI_CLASSES, x64=True, name_functions=False)
        import image
        import ida_funcs
        import pyclassinformer.pyclassinformer as pci
        import pyclassinformer.pci_config as pci_config
        import pyclassinformer.pci_report as pci_report
        harness.quiet(pci.run_pci, config=pci_config.pci_config(rnvm=True))
        result = pci_report.LAST_RESULT["result"]
        animal = [ea for ea, col in result.items() if col.name == "Animal"][0]
        vfea = result[animal].vfeas[0]
        name = ida_funcs.get_func_name(vfea)
        self.assertTrue(name.startswith("Animal::"), name)
        self.assertIn("Animal vtable slot 0: " + name,
                      image.IMAGE.cmts.get((animal, False), ""))

    def test_form_has_the_flag(self):
        import pyclassinformer.pci_config_form as form
        src = open(form.__file__).read()
        self.assertIn("{annotate}", src)
        self.assertIn('"annotate"', src)


class TestScale(AnnotationBase):
    """A larger database: every vftable is annotated, exactly once."""

    def setUp(self):
        classes = []
        for i in range(8):
            classes.append({"name": "Root%d" % i, "bases": [], "vftables": [
                {"offset": 0, "methods": ["Root%d::m%d" % (i, j) for j in range(3)]}]})
        for i in range(32):
            classes.append({"name": "Leaf%d" % i, "bases": ["Root%d" % (i % 8)],
                            "vftables": [{"offset": 0,
                                          "methods": ["Leaf%d::a%d" % (i, j) for j in range(4)]}]})
        self.img, self.expected = harness.build(classes, x64=True)
        self.result = harness.quiet(harness.parse, self.img)
        import image
        self.db = image.IMAGE
        import pyclassinformer.pci_annotate as pci_annotate
        self.ann = pci_annotate

    def test_every_slot_is_commented_once(self):
        counters = self.ann.annotate(self.result)
        slots = sum(len(col.vfeas) for col in self.result.values())
        self.assertEqual(len(self.result), 40)
        self.assertEqual(slots, 8 * 3 + 32 * 4)
        # every vftable contributes its slots plus the locator/TD/vftable
        # comments, and every method exactly one function comment
        self.assertEqual(counters["type_comments"], len(self.ann.TYPE_COMMENTS))
        self.assertEqual(counters["func_comments"] - slots,
                         len(self.result) - self._overlapping_ctors())
        self.assertEqual(len([c for c in self.db.cmts.values()
                              if "vtable slot" in c]), slots)
        again = self.ann.annotate(self.result)
        self.assertEqual(sum(again.values()), 0)

    def _overlapping_ctors(self):
        """Functions that are both a method and a ctor candidate."""
        owners = {}
        for col in self.result.values():
            for ea in col.vfeas:
                owners.setdefault(ea, set()).add(("method", col.name))
            for ea in col.refeas:
                owners.setdefault(ea, set()).add(("ctor", col.name))
        return len([ea for ea, roles in owners.items()
                    if len({r[0] for r in roles}) > 1])


if __name__ == "__main__":
    unittest.main()
