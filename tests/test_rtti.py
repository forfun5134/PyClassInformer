"""Tests of the RTTI parser (x86/x64, SI/MI, broken RTTI, ...)."""

import unittest

import harness


class TestSingleInheritance(unittest.TestCase):

    def setUp(self):
        self.img, self.expected = harness.build(harness.SI_CLASSES, x64=True)
        self.result = harness.quiet(harness.parse, self.img)

    def test_all_vftables_found(self):
        self.assertEqual(set(self.result), set(self.expected["vftables"]))
        self.assertEqual(len(self.result), 2)

    def test_class_names(self):
        names = {self.result[ea].name for ea in self.result}
        self.assertEqual(names, {"Animal", "Dog"})

    def test_virtual_methods(self):
        for ea, info in self.expected["vftables"].items():
            self.assertEqual(self.result[ea].vfeas, info["methods"],
                             "methods of %s" % info["class"])

    def test_hierarchy(self):
        animal = [c for c in self.result.values() if c.name == "Animal"][0]
        dog = [c for c in self.result.values() if c.name == "Dog"][0]
        self.assertEqual(animal.get_hierarchy_order(), "Animal (0,-1,0)")
        self.assertEqual(dog.get_hierarchy_order(), "Dog (0,-1,0) -> Animal (0,-1,0)")
        self.assertEqual([b.name for b in dog.bases], ["Dog", "Animal"])
        self.assertEqual(dog.nb_bases, 2)
        self.assertEqual(animal.nb_bases, 1)

    def test_offsets_and_flags(self):
        for col in self.result.values():
            self.assertEqual(col.offset, 0)
            self.assertEqual(col.flags, "")
            self.assertEqual(col.sig, 1)          # x64 locator signature

    def test_rtti_addresses(self):
        for ea, info in self.expected["vftables"].items():
            col = self.result[ea]
            self.assertEqual(col.ea, info["col"])
            self.assertEqual(col.tdea, info["td"])
            self.assertEqual(col.chdea, info["chd"])
            self.assertEqual(col.bcaea, info["bca"])
            self.assertEqual(col.col_ptr_ea, info["col_ptr"])

    def test_possible_ctors_reference_the_rtti_pointer(self):
        # the compiler generated code references the *start* of the vftable
        # (the slot that holds the RTTI pointer), not the first method
        for ea, info in self.expected["vftables"].items():
            self.assertIn(info["ctor"], self.result[ea].refeas)

    def test_vftable_is_named(self):
        import ida_name
        for ea, info in self.expected["vftables"].items():
            self.assertEqual(ida_name.get_name(info["col_ptr"]), "vtable__" + info["class"])

    def test_existing_names_are_preserved(self):
        """Applying the RTTI structures must not delete IDA's names."""
        import ida_name
        import image
        self.assertEqual(image.IMAGE.deleted_names, [])
        for info in self.expected["vftables"].values():
            # IDA names type descriptors "??_R0" + the type mangling
            self.assertTrue(ida_name.get_name(info["td"]).startswith("??_R0"))
            self.assertEqual(ida_name.get_name(info["col_ptr"]), "vtable__" + info["class"])

    def test_summary(self):
        import pyclassinformer.msvc_rtti as msvc_rtti
        summary = msvc_rtti.rtti_parser.summarize(self.result)
        self.assertEqual(summary["vftables"], 2)
        self.assertEqual(summary["classes"], 2)
        self.assertEqual(summary["vfuncs"], 4)
        self.assertEqual(summary["unique_vfuncs"], 4)
        self.assertEqual(summary["pure_virtual"], 0)
        self.assertEqual(summary["multiple_inheritance"], 0)

    def test_idempotent(self):
        # parsing the same database twice must return the same result
        result2 = harness.quiet(harness.parse, self.img)
        self.assertEqual({ea: c.name for ea, c in result2.items()},
                         {ea: c.name for ea, c in self.result.items()})


class TestX86(unittest.TestCase):

    def setUp(self):
        self.img, self.expected = harness.build(harness.SI_CLASSES, x64=False)
        self.result = harness.quiet(harness.parse, self.img)

    def test_found(self):
        self.assertEqual(set(self.result), set(self.expected["vftables"]))

    def test_signature_is_zero_on_x86(self):
        for col in self.result.values():
            self.assertEqual(col.sig, 0)

    def test_methods(self):
        for ea, info in self.expected["vftables"].items():
            self.assertEqual(self.result[ea].vfeas, info["methods"])


class TestMultipleInheritance(unittest.TestCase):

    def setUp(self):
        self.img, self.expected = harness.build(harness.MI_CLASSES, x64=True)
        self.result = harness.quiet(harness.parse, self.img)

    def test_all_vftables_found(self):
        self.assertEqual(set(self.result), set(self.expected["vftables"]))
        derived = [c for c in self.result.values() if c.name == "Derived"]
        self.assertEqual(len(derived), 2)

    def test_offsets(self):
        offsets = sorted(c.offset for c in self.result.values() if c.name == "Derived")
        self.assertEqual(offsets, [0, 8])

    def test_multiple_inheritance_flag(self):
        for col in self.result.values():
            if col.name == "Derived":
                self.assertEqual(col.flags, "M")
                self.assertEqual(col.flag_names, "MULTINH")
            else:
                self.assertEqual(col.flags, "")

    def test_hierarchy_paths(self):
        derived = [c for c in self.result.values() if c.name == "Derived" and c.offset == 0][0]
        self.assertEqual(sorted(derived.paths), [0, 8])
        self.assertEqual([[b.name for b in p] for p in derived.paths[0]], [["Derived", "Base1"]])
        self.assertEqual([[b.name for b in p] for p in derived.paths[8]], [["Derived", "Base2"]])

    def test_summary_counts_classes_not_vftables(self):
        import pyclassinformer.lib_classes_checker as libchk
        import pyclassinformer.msvc_rtti as msvc_rtti
        libchk.set_libflag(self.result)
        summary = msvc_rtti.rtti_parser.summarize(self.result)
        self.assertEqual(summary["vftables"], 4)
        self.assertEqual(summary["classes"], 3)
        # Derived has two vftables but is a single class
        self.assertEqual(summary["multiple_inheritance"], 1)
        self.assertEqual(summary["library_classes"], 0)
        self.assertEqual(summary["user_classes"], 3)

    def test_cols_of_the_same_class(self):
        import pyclassinformer.pci_utils as pci_utils
        u = pci_utils.utils.get()
        derived = [c for c in self.result.values() if c.name == "Derived" and c.offset == 0][0]
        self.assertEqual(u.get_col_offs(derived, self.result), [0, 8])
        self.assertEqual([b.name for b in u.get_col_bases(derived, self.result)],
                         ["Derived", "Base1"])
        derived8 = [c for c in self.result.values() if c.name == "Derived" and c.offset == 8][0]
        self.assertEqual([b.name for b in u.get_col_bases(derived8, self.result)], ["Base2"])


class TestBrokenRTTI(unittest.TestCase):

    def test_invalid_signature_is_ignored(self):
        img, expected = harness.build(harness.SI_CLASSES, x64=True,
                                      extra_setup=lambda i: i.add_bogus_rtti())
        result = harness.quiet(harness.parse, img)
        self.assertEqual(set(result), set(expected["vftables"]))
        for ea in result:
            self.assertNotEqual(result[ea].name, "bogus_method")

        # a rejected candidate must not leave a structure behind: every
        # structure that was applied belongs to the RTTI data that was parsed
        import image
        applied = {ea for eas in image.IMAGE.struct_applied.values() for ea in eas}
        valid = set()
        for col in result.values():
            valid |= {col.ea, col.td.ea, col.chd.ea, col.chd.bca.ea}
            valid |= {bcd.ea for bcd in col.bases}
            for bcd in col.bases:
                if bcd.chdea != image.BADADDR:
                    valid.add(bcd.chdea)
        self.assertEqual(applied - valid, set(),
                         "structures applied outside of the RTTI data")

    def test_no_rtti(self):
        img = harness.build([], x64=True)[0]
        result = harness.quiet(harness.parse, img)
        self.assertEqual(result, {})
        # the report writer and the summary must cope with an empty result
        import pyclassinformer.pci_report as pci_report
        import pyclassinformer.msvc_rtti as msvc_rtti
        self.assertEqual(msvc_rtti.rtti_parser.summarize({})["vftables"], 0)
        self.assertIn("\"vftables\": []", pci_report.build_json({}))
        self.assertIsNone(pci_report.export({}, path="/tmp/should_not_exist.json"))

    def test_base_class_without_pchd(self):
        """A BCD whose pClassDescriptor is 0 must not be applied to the image base."""
        import image

        def setup(img):
            # the BCD of "Animal" (second entry of Dog's BCA) gets a NULL pCHD
            cls = "Dog"
            info = img.expected["classes"][cls]
            bcd_ea = info["bca"]  # first entry = Dog's own BCD... set the base's
            img.img.write_uint(bcd_ea + 24, 0, 4)  # pClassDescriptor = 0

        img, expected = harness.build(harness.SI_CLASSES, x64=True, extra_setup=setup)
        harness.quiet(harness.parse, img)
        # nothing must have been applied to the image base or outside a section
        applied = [ea for eas in image.IMAGE.struct_applied.values() for ea in eas]
        self.assertNotIn(img.imagebase, applied)
        for ea in applied:
            self.assertIsNotNone(image.IMAGE.get_segment(ea),
                                 "structure applied outside of the image: %#x" % ea)


class TestNames(unittest.TestCase):

    def test_long_class_name(self):
        long_name = "C" + "x" * 700
        classes = [{"name": long_name, "bases": [], "vftables": [
            {"offset": 0, "methods": ["long::f"]}]}]
        img, expected = harness.build(classes, x64=True)
        result = harness.quiet(harness.parse, img)
        self.assertEqual(len(result), 1)
        self.assertEqual(list(result.values())[0].name, long_name)

    def test_template_name_without_demangler(self):
        # the mini demangler of the mock refuses templates; the parser must
        # fall back to the raw mangled name instead of dropping the class
        import pyclassinformer.msvc_rtti as msvc_rtti
        self.assertEqual(
            msvc_rtti.fallback_type_name(".?AVFoo@Bar@@"), "Bar::Foo")
        self.assertEqual(msvc_rtti.fallback_type_name(".?AVAnimal@@"), "Animal")

    def test_strip(self):
        import pyclassinformer.msvc_rtti as msvc_rtti
        self.assertEqual(msvc_rtti.strip("class Foo `RTTI Type Descriptor'"), "Foo")
        self.assertEqual(msvc_rtti.strip("struct ns::Bar `RTTI Type Descriptor'"), "ns::Bar")
        self.assertEqual(msvc_rtti.strip("int `RTTI Type Descriptor'"), "int")
        self.assertEqual(msvc_rtti.strip("Foo"), "Foo")
        self.assertEqual(msvc_rtti.strip(None), None)


class TestPureVirtual(unittest.TestCase):

    def test_purecall_detected(self):
        classes = [{"name": "Abstract", "bases": [], "vftables": [
            {"offset": 0, "methods": ["_purecall", "Abstract::ok"]}]}]
        img, expected = harness.build(classes, x64=True)
        result = harness.quiet(harness.parse, img)
        col = list(result.values())[0]
        self.assertEqual(col.pure_virtual_count, 1)
        self.assertTrue(col.is_abstract)

        import pyclassinformer.msvc_rtti as msvc_rtti
        summary = msvc_rtti.rtti_parser.summarize(result)
        self.assertEqual(summary["pure_virtual"], 1)
        self.assertEqual(summary["abstract_classes"], 1)


class TestStructureBackends(unittest.TestCase):

    def _parse_with(self, force_typeinf):
        img, expected = harness.build(harness.MI_CLASSES, x64=True)
        return harness.quiet(harness.parse, img, force_typeinf=force_typeinf), expected

    def test_typeinf_backend_matches_legacy(self):
        legacy, expected = self._parse_with(False)
        typeinf, _ = self._parse_with(True)
        self.assertEqual(set(legacy), set(typeinf))
        for ea in legacy:
            self.assertEqual(legacy[ea].name, typeinf[ea].name)
            self.assertEqual(legacy[ea].offset, typeinf[ea].offset)
            self.assertEqual(legacy[ea].vfeas, typeinf[ea].vfeas)
            self.assertEqual([b.name for b in legacy[ea].bases],
                             [b.name for b in typeinf[ea].bases])
            self.assertEqual({off: [[b.name for b in path] for path in paths]
                              for off, paths in legacy[ea].paths.items()},
                             {off: [[b.name for b in path] for path in paths]
                              for off, paths in typeinf[ea].paths.items()})
        self.assertEqual(set(legacy), set(expected["vftables"]))

    def test_layouts(self):
        import pyclassinformer.msvc_rtti as msvc_rtti
        import pyclassinformer.ida_compat as ida_compat

        td = ida_compat.compute_layout(msvc_rtti.TD_MEMBERS, True)
        self.assertEqual(td[1], 16)                     # header size on x64
        self.assertEqual(td[0]["name"], 16)
        self.assertEqual(ida_compat.compute_layout(msvc_rtti.TD_MEMBERS, False)[1], 8)

        col = ida_compat.compute_layout(msvc_rtti.COL_MEMBERS_X64, True)
        self.assertEqual(col[1], 24)
        self.assertEqual(col[0]["offset"], 4)
        self.assertEqual(col[0]["pTypeDescriptor"], 12)
        self.assertEqual(col[0]["pClassDescriptor"], 16)
        self.assertEqual(col[0]["pSelf"], 20)
        self.assertEqual(ida_compat.compute_layout(msvc_rtti.COL_MEMBERS, False)[1], 20)

        self.assertEqual(ida_compat.compute_layout(msvc_rtti.BCD_MEMBERS, True)[1], 28)
        self.assertEqual(ida_compat.compute_layout(msvc_rtti.CHD_MEMBERS, True)[1], 16)


class TestDatabaseSwitch(unittest.TestCase):

    def test_structs_are_recreated_for_a_new_database(self):
        img1, expected1 = harness.build(harness.SI_CLASSES, x64=True)
        result1 = harness.quiet(harness.parse, img1)

        # a second database with a different layout
        img2, expected2 = harness.build(harness.MI_CLASSES, x64=False,
                                        input_file="C:/samples/other.exe")
        result2 = harness.quiet(harness.parse, img2)

        self.assertEqual(set(result1), set(expected1["vftables"]))
        self.assertEqual(set(result2), set(expected2["vftables"]))
        self.assertEqual({c.name for c in result2.values()}, {"Base1", "Base2", "Derived"})


if __name__ == "__main__":
    unittest.main()
