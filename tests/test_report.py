"""Tests of the JSON/CSV/text report writers."""

import csv
import io
import json
import os
import shutil
import tempfile
import unittest

import harness


class TestReport(unittest.TestCase):

    def setUp(self):
        self.img, self.expected = harness.build(harness.MI_CLASSES, x64=True)
        self.result = harness.quiet(harness.parse, self.img)
        import pyclassinformer.lib_classes_checker as libchk
        libchk.set_libflag(self.result)
        import pyclassinformer.pci_report as pci_report
        self.report = pci_report
        self.tmpdir = tempfile.mkdtemp(prefix="pci_test_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------
    def test_json_structure(self):
        doc = json.loads(self.report.build_json(self.result))
        self.assertEqual(doc["tool"], "PyClassInformer")
        self.assertEqual(doc["format_version"], self.report.FORMAT_VERSION)
        self.assertEqual(doc["architecture"], "x64")
        self.assertEqual(doc["plugin_version"], self.report.PLUGIN_VERSION)
        self.assertEqual(doc["ida_version"], "9.5")
        self.assertEqual(doc["imagebase"], self.img.imagebase)
        self.assertGreaterEqual(len(doc["vftables"]), 4)

        by_name = {}
        for entry in doc["vftables"]:
            by_name.setdefault(entry["class"], []).append(entry)
        self.assertEqual(set(by_name), {"Base1", "Base2", "Derived"})

        derived = sorted(by_name["Derived"], key=lambda e: e["offset"])
        self.assertEqual([e["offset"] for e in derived], [0, 8])
        self.assertEqual(derived[0]["vftable"], self.expected["vftables"] and
                         [ea for ea, info in self.expected["vftables"].items()
                          if info["class"] == "Derived" and info["offset"] == 0][0])
        self.assertEqual(derived[0]["col"], [info["col"] for info in self.expected["vftables"].values()
                                             if info["class"] == "Derived" and info["offset"] == 0][0])
        self.assertEqual(derived[0]["class_hierarchy_descriptor"]["ea"],
                         self.expected["classes"]["Derived"]["chd"])
        self.assertEqual(derived[0]["type_descriptor"]["ea"],
                         self.expected["classes"]["Derived"]["td"])
        self.assertEqual(derived[0]["type_descriptor"]["mangled"], ".?AVDerived@@")
        self.assertEqual(derived[0]["num_base_classes"], 3)
        self.assertTrue(derived[0]["flag_names"] == ["MULTINH"])
        self.assertEqual(len(derived[0]["methods"]), 2)
        self.assertEqual(derived[1]["hierarchy"][0][0]["class"], "Derived")
        self.assertEqual(derived[1]["hierarchy"][0][1]["class"], "Base2")

    def test_json_is_valid_for_empty_result(self):
        doc = json.loads(self.report.build_json({}))
        self.assertEqual(doc["vftables"], [])
        self.assertEqual(doc["summary"]["vftables"], 0)

    def test_csv_header_matches_columns(self):
        rows = list(csv.reader(io.StringIO(self.report.build_csv(self.result))))
        self.assertEqual(rows[0], [c["title"] for c in self.report.COLUMNS])
        self.assertEqual(len(rows) - 1, len(self.result))

    def test_csv_rows_match_chooser_rows(self):
        import pyclassinformer.pci_chooser as pci_chooser
        chooser = pci_chooser.pci_chooser_t("[t]", self.result)
        csv_rows = list(csv.reader(io.StringIO(self.report.build_csv(self.result))))[1:]
        chooser_rows = []
        for i in range(chooser.OnGetSize()):
            chooser_rows.append(chooser.OnGetLine(i))
        u = chooser.u
        expected_rows = []
        for ea in self.report.sorted_vftables(self.result):
            expected_rows.append(self.report.row_values(self.result[ea], self.result, u, vftable=ea))
        self.assertEqual(chooser_rows, expected_rows)
        self.assertEqual(len(csv_rows), len(expected_rows))
        for csv_row, values in zip(csv_rows, expected_rows):
            self.assertEqual(csv_row, values)

    def test_text_report(self):
        text = self.report.build_text(self.result)
        self.assertIn("PyClassInformer summary", text)
        self.assertIn("Derived", text)
        self.assertIn("Base2", text)

    def test_write_all_formats(self):
        for fmt in ("json", "csv", "txt"):
            path = os.path.join(self.tmpdir, "report." + fmt)
            self.report.write(path, self.result)
            self.assertTrue(os.path.isfile(path))
            self.assertGreater(os.path.getsize(path), 10)
        with open(os.path.join(self.tmpdir, "report.json"), "rb") as f:
            json.loads(f.read().decode("utf-8"))
        with open(os.path.join(self.tmpdir, "report.csv"), "rb") as f:
            # utf-8 BOM for spreadsheet applications
            self.assertTrue(f.read(3) == b"\xef\xbb\xbf")

    def test_export_with_explicit_path(self):
        path = os.path.join(self.tmpdir, "explicit.json")
        self.assertEqual(self.report.export(self.result, path=path), path)
        with open(path, "rb") as f:
            self.assertEqual(json.loads(f.read().decode("utf-8"))["tool"], "PyClassInformer")

    def test_export_unsupported_format(self):
        path = os.path.join(self.tmpdir, "x.bin")
        self.assertIsNone(self.report.export(self.result, path=path))

    def test_export_last(self):
        self.report.remember(self.result)
        path = os.path.join(self.tmpdir, "last.json")
        self.assertEqual(self.report.export_last(path=path), path)

    def test_sorted_vftables_is_deterministic(self):
        order1 = self.report.sorted_vftables(self.result)
        order2 = self.report.sorted_vftables(dict(reversed(list(self.result.items()))))
        self.assertEqual(order1, order2)
        names = [self.result[ea].name for ea in order1]
        self.assertEqual(names, sorted(names))


class TestReportWithoutRTTI(unittest.TestCase):

    def test_export_returns_none(self):
        import pyclassinformer.pci_report as pci_report
        self.assertIsNone(pci_report.export({}, path="/tmp/never.json"))
        self.assertIsNone(pci_report.export_last(path="/tmp/never.json"))


if __name__ == "__main__":
    unittest.main()
