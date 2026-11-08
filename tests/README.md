# Offline test harness

These tests run the plugin **without IDA**. They are not a replacement for a
real IDA run, but they exercise the parsing logic, the report writers and the
non-visual parts of the UI classes on a machine that has no IDA installed.

```bash
python3 tests/run_tests.py          # quiet
python3 tests/run_tests.py -v       # verbose
```

Requires nothing but Python 3.8+ (the standard library only).

## How it works

| File | Purpose |
| --- | --- |
| `mock_ida/` | A small model of the IDAPython 9.5 API: segments, bytes, names, xrefs, functions, comments, `ida_typeinf` structures and type comments, `ida_kernwin.Choose`/`Form`/actions, `ida_dirtree` (including the dynamic Functions/Names trees), ... |
| `fakepe.py` | Builds synthetic MSVC RTTI data (TD, CHD, BCA, BCD, COL, vftables) for x86 and x64, with correct MSVC layouts and RVAs, and returns the expected result |
| `harness.py` | Helpers: build an image, reset the global state between tests, run the parser quietly |
| `test_rtti.py` | Parser: single/multiple inheritance, x86/x64, hierarchy paths, flags, pure virtual methods, broken RTTI, long and undemanglable names, both structure backends, database switching |
| `test_report.py` | JSON/CSV/text reports: schema, column order, chooser row parity, file writing, error handling |
| `test_ui.py` | Result chooser (rows, colors, navigation, export actions), Method Classifier (renaming, FUNC_LIB, tree items) and `run_pci` end-to-end |
| `test_utils.py` | `ida_compat` (versions, layouts, structure creation), `pci_utils` (vftable detection, method walking, ARM Thumb normalization), `qtutils` without Qt, library class rules, plugin entry point |
| `test_annotation.py` | Comments and type comments: exact text of every comment kind, idempotence, "a user comment is never overwritten", the per-kind switches, and `run_pci` with the option on/off |
| `test_apidocs.py` | IDAPython surface audit: every `ida_xxx.name` reference of the plugin must exist in the 9.5 model, removed modules may only be imported in a `try` block, `CHCOL_*` must be resolved through `chcol()`, and the documented constants/flags must be present |

## What is verified

- vftable detection and the exact addresses of every RTTI structure
- the number and order of virtual methods, including the "stops at a
  non-code slot" rule
- single and multiple inheritance: offsets, `pdiff`/`mdisp`, hierarchy paths,
  CHD flags, the possible constructors/destructors of each vftable
- the structure layouts (TD 16/8, COL 24/20, BCD 28, CHD 16) and that both the
  legacy and the `ida_typeinf` structure backends produce the same result
- that invalid candidates leave the database untouched
- JSON/CSV/text exports, including the "nothing to export" paths
- renaming of virtual methods/ctors and the `FUNC_LIB` flag for library classes
- the textual dump of the Output window (every field is labelled), the summary
  counters and the JSON/CSV/text reports
- the plugin entry point: creating, reloading and deleting it (term() twice, or
  without a successful init(), must not raise)
- the annotations: the text of the vftable slot, ctor/dtor, method and type
  comments (including the class hierarchy, the base subobject offsets, the
  pure virtual count and the CHD flags), that a second run adds nothing, that
  comments of the user are preserved, that `_purecall` gets no function comment
  and that a shared method lists at most three classes
- that every base class descriptor of the Method Classifier can be reached
  (the `BCD at 0x...` items) and that the CHD item counts the hierarchy entries
- the folder moves of the functions (`mvvm`/`mvcd`) in the Functions and Names
  dirtrees, and the dirtree helpers (`get_full_paths`, `get_abs_path_by_inode`,
  `get_parent_dir_by_inode`)
- that every IDAPython name the plugin references exists in the 9.5 model
- the plugin entry point (`PLUGIN_ENTRY().init()` registers the action, the
  menu entry and the options form)

## What is *not* verified

- the real Qt widgets (`ida_kernwin.Choose`, `Form`, docking): the mock only
  records the calls
- IDA's own type application (`ida_bytes.create_struct`, `apply_tinfo`)
- anything that depends on IDA's analysis (function detection, demangling
  quality, xref types)
- Hex-Rays itself: the tests can only prove that a comment was attached to the
  instruction/function that the decompiler reads, not how it is rendered
- performance on multi-megabyte binaries

The mock's `CHCOL_*`/`GCRF_*` numeric values and the demangler are
approximations. The
plugin resolves these constants through `chcol()` and falls back to the raw
mangled name, so the tests describe the behaviour but not the exact IDA output.

Keep the module names and the API surface of `mock_ida/` in sync with the real
IDAPython when a new IDA version is supported.
