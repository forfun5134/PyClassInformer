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
| `mock_ida/` | A small model of the IDAPython 9.5 API: segments, bytes, names, xrefs, functions, `ida_typeinf` structures, `ida_kernwin.Choose`/`Form`/actions, `ida_dirtree`, ... |
| `fakepe.py` | Builds synthetic MSVC RTTI data (TD, CHD, BCA, BCD, COL, vftables) for x86 and x64, with correct MSVC layouts and RVAs, and returns the expected result |
| `harness.py` | Helpers: build an image, reset the global state between tests, run the parser quietly |
| `test_rtti.py` | Parser: single/multiple inheritance, x86/x64, hierarchy paths, flags, pure virtual methods, broken RTTI, long and undemanglable names, both structure backends, database switching |
| `test_report.py` | JSON/CSV/text reports: schema, column order, chooser row parity, file writing, error handling |
| `test_ui.py` | Result chooser (rows, colors, navigation, export actions), Method Classifier (renaming, FUNC_LIB, tree items) and `run_pci` end-to-end |
| `test_utils.py` | `ida_compat` (versions, layouts, structure creation), `pci_utils` (vftable detection, method walking, ARM Thumb normalization), `qtutils` without Qt, library class rules, plugin entry point |

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
- the plugin entry point (`PLUGIN_ENTRY().init()` registers the action, the
  menu entry and the options form)

## What is *not* verified

- the real Qt widgets (`ida_kernwin.Choose`, `Form`, docking): the mock only
  records the calls
- IDA's own type application (`ida_bytes.create_struct`, `apply_tinfo`)
- anything that depends on IDA's analysis (function detection, demangling
  quality, xref types)
- performance on multi-megabyte binaries

The mock's `CHCOL_*` numeric values and the demangler are approximations. The
plugin resolves these constants through `chcol()` and falls back to the raw
mangled name, so the tests describe the behaviour but not the exact IDA output.

Keep the module names and the API surface of `mock_ida/` in sync with the real
IDAPython when a new IDA version is supported.
