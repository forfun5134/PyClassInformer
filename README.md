# PyClassInformer
## Yet Another RTTI Parsing IDA plugin
![PyClassInformer Icon](/pyclassinformer/pci_icon.png)

PyClassInformer is an RTTI parser. Although there are several RTTI parsers such as Class Informer and SusanRTTI, and even IDA can also parse RTTI, I created this tool. It is because they cannot be used as libraries for parsing RTTI. IDA cannot easily manage class hierarchies such as checking them as a list and filtering the information, either.

**PyClassInformer can parse RTTI on PE formatted binaries compiled by MSVC++ for x86, x64, ARM and ARM64**. Since it is written in IDAPython, you can run it on IDA for Mac OS and Linux as well as Windows. You can also use results of parsing RTTI in your python code by importing this tool as a library.

## Usage
Launch it by pressing Alt+Shift+L. Or navigate to Edit -> Plugins -> PyClassInformer.  
Then, select the options. In most cases, the default options should remain unchanged.

## Installation
Put "pyclassinformer_plugin.py" and "pyclassinformer" folder including the files under it into the "plugins" folder of IDA's user directory ($IDAUSR).  
If you use IDA 8.5 or later and want to manage this plugin with a directory, make a directory like "pci_plugin" in "plugins", copy "ida-plugin.json" into it as well as the files and the folders above.

See the URL if you don't know about "$IDAUSR".  
[https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/](https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/)  
[https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml](https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml)

## Requirements
- IDA Pro 7.4 or later (tested on 7.4 SP1 to **9.5**, including every 8.x and 9.x release)
- Python 3.x (tested on Python 3.8, 3.10, 3.11 and 3.12)

You will need at least IDA Pro 7.4 or later because of the APIs that I use. If you want to use full features, use IDA 8.3 or later. Otherwise, some features will be limited to use or skipped.

## What is new in the IDA 9.5 compatible version
The parsing core was reworked so that it depends on neither the IDA version nor on
analysis settings (see "IDA 9.5 compatibility notes" below). In short:

- **More information**: two new output modes (a summary of the parsed RTTI data,
  and a verbose mode that lists every virtual method and every function that
  refers to a vftable), seven new columns (Bases, Pure, Ctors, Lib, COL, TD and CHD),
  the number of vftables in the chooser title, and JSON/CSV/text reports.
- **More accurate**: the RTTI pointer slot right in front of a vftable is now
  recognized (it is named `vtable__<Class>` and considered when looking for
  constructors/destructors), vftable detection no longer depends on xrefs, the
  vftable length is computed deterministically, and the COLs of a class are
  grouped by their type/hierarchy descriptor (this fixes missing or wrong
  "offset" values on some multiple inheritance binaries).
- **More robust**: broken RTTI (invalid signature, NULL `pClassDescriptor`,
  truncated hierarchies, names that IDA cannot demangle) is skipped instead of
  aborting the whole run, and a candidate that is not a COL never modifies the
  database anymore.
- **Faster**: type descriptors are parsed once, structures that were already
  applied are not re-applied, and strings are read in one call.

## Features (short)
- Display class names, vftables and class hierarchies as a list
- Display RTTI parsed results on the Output window
- Display vftables, class names, virtual methods, possible constructors and destructors, and class hierarchies as a dir tree (IDA 7.7 or later)
- Create directories for classes and move virtual methods to them in Functions and Names subviews (IDA 7.7 or later)
- Move functions refer vftables to "possible ctors or dtors" folder under each class directory in Functions and Names subviews (IDA 7.7 or later)
- Rename virtual methods by appending class names to them
- Add the FUNC_LIB flag to methods that known classes own
- Rename possible constructors and destructors
- Coloring known class names and their methods on the list and the tree widgets (IDA 8.3 or later)
- Print a summary of the parsed RTTI data (number of classes, vftables, virtual methods, abstract classes, library/user classes, ...)
- Export the result as JSON, CSV or a plain text report
- Report abstract classes (pure virtual methods) and multiple inheritance flags

## Features in detail
### Default output
![PyClassInformer Result](/images/result.png)
The image above is an example of PyClassInformer result. And the image below is an example of the original Class Informer result.  
  
![Original ClassInformer Result](/images/orig_class_informer.png)  
  
As you see, almost all columns match the original ones.   
  
In addition, PyClassInformer has two more columns. One is "offset", which shows the offset of a vftable in a class layout.  
  
Another one named "Hierarchy Order" shows class hierarchy information related to a vftable of a line. The column shows the order of inheritance from the class to the top-most super class.  
  
These are useful for grasping class layouts and class hierarchies. Double-clicking a line navigates to its vftable address as well.

### RTTI parsed results
If you check the Output window, you will also see parsed RTTI information such as Complete Object Locator as COL, Class Hierarchy Descriptor as CHD and Base Class Descriptor as BCD with their addresses. They are useful for checking more details and debugging.  
  
![Class Hierarchy](/images/class_hierarchy.png)  

You will also see class hierarchies by checking indents of BCDs. For example, CMFCComObject, which is the class for the vftable at 0x530fcc, inherits ATL::CAccessibleProxy. And ATL::CAccessibleProxy inherits three super classes, ATL::CComObjectRootEx, ATL::IAccessibleProxyImpl and IOleWindow. Like this, you can get class hierarchy information as a form of a tree.

### Automatic renaming
PyClassInformer can automatically append class names to their virtual method names. Therefore, you can easily find them by filtering the class name. The image below is a result appending a class name "CDC" to its methods.  

![automatically renaming virtual methods](/images/auto_renmaing.png)  
  
PyClassInformer can also rename functions that refer to vftables to "class name" + "_possible_ctor_or_dtor". The image below is a result. Although some false positives will occur due to inlined ctors and dtors, and dynamic initializers, this feature is still useful to find them.  
  
![automatically renaming possible ctors and dtors](/images/auto_renmaing2.png)  

### Virtual method classification (<= IDA 7.7)
The detected methods are moved to each class folder in Functions and Names subviews.  
> [!NOTE]
> This is only available IDA 7.7 or later. 
  
![method classifications](/images/classification.png)  
  
PyClassInformer also displays a new widget named "Method Classifier". It lists all detected classes, vftables, virtual methods and possible constructors and destructors, and class hierarchies at once as a form of a tree.  

![method classifier](/images/method_classifier.png)  

> [!TIP]
> Class hierarchies are represented as directories in Method Classifier.
> Unfortunately, IDA's quick filter feature cannot filter directory contents.
> To search them, use text search feature (Ctrl+T (find first text) and Alt+T (Find next text)).
> For example, input a class name, a single space, and a parenthesis like "CWinApp (".

> [!NOTE]
> This is only available IDA 7.7 or later. 

### Known classes detection (<= IDA 8.3)
PyClassInformer can color known class names for easily finding user-defined classes.
The image below is an example of a coloring result.  
You can easily find CSimpleTestApp, CSimpleTestDoc, CSimpleTestView and CSimpleTestCtrlItem are user-defined classes. So you can focus on checking them.  
  
![Class coloring](/images/coloring.png)  

The coloring is also applied to Method Classifier widget. Therefore, you can easily find overridden virtual methods like the image below.  

![Methods coloring](/images/overridden_methods.png)  
  
> [!NOTE]
> The coloring feature is only available IDA 8.3 or later. 
  
Known class names are defined in "lib_classes.json". I added many patterns related to STL, which starts with "std::", and several versions of MFC Application with MFC Application Wizard.  
If you find some additional legitimate classes, you can add them to it.  

PyClassInformer also adds the FUNC_LIB flag to the methods that match the list. Therefore, you can recognize they are a part of static linked libraries.  
The following images are before and after PyClassInformer execution. Many known class methods are found and IDA can recognize them as a part of static linked libraries.  
  
![Methods coloring](/images/before_libflag_applied.png)  
![Methods coloring](/images/after_libflag_applied.png)  

### Reports (JSON / CSV / text)
![PyClassInformer Result](/images/result.png)

The parsed data can be exported from the context menu of the result list
(right click), from *Edit -> Plugins -> PyClassInformer: Export RTTI report ...*,
or by checking "Export a JSON report after parsing" in the options. The export
is also available from Python:

```python
import pyclassinformer.pyclassinformer as pci
from pyclassinformer import pci_report

result = pci.parse_rtti()                  # parse without any UI
pci_report.export(result, "report.json")   # .json / .csv / .txt
```

The JSON report is versioned (`format_version`) and contains, for every
vftable: the class name, the addresses of the COL/TD/CHD/BCA, the RTTI
signature, the class offset, the multiple inheritance flags, the number of base
classes, whether the class is a library class and/or abstract, the virtual
methods (with a `pure` flag for pure virtual methods), the functions that
refer to the vftable (possible constructors/destructors), the hierarchy paths
and every hierarchy path of the class:

```json
{
  "tool": "PyClassInformer",
  "format_version": 1,
  "generated": "2026-11-08T10:30:00",
  "input_file": "C:/samples/sample.exe",
  "imagebase": 5368709120,
  "plugin_version": "1.1",
  "ida_version": "9.5",
  "architecture": "x64",
  "summary": {"vftables": 812, "classes": 640, "vfuncs": 4210, "...": "..."},
  "vftables": [
    {
      "vftable": 5368721600,
      "class": "Dog",
      "col": 5368721408,
      "signature": 1,
      "offset": 0,
      "cd_offset": 0,
      "self": 5368721408,
      "type_descriptor": {"ea": 5368721392, "mangled": ".?AVDog@@", "demangled": "class Dog `RTTI Type Descriptor'"},
      "class_hierarchy_descriptor": {"ea": 5368721472, "signature": 0, "attributes": 0, "base_class_array": 5368721488},
      "flags": "",
      "flag_names": [],
      "attributes": 0,
      "num_base_classes": 2,
      "library": false,
      "abstract": false,
      "pure_virtual_methods": 0,
      "methods": [{"ea": 5368713264, "name": "Dog::speak", "pure": false}],
      "referers": [{"ea": 5368713296, "name": "Dog::Dog"}],
      "hierarchy": [[{"class": "Dog", "ea": 5368721512, "depth": 0, "mdisp": 0,
                      "pdisp": -1, "vdisp": 0, "attributes": 64,
                      "flag_names": ["HASPCHD"]}]],
      "all_hierarchy_paths": [{"offset": 0, "path": ["Dog", "Animal"]}]
    }
  ]
}
```

`summary` contains the counters of the run (class counters are per class name,
not per vftable): `vftables`, `classes`,
`class_names`, `vfuncs`, `unique_vfuncs`, `pure_virtual`, `abstract_classes`,
`ref_funcs`, `multiple_inheritance`, `virtual_inheritance`,
`ambiguous_inheritance`, `library_classes`, `user_classes` and `no_hierarchy`.
`hierarchy` holds the paths of this vftable (the BCDs with their `mdisp`,
`pdisp` and `vdisp`), `all_hierarchy_paths` the paths of every vftable of the
class.

`architecture` is `x86`, `x64`, `arm` or `arm64` (it is derived from the
processor name, not only from the bitness).

The CSV export contains the same rows as the result list (identical column
order, UTF-8 with BOM so that spreadsheet applications show the class names
correctly). The text export is a readable list plus the summary.

## IDA 9.5 compatibility notes
IDA 9.5 (build 9.5.261026) changed several things that affect this plugin. All
of them are handled, and the handling is version agnostic (older IDA versions
keep working the same way):

- **Qt 6.12 LTS / PySide6 upgrade.** The optional Qt helpers (`qtutils.py`)
  no longer assume a specific binding or a specific `Qt` enum layout; when no
  binding is available (e.g. idat, IDA free) the plugin still loads and only the
  toolbar icon hook is skipped.
- **`ida_struct`/`ida_enum` are gone** (removed in 9.0). Structures are created
  with a layout computed in Python (`ida_compat.compute_layout`), so RTTI is
  parsed even if the database refuses the type. The backend follows the
  official guidance (`IDAPython porting guide for IDA 9`): the `idc` wrappers
  (`add_struc`/`add_struc_member`) up to IDA 8.4, and
  `tinfo_t.create_udt()`/`tinfo_t.add_udm()` from IDA 9.0 on. Set
  `ida_compat.PREFER_LEGACY_STRUCT_API` to `True`/`False` to force one of them.
  `tinfo_t.set_named_type()` may return a `terr_t` (where `TERR_OK == 0`), which
  is handled by `ida_compat.terr_ok()`.
- **`XrefsTo()` reports Thumb/MIPS16 function pointers as `address + 1`** on
  ARM since 9.5. The plugin passes `ida_xref.XREF_EXACT` when available, so a
  vftable is not reported twice and constructors are not missed; 32 bit ARM
  pointers are also normalized by clearing the Thumb bit.
- **Chooser constants moved** (`ida_kernwin.CHCOL_*` vs `Choose.CHCOL_*`).
  `chcol()` resolves them on both locations and falls back gracefully.
- **Quick filter rework / Shift+Enter.** Nothing to do, but note that the
  earlier note about the quick filter still applies to the Method Classifier.

### Correctness notes
The vftable handling was tightened in several places. These are the two
behaviors that differ from older releases of this plugin:

1. Compiler generated code usually references the **slot that holds the RTTI
   pointer**, i.e. `vftable - pointer_size`, not the first method slot. Both
   addresses are now checked, so constructors/destructors are found in binaries
   where they used to be missed. The slot itself is named `vtable__<Class>`.
2. The vftable length is computed by walking the slots until a slot no longer
   points to code (this is deterministic). The previous implementation asked
   IDA for the next slot with an xref, which returned a single method per
   vftable in databases where the method slots had no xrefs.

### Review against the official documentation
The changes above were checked against Hex-Rays' documentation for 9.5:

- [IDA 9.5 release notes](https://docs.hex-rays.com/release-notes/9_5): Qt 6.12
  / PySide6, `XREF_EXACT` and the Thumb/MIPS16 xrefs, the installation
  manifests, the removed `ida_struct`/`ida_enum`, the new class API (Dalvik is
  its first backend, so it does not replace an MSVC RTTI parser), the new
  `export_listing` API, `ask_file("","")` crash fix, plugin directory ordering
  fix. The 9.5 notes do **not** announce a `Choose` callback change.
- [IDAPython porting guide for IDA 9](https://docs.hex-rays.com/developer/idapython/how-tos/idapython-porting-guide-ida-9):
  `add_struc` -> `tinfo_t.create_udt`, `add_struc_member` -> `tinfo_t.add_udm`,
  `get_struc_id` -> `get_named_type_tid`, `del_struc` -> `del_named_type`, and
  `struc_t`/`member_t` -> `tinfo_t`/`udm_t`. This is what `ida_compat.py` uses.
- [IDAPython API reference](https://python.docs.hex-rays.com/):
  `ida_typeinf.apply_tinfo(ea, tif, flags)`, `udm_t.offset`/`size` in *bits*,
  `Choose`/`Form`/action APIs.

Two regressions were found this way and fixed: a `del_items()` call that used
`DELIT_DELNAMES` (it deleted IDA's own `??_R0?AVFoo@@` type-descriptor names)
and a `set_named_type()` return value that was read as a boolean although it is
a `terr_t` (this made the plugin silently fall back to the legacy structure
backend). Both are covered by tests now.

## Testing without IDA
The repository ships an offline test harness. It contains a small model of the
IDAPython 9.5 API (`tests/mock_ida`) and a builder for synthetic MSVC RTTI
images (`tests/fakepe.py`), so the parser, the report writers and the UI
classes can be exercised on any machine:

```bash
python3 tests/run_tests.py        # 93 tests, no IDA required
python3 tests/run_tests.py -v
```

> [!NOTE]
> The harness models IDAPython, it is not IDAPython. It verifies the logic
> (addresses, offsets, flags, hierarchy walking, reports, renaming), but it
> cannot verify the real Qt widgets or IDA's type application. A final check on
> a real IDA 9.5 with a large MFC/STL binary is still recommended.

## Note
- I **WILL NOT** support parsing GCC's RTTI. **DO NOT** open an issue about it.
- I **WILL NOT** support beta versions of IDA. **DO NOT** open an issue about it.
- I **WILL NOT** support IDA free and IDA demo except for IDA Classroom Free because they do not have IDAPython.
- Some code is from SusanRTTI and the output table is similar to Class Informer.  
[https://github.com/nccgroup/SusanRTTI](https://github.com/nccgroup/SusanRTTI)  
[https://sourceforge.net/projects/classinformer/](https://sourceforge.net/projects/classinformer/)
