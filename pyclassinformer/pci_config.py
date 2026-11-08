try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError


class pci_config(object):

    alldata = True
    rtti = True
    exana = True
    mvvm = True
    mvcd = True
    rnvm = True
    rncd = True
    dirtree = True

    #: new in this version
    summary = True        # print a summary of the parsed RTTI data
    verbose = False       # list virtual methods / vftable referrers in the Output window
    export_report = False # export a JSON report after parsing

    def __init__(self, alldata=False, rtti=True, exana=True, mvvm=True, mvcd=True,
                 rnvm=True, rncd=True, summary=True, verbose=False, export_report=False):
        self.alldata = alldata
        self.rtti = rtti
        self.exana = exana
        self.mvvm = mvvm
        self.mvcd = mvcd
        self.rnvm = rnvm
        self.rncd = rncd
        self.summary = summary
        self.verbose = verbose
        self.export_report = export_report
        self.check_dirtree()

    def check_dirtree(self):
        try:
            import ida_dirtree
            ida_dirtree.dirtree_t.find_entry
        # for IDA 7.x
        except (ModuleNotFoundError, AttributeError) as e:
            # IDA 7.4/7.5/7.6 have no (or no complete) ida_dirtree API
            print("[PyClassInformer] Note: ida_dirtree is not available (%s); "
                  "folder based analysis is disabled." % e)
            self.exana = False
            self.mvvm = False
            self.mvcd = False
            self.dirtree = False
