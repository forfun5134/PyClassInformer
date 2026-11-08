import idc
import ida_kernwin
import ida_idaapi

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.pci_utils")
ida_idaapi.require("pyclassinformer.pci_report")
import pyclassinformer.pci_utils as pci_utils
import pyclassinformer.pci_report as pci_report

#: the chooser that is currently displayed (used by the export actions)
CURRENT = {"chooser": None}

EXPORT_ACTIONS = (
    ("pyclassinformer:export_json", "PyClassInformer: Export RTTI report as JSON...", "json"),
    ("pyclassinformer:export_csv", "PyClassInformer: Export RTTI report as CSV...", "csv"),
    ("pyclassinformer:export_text", "PyClassInformer: Export RTTI report as text...", "txt"),
)


class export_action_t(ida_kernwin.action_handler_t):
    """Export the data of the displayed chooser to a file."""

    def __init__(self, fmt):
        ida_kernwin.action_handler_t.__init__(self)
        self.fmt = fmt

    def activate(self, ctx):
        chooser = CURRENT.get("chooser")
        result = chooser.data if chooser is not None else pci_report.LAST_RESULT.get("result")
        pci_report.export(result, fmt=self.fmt)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def register_export_actions(register=True):
    """Register (or unregister) the export actions and their menu entries."""
    for name, label, fmt in EXPORT_ACTIONS:
        try:
            if register:
                ida_kernwin.register_action(ida_kernwin.action_desc_t(
                    name, label, export_action_t(fmt), None, label))
                ida_kernwin.attach_action_to_menu(
                    "Edit/Plugins/", name, ida_kernwin.SETMENU_APP)
            else:
                ida_kernwin.detach_action_from_menu("Edit/Plugins/", name)
                ida_kernwin.unregister_action(name)
        except Exception:
            # an action with the same name may already be registered; ignore
            pass


register_export_actions(register=True)


def chcol(name):
    """Resolve a CHCOL_* constant (see mc_tree.chcol)."""
    for obj in (ida_kernwin.Choose, ida_kernwin):
        value = getattr(obj, "CHCOL_" + name, None)
        if value is not None:
            return value
    return 0


class pci_chooser_t(ida_kernwin.Choose):

    def __init__(self, title, data, icon=-1, libcolor=0xffffffe9, defcolor=0xffffffff):
        cols = []
        for column in pci_report.COLUMNS:
            cols.append([column["title"], column["width"] | chcol(column["chcol"])])

        ida_kernwin.Choose.__init__(
            self,
            title,
            cols,
            flags=ida_kernwin.CH_MULTI|ida_kernwin.CH_ATTRS,
            icon=icon
        )
        self.data = data
        self.u = pci_utils.utils.get()
        self.items = []
        for vftable_ea in pci_report.sorted_vftables(data):
            col = data[vftable_ea]
            values = pci_report.row_values(col, data, self.u, vftable=vftable_ea)
            self.items.append(values + [col.libflag, vftable_ea])

        self.libcolor = libcolor
        self.defcolor = defcolor
        self.libflag = data[next(iter(data))].LIBLIB if data else 1
        CURRENT["chooser"] = self

    # ------------------------------------------------------------------
    # hierarchy helpers (kept for backwards compatibility)
    # ------------------------------------------------------------------
    def get_hierarychy(self, data, vftable_ea):
        return pci_report.hierarchy_summary(data[vftable_ea], data, self.u)

    def get_hierarychy_order(self, data, vftable_ea):
        return pci_report.hierarchy_order(data[vftable_ea])

    # ------------------------------------------------------------------
    # ida_kernwin.Choose implementation
    # ------------------------------------------------------------------
    def OnInit(self):
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        if isinstance(n, list):
            n = n[0]
        return self.items[n][:-2]

    # for old versions of IDA
    def OnSelectLine(self, n):
        # CH_MULTI passes a list.
        # Change it to integer before passing to jumpto.
        if isinstance(n, list):
            n = n[0]
        idc.jumpto(self.items[n][-1])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

    def OnGetEA(self, n):
        if isinstance(n, list):
            n = n[0]
        return self.items[n][-1]

    def OnGetLineAttr(self, n):
        # change the line color if a class is a part of static linked libraries
        if isinstance(n, list):
            n = n[0]
        color = self.defcolor
        if self.items[n][-2] == self.libflag:
            color = self.libcolor
        return (color, 0)

    def OnPopup(self, widget, popup_handle):
        """Add the export actions to the context menu of the chooser."""
        for name, label, _ in EXPORT_ACTIONS:
            try:
                ida_kernwin.attach_action_to_popup(widget, popup_handle, name)
            except Exception:
                pass
        return 0

    def OnClose(self):
        if CURRENT.get("chooser") is self:
            CURRENT["chooser"] = None


def show_pci_chooser_t(data, icon=-1, modal=False, libcolor=0xffffffe9, defcolor=0xffffffff):
    title = "[PyClassInformer] {} vftables".format(len(data))
    c = pci_chooser_t(title, data, icon, libcolor, defcolor)
    c.Show(modal=modal)
    # keep a reference: IDA may garbage collect the chooser otherwise
    CURRENT["chooser"] = c
    return c
