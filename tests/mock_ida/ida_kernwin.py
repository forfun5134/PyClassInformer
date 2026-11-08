"""Mock of ida_kernwin (UI helpers are recorded, never displayed)."""
import image

DP_FLOATING = 0x0001
DP_TAB = 0x0002
DP_INSIDE = 0x0004

SETMENU_APP = 0x01
SETMENU_POSMASK = 0x0F
SETMENU_FIRST = 0x10

AST_ENABLE_ALWAYS = 0
AST_ENABLE = 1
AST_DISABLE = 2

BWN_DISASM = 1

MESSAGES = []
ACTIONS = {}
POPUP_ATTACHMENTS = []
MENU_ATTACHMENTS = []
TOOLBARS = {}
CHOSERS = []
DOCK_CALLS = []


def msg(text):
    MESSAGES.append(text)
    print(text, end="")


def warning(text):
    MESSAGES.append(text)


def set_dock_pos(widget, dock_to, position, size=0, x=0, y=0):
    DOCK_CALLS.append((widget, dock_to, position))
    return True


def load_custom_icon(data=None, format="png", path=None):
    return 0x1234


def free_custom_icon(icon):
    return True


def create_toolbar(name, label, hotkey=""):
    TOOLBARS[name] = label
    return True


def attach_action_to_toolbar(toolbar, action_name):
    return True


def detach_action_from_toolbar(toolbar, action_name):
    return True


def delete_toolbar(name):
    return True


def update_action_icon(action_name, icon):
    return True


def open_navband_window(ea, zoom):
    return None


def get_screen_ea():
    return image.IMAGE.segments[0].start_ea if image.IMAGE.segments else 0


def ask_file(save, default_name="", filters="", caption=""):
    return None


def get_chooser_rows(cri, chooser, flags):
    # emulate a chooser that provides no rows: PyClassInformer must fall back
    # to the default colors
    return True


class chooser_row_info_vec_t(object):
    def size(self):
        return 0


class action_handler_t(object):
    def __init__(self):
        pass

    def activate(self, ctx):
        return 0

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class action_desc_t(object):
    def __init__(self, name, label, handler, shortcut=None, tooltip=None, icon=-1):
        self.name = name
        self.label = label
        self.handler = handler
        self.shortcut = shortcut
        self.tooltip = tooltip
        self.icon = icon


def register_action(desc):
    if desc.name in ACTIONS:
        return False
    ACTIONS[desc.name] = desc
    return True


def unregister_action(name):
    ACTIONS.pop(name, None)
    return True


def attach_action_to_menu(menu_path, name, flags=0):
    MENU_ATTACHMENTS.append((menu_path, name))
    return True


def detach_action_from_menu(menu_path, name):
    return True


def attach_action_to_popup(widget, popup_handle, name, flags=0):
    POPUP_ATTACHMENTS.append((widget, popup_handle, name))
    return True


class UI_Hooks(object):
    def __init__(self):
        self.hooked = False

    def hook(self):
        self.hooked = True
        return True

    def unhook(self):
        self.hooked = False
        return True


CH_MULTI = 0x0001
CH_ATTRS = 0x0002
CH_TM_FULL_TREE = 0x0004
CH_NON_PERSISTED_TREE = 0x0008
CH_RENAME_IS_EDIT = 0x0010
CH_CAN_INS = 0x0020
CH_NO_SORT = 0x0040
CH_KEEP = 0x0080

CHCOL_PLAIN = 0x00000000
CHCOL_EA = 0x00000001
CHCOL_DEC = 0x00000002
CHCOL_HEX = 0x00000003
CHCOL_FNAME = 0x00000004
CHCOL_INODENAME = 0x00000008


class Choose(object):
    CH_MULTI = CH_MULTI
    CH_ATTRS = CH_ATTRS
    CH_TM_FULL_TREE = CH_TM_FULL_TREE
    CH_NON_PERSISTED_TREE = CH_NON_PERSISTED_TREE
    CH_RENAME_IS_EDIT = CH_RENAME_IS_EDIT
    CHCOL_PLAIN = CHCOL_PLAIN
    CHCOL_EA = CHCOL_EA
    CHCOL_DEC = CHCOL_DEC
    CHCOL_HEX = CHCOL_HEX
    CHCOL_INODENAME = CHCOL_INODENAME

    CH_MULTI = 0x0001
    CH_ATTRS = 0x0002
    CH_TM_FULL_TREE = 0x0004
    CH_NON_PERSISTED_TREE = 0x0008
    CH_RENAME_IS_EDIT = 0x0010
    CH_CAN_INS = 0x0020
    CH_NO_SORT = 0x0040

    NOTHING_CHANGED = (0,)
    ALL_CHANGED = (1,)

    def __init__(self, title, cols, flags=0, icon=-1, popup_names=None):
        self.title = title
        self.cols = cols
        self.flags = flags
        self.icon = icon
        self.shown = False
        CHOSERS.append(self)

    def Show(self, modal=False):
        self.shown = True
        self.OnInit()
        return True

    def OnInit(self):
        return True

    def Close(self):
        self.shown = False
        if hasattr(self, "OnClose"):
            self.OnClose()

    def GetSelectedItems(self):
        return []


class Form(object):
    class FormChangeCb(object):
        def __init__(self, func):
            self.func = func

    class RadGroupControl(object):
        def __init__(self, names):
            self.names = names
            for name in names:
                setattr(self, name, type("Radio", (), {"selected": False})())

    class ChkGroupControl(object):
        def __init__(self, names):
            self.names = names
            for name in names:
                setattr(self, name, type("Check", (), {"checked": False})())

    def __init__(self, *args, **kwargs):
        self.args = args

    def Compile(self):
        return True

    def Execute(self):
        return 0

    def Free(self):
        return True
