import ida_idaapi
import ida_kernwin

import os

dirpath = os.path.dirname(os.path.abspath(__file__))
script_dir = os.path.join(dirpath, "pyclassinformer")
if not os.path.isdir(script_dir):
    script_dir = os.path.join(dirpath, "..", "pyclassinformer")

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.qtutils")
import pyclassinformer.qtutils as qtutils

# for IDA 7.4 or earlier
try:
    g_flags = ida_idaapi.PLUGIN_MULTI
except AttributeError:
    g_flags = ida_idaapi.PLUGIN_DRAW

# for IDA 7.4 or earlier
try:
    g_obj = ida_idaapi.plugmod_t
except AttributeError:
    g_obj = object

g_plugmod_flag = False
if g_flags != ida_idaapi.PLUGIN_DRAW and g_obj != object:
    g_plugmod_flag = True


def _load_icon():
    path = os.path.join(script_dir, "pci_icon.png")
    try:
        with open(path, "rb") as f:
            data = f.read()
        return ida_kernwin.load_custom_icon(data=data, format="png")
    except Exception:
        # the icon is a nice to have, never let it break the plugin
        return -1


class pci_plugin_t(ida_idaapi.plugin_t):
    flags = g_flags
    comment = "Yet Another RTTI Parser"
    wanted_name = "PyClassInformer"
    wanted_hotkey = "Alt-Shift-L"
    help = "Press '" + wanted_hotkey + "' to display the " + wanted_name + " result."

    toolbar_displayed_name = wanted_name
    toolbar_name = toolbar_displayed_name + 'Toolbar'

    action_name = "pyclassinformer:execute"
    menu_path = "Edit/Plugins/"

    act_icon = _load_icon()

    class exec_pci_action(ida_kernwin.action_handler_t):
        def __init__(self, plugin):
            ida_kernwin.action_handler_t.__init__(self)
            import weakref
            self.v = weakref.ref(plugin)

        def activate(self, ctx):
            plugin = self.v()
            if plugin is not None:
                plugin.plugin_mod.run(None)

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    def attach_to_menu_and_toolbar(self):
        # A previous load (a plugin reload, or an aborted init) may still own
        # the action name; IDA would refuse to register it again.
        try:
            ida_kernwin.unregister_action(self.action_name)
        except Exception:
            pass
        # insert the action
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
            self.action_name,
            self.comment,
            self.exec_pci_action(self),
            None,
            self.wanted_name,
            self.act_icon))

        # attach the action to menu
        ida_kernwin.attach_action_to_menu(
            self.menu_path,
            self.action_name,
            ida_kernwin.SETMENU_APP)

        # create the toolbar and attach the action to the toolbar
        ida_kernwin.create_toolbar(self.toolbar_name, self.toolbar_displayed_name)
        ida_kernwin.attach_action_to_toolbar(self.toolbar_name, self.action_name)

        # install ui hook to enable toolbar later
        try:
            self.ph = qtutils.enable_toolbar_t(self.toolbar_name)
        except Exception:
            self.ph = None

    @staticmethod
    class register_icon(ida_kernwin.UI_Hooks):
        def updated_actions(self):
            # update_action_icon() takes the *action name* (not the menu path):
            # the icon of the action can only be set once the actions have been
            # created, which is when this hook fires
            try:
                done = ida_kernwin.update_action_icon(
                    pci_plugin_t.action_name, pci_plugin_t.act_icon)
            except Exception:
                done = False
            if done:
                # unhook this if it's successful
                self.unhook()

    def init(self):
        ida_kernwin.msg("############### %s (%s) ###############%s" % (self.wanted_name, self.comment, os.linesep))
        ida_kernwin.msg("%s%s" % (self.help, os.linesep))

        # attach action to menu and toolbar
        try:
            self.attach_to_menu_and_toolbar()
        except Exception as e:
            ida_kernwin.msg("PyClassInformer: could not add the menu/toolbar entries: %s%s"
                            % (e, os.linesep))

        r = self.flags
        self.plugin_mod = pci_plugmod_t()
        if g_plugmod_flag:
            r = self.plugin_mod
        return r

    # for old IDA til 7.6
    def run(self, arg):
        self.plugin_mod.run(arg)

    # for old IDA til 7.6
    def term(self):
        # term() may arrive without a successful init() (a failed load, and
        # IDA deletes the plugin object even then)
        plugin_mod = getattr(self, "plugin_mod", None)
        if plugin_mod is not None:
            plugin_mod.term()


class pci_plugmod_t(g_obj):
    toolbar_name = pci_plugin_t.toolbar_name
    menu_path = pci_plugin_t.menu_path
    action_name = pci_plugin_t.action_name
    act_icon = pci_plugin_t.act_icon

    def __del__(self):
        self.term()

    def run(self, arg):
        pci_plugmod_t.run_pci(icon=self.act_icon)

    def term(self):
        self.detatch_from_menu_and_toolbar()

    def detatch_from_menu_and_toolbar(self):
        # term() runs on a plugin reload and while IDA shuts down (from
        # __del__), when the UI may already be gone and nothing was
        # registered: every step is guarded so that the cleanup itself never
        # produces an error.
        for step in (
            lambda: ida_kernwin.detach_action_from_toolbar(self.toolbar_name, self.action_name),
            lambda: ida_kernwin.delete_toolbar(self.toolbar_name),
            lambda: ida_kernwin.detach_action_from_menu(self.menu_path, self.action_name),
            lambda: ida_kernwin.unregister_action(self.action_name),
        ):
            try:
                step()
            except Exception:
                pass
        if self.act_icon not in (-1, None):
            try:
                ida_kernwin.free_custom_icon(self.act_icon)
            except Exception:
                pass

    @staticmethod
    def run_pci(icon=-1):
        # imported lazily: the config form needs Qt, and importing the plugin
        # must keep working when Qt is not available
        ida_idaapi.require("pyclassinformer.pci_config_form")
        ida_idaapi.require("pyclassinformer.pyclassinformer")
        import pyclassinformer.pci_config_form as pci_config_form
        import pyclassinformer.pyclassinformer as pci_core

        config = pci_config_form.pci_form_t.show()
        if config is not None:
            pci_core.run_pci(config=config, icon=icon)
        else:
            print("PyClassInformer: Canceled")


def PLUGIN_ENTRY():
    return pci_plugin_t()


# install a UI hook to add icon in the plugin menu
try:
    ri = pci_plugin_t.register_icon()
    ri.hook()
except Exception:
    ri = None
