"""Qt helpers that work with both PyQt5 (IDA <= 9.1) and PySide6 (IDA >= 9.2).

IDA 9.5 ships Qt 6.12/PySide6, IDA 9.2 introduced PySide6, and older versions
use PyQt5.  Every helper here degrades gracefully (returns None/False) when Qt
is not available at all, which is the case for idalib / text mode sessions.
"""

import ida_kernwin

try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError


def _import_qt():
    """Return ``(binding, QtCore, QtWidgets, QtGui, wrapinstance)`` or None."""
    try:
        from sip import wrapinstance
        from PyQt5 import QtCore, QtWidgets, QtGui
        return ("pyqt5", QtCore, QtWidgets, QtGui, wrapinstance)
    except ImportError:
        pass
    try:
        from shiboken6 import wrapInstance as wrapinstance
        from PySide6 import QtCore, QtWidgets, QtGui
        return ("pyside6", QtCore, QtWidgets, QtGui, wrapinstance)
    except ImportError:
        return None


def _qt():
    return _import_qt()


def can_use_qt():
    return _import_qt() is not None


def get_qver():
    qt = _import_qt()
    if qt is None:
        return (0, 0)
    v = qt[1].qVersion()
    parts = [int(x) for x in v.split(".")]
    while len(parts) < 2:
        parts.append(0)
    return parts[0], parts[1]


def get_widget(w, widget_types=None, title=None, max_try=100):
    """Walk up the parent chain of ``w`` looking for a widget of interest."""
    qt = _import_qt()
    if qt is None or w is None:
        return None
    _, _, QtWidgets, _, wrapinstance = qt

    if widget_types is None:
        widget_types = set([QtWidgets.QWidget, QtWidgets.QSplitter])

    widget = wrapinstance(int(w), QtWidgets.QWidget)
    i = 0
    while i < max_try and widget and type(widget) != QtWidgets.QMainWindow:
        if type(widget) in widget_types:
            if title is None or title == widget.windowTitle():
                return widget
        widget = widget.parent()
        i += 1
    return None


def get_qmain_window(w, max_try=100):
    qt = _import_qt()
    if qt is None or w is None:
        return None
    _, _, QtWidgets, _, wrapinstance = qt

    widget = wrapinstance(int(w), QtWidgets.QWidget)
    i = 0
    while i < max_try and widget:
        if type(widget) == QtWidgets.QMainWindow:
            return widget
        widget = widget.parent()
        i += 1
    return None


def find_toolbar(widget, toolbar_name):
    qt = _import_qt()
    if qt is None or widget is None:
        return None
    _, _, QtWidgets, _, _ = qt

    for cwidget in widget.children():
        if type(cwidget) == QtWidgets.QToolBar and cwidget.objectName() == toolbar_name:
            return cwidget
    return None


def set_toobar_visible(w, toolbar_name):
    qt = _import_qt()
    if qt is None or w is None:
        return False
    _, QtCore, QtWidgets, QtGui, _ = qt

    widget = get_qmain_window(w)
    if widget is None:
        return False

    tb_widget = find_toolbar(widget, toolbar_name)
    if tb_widget is None:
        return False
    if not tb_widget.isVisible():
        tb_widget.setEnabled(True)
        tb_widget.setVisible(True)
        return True
    try:
        # Qt 6 moved the toolbar areas into QtCore.Qt.ToolBarArea
        area = getattr(getattr(QtCore.Qt, "ToolBarArea", QtCore.Qt), "TopToolBarArea", 4)
        widget.addToolBar(area, tb_widget)
    except Exception:
        pass
    return False


class enable_toolbar_t(ida_kernwin.UI_Hooks):
    def __init__(self, toolbar_name):
        self.toolbar_name = toolbar_name
        ida_kernwin.UI_Hooks.__init__(self)
        self.hook()

    def ready_to_run(self):
        self.enable_toolbar()

    def enable_toolbar(self):
        try:
            widget = ida_kernwin.open_navband_window(ida_kernwin.get_screen_ea(), 1)
        except Exception:
            widget = None
        if widget is not None:
            set_toobar_visible(widget, self.toolbar_name)

    def __del__(self):
        try:
            self.unhook()
        except Exception:
            pass


class dark_mode_checker_t(object):

    @staticmethod
    def is_dark_mode():
        return dark_mode_checker_t.is_dark_mode_with_main()

    @staticmethod
    def get_main_window():
        qt = _import_qt()
        if qt is None:
            return None
        _, _, QtWidgets, _, _ = qt

        candidates = list(QtWidgets.QApplication.topLevelWidgets())
        for widget in [QtWidgets.QApplication.activeWindow(),
                       QtWidgets.QApplication.focusWidget()] + candidates:
            while widget:
                if isinstance(widget, QtWidgets.QMainWindow):
                    return widget
                widget = widget.parent()
        return None

    @staticmethod
    def _is_dark_mode(bgcolor, threshold=128):
        if bgcolor >= 0:
            bgcolor &= 0xffffff
            green = bgcolor >> 16
            blue = (bgcolor >> 8) & 0xff
            red = bgcolor & 0xff
            if green < threshold and blue < threshold and red < threshold:
                return True
        return False

    @staticmethod
    def is_dark_mode_with_main():
        qt = _import_qt()
        if qt is None:
            return False
        _, _, QtWidgets, _, _ = qt

        widget = dark_mode_checker_t.get_main_window()
        if not isinstance(widget, QtWidgets.QMainWindow):
            return False
        bgcolor = dark_mode_checker_t.get_bgcolor(x=0, y=0, w=widget)
        if bgcolor < 0:
            return False
        return dark_mode_checker_t._is_dark_mode(bgcolor)

    @staticmethod
    def get_bgcolor(x=0, y=0, w=None):
        bgcolor = -1
        qt = _import_qt()
        if qt is None or w is None:
            return bgcolor
        _, QtCore, QtWidgets, QtGui, wrapinstance = qt

        try:
            if str(w).startswith("<Swig Object of type 'TWidget *' at") and str(type(w)) in [
                    "<class 'SwigPyObject'>", "<type 'SwigPyObject'>"]:
                widget = wrapinstance(int(w), QtWidgets.QWidget)
            else:
                widget = w

            pixmap = widget.grab(QtCore.QRect(x, y, x + 1, y + 1))
            image = QtGui.QImage(pixmap.toImage())
            bgcolor = image.pixel(0, 0)
        except Exception:
            bgcolor = -1
        return bgcolor
