import os
import json
import re

#: class names (or name prefixes) of well known libraries such as the STL and MFC
DEFAULT_RULES = os.path.join(os.path.dirname(__file__), "lib_classes.json")


class lib_classes_checker_t(object):

    def __init__(self, rules=DEFAULT_RULES):
        self.lib_class_ptns = {"=": [], "startswith": [], "regex": []}
        try:
            with open(rules) as f:
                data = json.load(f)
        except Exception as e:
            print("[PyClassInformer] Warning: could not load {} ({}). "
                  "Known library classes will not be detected.".format(rules, e))
            data = None

        if isinstance(data, dict):
            for key in self.lib_class_ptns:
                values = data.get(key)
                if isinstance(values, list):
                    self.lib_class_ptns[key] = values

    def does_class_startwith(self, name, ptns):
        for ptn in ptns:
            if name.startswith(ptn):
                return True
        return False

    def does_class_match_regex_ptns(self, name, ptns):
        for ptn in ptns:
            try:
                if re.match(ptn, name):
                    return True
            except re.error:
                continue
        return False

    def _is_class_lib(self, name):
        if name in self.lib_class_ptns["="]:
            return True
        if self.does_class_startwith(name, self.lib_class_ptns["startswith"]):
            return True
        if self.does_class_match_regex_ptns(name, self.lib_class_ptns["regex"]):
            return True
        return False

    def is_class_lib(self, name):
        if not name:
            return False
        if self._is_class_lib(name):
            return True
        # also check the class name without its template arguments, so that
        # e.g. "std::vector<int>" also matches a "std::vector" pattern
        base = name.split("<")[0].strip()
        if base and base != name and self._is_class_lib(base):
            return True
        return False


#: the rules file is parsed once per database, not once per vftable
_checker = None


def get_checker():
    global _checker
    if _checker is None:
        _checker = lib_classes_checker_t()
    return _checker


def set_libflag(data):
    checker = get_checker()
    for vftable_ea in data:
        col = data[vftable_ea]

        # get the class name that owns the vftable
        class_name = col.name

        # check the class is a part of standard library classes such as STL and MFC
        col.libflag = col.LIBNOTLIB
        if checker.is_class_lib(class_name):
            col.libflag = col.LIBLIB

"""
lib_class_ptns = lib_classes_checker_t()
print(lib_class_ptns.is_class_lib("std::aaaa")) # True
print(lib_class_ptns.is_class_lib("CWinApp")) # True
print(lib_class_ptns.is_class_lib("CSimpleTextApp")) # False
"""
