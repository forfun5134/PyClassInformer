"""Mock of ida_dirtree."""
import os

DIRTREE_FUNCS = 1
DIRTREE_NAMES = 2
DIRTREE_LOCAL_TYPES = 3

BADIDX = 0xFFFFFFFF


class direntry_t(object):
    BADIDX = BADIDX

    def __init__(self, inode=BADIDX, isdir=False):
        self.index = inode
        self.isdir = isdir


class dirspec_t(object):
    def __init__(self):
        pass

    def rename_inode(self, inode, newname):
        return True


def _norm(path):
    path = "/" + path.strip("/")
    return path if path != "/" else "/"


class dirtree_t(object):
    def __init__(self, dirspec):
        self.dirspec = dirspec
        self.cwd = "/"
        self.dirs = {"/"}
        self.entries = {}          # abspath -> inode

    def mkdir(self, path):
        parts = _norm(path).strip("/").split("/")
        cur = ""
        for part in parts:
            if not part:
                continue
            cur += "/" + part
            self.dirs.add(cur)
        return 0

    def chdir(self, path):
        self.cwd = _norm(path)
        return 0

    def link(self, inode):
        name = self.dirspec.get_name(inode)
        path = _norm(self.cwd)
        self.entries[(path + ("/" if path != "/" else "") + name)] = inode
        return 0

    def rename(self, old, newdir):
        inode = self.entries.pop(old, None)
        if inode is None:
            return -1
        name = self.dirspec.get_name(inode)
        self.entries[_norm(newdir) + "/" + name if _norm(newdir) != "/" else "/" + name] = inode
        return 0

    def find_entry(self, de):
        for path, inode in self.entries.items():
            if inode == de.index:
                return path
        if isinstance(de, direntry_t) and de.isdir:
            return "/"
        return "/"

    def get_abspath(self, cursor):
        return cursor if cursor else "/"

    def get_parent_cursor(self, cursor):
        parent = os.path.dirname(_norm(cursor)) or "/"
        return parent

    def resolve_cursor(self, cursor):
        return direntry_t(0, False)


class _StdDirtree(dirtree_t):
    """Simulation of the Functions/Names dirtree: flat, one entry per function."""

    def __init__(self, kind):
        dirtree_t.__init__(self, dirspec_t())
        self.kind = kind
        self.dirs = {"/"}
        self.entries = {}

    def find_entry(self, de):
        ea = de.index
        return "/" + (self.dirspec.get_name(de.index) if False else str(ea))

    def get_abspath(self, cursor):
        import ida_name
        ea = int(cursor.strip("/") or 0)
        if ea:
            return "/" + ida_name.get_name(ea)
        return "/"

    def get_parent_cursor(self, cursor):
        return "/"

    def get_name(self, inode):
        return str(inode)


STD_TREES = {}


def get_std_dirtree(dirtree_id):
    tree = STD_TREES.get(dirtree_id)
    if tree is None:
        tree = _StdDirtree(dirtree_id)
        STD_TREES[dirtree_id] = tree
    return tree
