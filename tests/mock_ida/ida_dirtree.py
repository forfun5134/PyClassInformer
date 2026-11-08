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


class dirtree_cursor_t(object):
    """Opaque cursor (a tuple of indices in the real SDK)."""

    def __init__(self, value=0):
        self.value = value

    def __repr__(self):
        return "<dirtree_cursor_t %s>" % self.value


class dirtree_iterator_t(object):
    """Iterator state used by dirtree_t.findfirst()/findnext()."""

    def __init__(self):
        self.cursor = dirtree_cursor_t()
        self.pattern = ""


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

    def _children(self, parent):
        """Immediate children (entries and sub directories) of ``parent``."""
        parent = _norm(parent)
        prefix = "" if parent == "/" else parent
        result = []
        for path in set(list(self.entries) + list(self.dirs)):
            if path == "/" or not path.startswith(prefix + "/"):
                continue
            rest = path[len(prefix) + 1:]
            if not rest or "/" in rest:
                continue
            result.append(path)
        return sorted(result)

    def findfirst(self, iterator, pattern):
        # the plugin only uses the "<dir>/*" form
        base = pattern[:-2] if pattern.endswith("/*") else pattern
        iterator.pattern = pattern
        iterator._items = self._children(base)
        iterator._index = 0
        if not iterator._items:
            iterator.cursor = None
            return False
        iterator.cursor = iterator._items[0]
        return True

    def findnext(self, iterator):
        items = getattr(iterator, "_items", [])
        index = getattr(iterator, "_index", 0) + 1
        if index >= len(items):
            return False
        iterator._index = index
        iterator.cursor = items[index]
        return True

    def resolve_cursor(self, cursor):
        path = _norm(cursor)
        if path in self.entries:
            return direntry_t(self.entries[path], False)
        return direntry_t(BADIDX, True)

    def get_abspath(self, cursor):
        return _norm(cursor) if cursor else "/"

    def get_parent_cursor(self, cursor):
        return os.path.dirname(_norm(cursor)) or "/"


class _StdDirtree(dirtree_t):
    """Simulation of the Functions/Names dirtrees.

    The real dirtrees are dynamic views of the database: renaming a function
    changes its path.  The mock therefore stores only the *folder* of every
    inode (the entry address) and computes the path from the current name,
    which is exactly what PyClassInformer relies on when it moves functions
    into "/classes/<class>/virtual methods/".
    """

    def __init__(self, kind):
        dirtree_t.__init__(self, dirspec_t())
        self.kind = kind
        self.dirs = {"/"}
        self.entries = {}      # not used: the entries are computed on demand
        self.folders = {}      # inode (ea) -> dirpath

    # -- helpers ------------------------------------------------------
    def _all_inodes(self):
        import image
        return sorted(image.IMAGE.funcs)

    def _path(self, inode):
        import ida_funcs
        name = ida_funcs.get_func_name(inode)
        if not name:
            return None
        folder = _norm(self.folders.get(inode, "/"))
        return "/" + name if folder == "/" else folder + "/" + name

    # -- dirtree_t interface -----------------------------------------
    def find_entry(self, de):
        return self._path(de.index) or "/"

    def get_abspath(self, cursor):
        return _norm(cursor) if cursor else "/"

    def get_parent_cursor(self, cursor):
        return os.path.dirname(_norm(cursor)) or "/"

    def get_name(self, inode):
        import ida_funcs
        return ida_funcs.get_func_name(inode) or str(inode)

    def mkdir(self, path):
        return dirtree_t.mkdir(self, path)

    def chdir(self, path):
        return 0

    def link(self, inode):
        return 0

    def rename(self, old, newdir):
        old = _norm(old)
        newdir = _norm(newdir)
        for inode in self._all_inodes():
            if self._path(inode) == old:
                self.folders[inode] = newdir
                return 0
        return -1

    def _children(self, parent):
        """Entries and immediate sub directories of ``parent``."""
        parent = _norm(parent)
        prefix = "" if parent == "/" else parent
        result = []
        for inode in self._all_inodes():
            if _norm(self.folders.get(inode, "/")) != parent:
                continue
            path = self._path(inode)
            if path:
                result.append(path)
        for path in self.dirs:
            if path == "/" or not path.startswith(prefix + "/"):
                continue
            rest = path[len(prefix) + 1:]
            if rest and "/" not in rest:
                result.append(path)
        return sorted(result)

    def resolve_cursor(self, cursor):
        path = _norm(cursor)
        for inode in self._all_inodes():
            if self._path(inode) == path:
                return direntry_t(inode, False)
        return direntry_t(BADIDX, True)


STD_TREES = {}


def get_std_dirtree(dirtree_id):
    tree = STD_TREES.get(dirtree_id)
    if tree is None:
        tree = _StdDirtree(dirtree_id)
        STD_TREES[dirtree_id] = tree
    return tree
