import idc
import ida_kernwin
import ida_idaapi
import ida_dirtree
import ida_name

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.pci_utils")
ida_idaapi.require("pyclassinformer.msvc_rtti")
ida_idaapi.require("pyclassinformer.dirtree_utils")
import pyclassinformer.dirtree_utils as dirtree_utils
import pyclassinformer.msvc_rtti as msvc_rtti
import pyclassinformer.pci_utils as pci_utils

def chcol(name):
    """Resolve a CHCOL_* constant, which some IDA versions expose on
    ida_kernwin.Choose and others on the ida_kernwin module."""
    for obj in (ida_kernwin.Choose, ida_kernwin):
        value = getattr(obj, "CHCOL_" + name, None)
        if value is not None:
            return value
    return 0


COLUMNS = [
    ("EA",         15 | chcol("EA") | chcol("FNAME")),
    ("Name",       50 | chcol("PLAIN") | chcol("INODENAME")),
    ("Offset",      4 | chcol("HEX")),
    ("CdOffset",    4 | chcol("HEX")),
    ("Flags",       6 | chcol("PLAIN")),
    ("Bases",       4 | chcol("DEC")),
    ("Pure",        4 | chcol("DEC")),
    ("Refs",        4 | chcol("DEC")),
]


def sanitize_name(name):
    """Make a class name usable as a directory entry name."""
    if not name:
        return "unknown"
    for c in ("/", "\\", "\0"):
        name = name.replace(c, "_")
    return name[:255]


# dirspec for the dirtree
class my_dirspec_t(ida_dirtree.dirspec_t):
    def __init__(self, chooser):
        ida_dirtree.dirspec_t.__init__(self)
        self.chooser = chooser

        self.inodes = []
        self.name_index = {}

    def add_entry(self, dirpath, name):
        if (dirpath, name) not in self.inodes:
            new_inode = len(self.inodes)
            self.inodes.append((dirpath, name))
            self.name_index[dirpath, name] = new_inode
        # inode has already been inserted
        else:
            new_inode = -1
        return new_inode

    def update_parent_dir(self, inode, new_dirpath):
        # get old dir and node name by inode
        old_dirpath, name = self.get_name_idx(inode)

        # change dir entry to new one
        if old_dirpath != new_dirpath:
            del self.name_index[old_dirpath, name]
            self.name_index[new_dirpath, name] = inode
            self.inodes[inode] = (new_dirpath, name)

    def get_name_idx(self, inode):
        if inode >= 0 and inode < len(self.inodes):
            return self.inodes[inode]

    def get_name(self, inode, flags=0):
        return self.get_name_idx(inode)[1]

    def get_inode(self, dirpath, name):
        return self.name_index.get((dirpath, name), ida_dirtree.direntry_t.BADIDX)

    def n_inodes(self):
        return len(self.inodes)

    def rename_inode(self, inode, newname):
        return ida_dirtree.dirspec_t.rename_inode(self, inode, newname)

    def get_attrs(self, inode):
        pass

    def unlink_inode(self, inode):
        pass


class mc_tree_t(ida_kernwin.Choose):

    def __init__(self, title, data, base_class_paths, icon=-1):
        self.dirspec = my_dirspec_t(self)
        self.dirtree = ida_dirtree.dirtree_t(self.dirspec)

        self.data = data
        self.base_class_paths = base_class_paths
        self.u = pci_utils.utils.get()

        ida_kernwin.Choose.__init__(
            self,
            title,
            COLUMNS,
            flags=ida_kernwin.CH_TM_FULL_TREE | ida_kernwin.CH_NON_PERSISTED_TREE | ida_kernwin.CH_RENAME_IS_EDIT,
            icon=icon
        )
        self.items = []

    # ------------------------------------------------------------------
    def add_item(self, dirtree_path, ea, name, offset=ida_idaapi.BADADDR,
                 cdoffset=ida_idaapi.BADADDR, flags="", bases=0, pure=0, refs=0):
        r = -1
        inode = self.dirspec.add_entry(dirtree_path, name)
        if inode >= 0:
            self.items.append([
                hex(ea) if ea != ida_idaapi.BADADDR else "",
                name,
                hex(offset) if offset != ida_idaapi.BADADDR else "",
                hex(cdoffset) if cdoffset != ida_idaapi.BADADDR else "",
                flags,
                "{}".format(bases) if bases else "",
                "{}".format(pure) if pure else "",
                "{}".format(refs) if refs else "",
                ea])
            self.dirtree.chdir(dirtree_path)
            r = self.dirtree.link(inode)
        return inode, r

    def process_data(self):
        for vftable_ea in self.data:
            col = self.data[vftable_ea]
            class_name = col.name

            # for creating a directory of a class name
            dirtree_path = "/" + sanitize_name(class_name) + "/"  # needs the last slash for a directory
            self.dirtree.mkdir(dirtree_path)

            bc_path = self.base_class_paths.get(vftable_ea)
            if not bc_path:
                continue
            actual_class_name = bc_path[-1].name

            # for vftable folder
            dp = dirtree_path + "vftable/"  # needs the last slash for a directory
            self.dirtree.mkdir(dp)

            # for vftable with COL info
            # get demangled name (fall back to the name PyClassInformer
            # applied to the vftable/RTTI pointer when IDA only has an
            # auto generated name)
            name = ida_name.get_short_name(vftable_ea) or ""
            if name.startswith(("off_", "unk_", "dword_", "qword_", "")):
                alternative = ""
                col_ptr_ea = getattr(col, "col_ptr_ea", ida_idaapi.BADADDR)
                if col_ptr_ea != ida_idaapi.BADADDR:
                    alternative = ida_name.get_short_name(col_ptr_ea) or ""
                if alternative and not alternative.startswith(("off_", "unk_", "dword_", "qword_")):
                    name = alternative
                else:
                    name = "vtable__" + class_name
            # add the actual class name information
            if class_name != actual_class_name:
                name += " for {} ({})".format(actual_class_name, col.offset)
            self.add_item(dp, vftable_ea, name, col.offset, col.cdOffset, col.flags,
                          col.nb_bases, col.pure_virtual_count, len(col.refeas))

            # RTTI relevant structures of the vftable (jumpable)
            dp = dirtree_path + "RTTI/"  # needs the last slash for a directory
            self.dirtree.mkdir(dp)
            self.add_item(dp, vftable_ea - self.u.PTR_SIZE, "COL at {:#x}".format(col.ea))
            self.add_item(dp, col.tdea, "TD at {:#x}".format(col.tdea))
            if col.chd is not None:
                self.add_item(dp, col.chdea, "CHD at {:#x}".format(col.chdea))
                if col.chd.bca is not None:
                    self.add_item(dp, col.chd.bcaea, "BCA at {:#x}".format(col.chd.bcaea))

            # for virtual methods folder
            dp = dirtree_path + "virtual methods/"  # needs the last slash for a directory
            self.dirtree.mkdir(dp)

            # if the class has multiple vftables, create a nested folder
            col_offs = self.u.get_col_offs(col, self.data)
            if len(col_offs) > 1:
                # if the class has multiple vftables, create a nested folder with the actual class name
                if class_name != actual_class_name:
                    dp += "virtual methods for {} ({})/".format(actual_class_name, col.offset)  # needs the last slash for a directory
                else:
                    dp += "virtual methods/"  # needs the last slash for a directory
                self.dirtree.mkdir(dp)

            # add virtual methods to the folder
            for vfea in col.vfeas:
                name = ida_name.get_short_name(vfea)
                pure = 1 if msvc_rtti.is_pure_virtual(vfea) else 0
                self.add_item(dp, vfea, name, pure=pure)

            # add functions that refer to vftable
            dp = dirtree_path + "possible ctors or dtors/"  # needs the last slash for a directory
            self.dirtree.mkdir(dp)
            for funcea in col.refeas:
                name = ida_name.get_short_name(funcea)
                self.add_item(dp, funcea, name)

            # for hierarchy path
            for off in col.paths:
                for path in col.paths[off]:
                    dp = dirtree_path + "hierarchy"
                    self.dirtree.mkdir(dp + "/")  # needs the last slash for a directory
                    for bcd in path:
                        # make directory for a BCD
                        flags = msvc_rtti.flags_to_short(bcd.attributes, msvc_rtti.BCD_FLAGS)
                        dp += "/" + sanitize_name(bcd.name) + " ({},{},{})".format(bcd.mdisp, bcd.pdisp, bcd.vdisp)
                        if flags:
                            dp += " [{}]".format(flags)
                        self.dirtree.mkdir(dp + "/")  # needs the last slash for a directory

                        # IDA seems not to apply quick filter to directories.
                        # to avoid that, insert a text node as well if you want.

    def OnInit(self):
        self.process_data()
        return True

    def OnGetSize(self):
        return self.dirspec.n_inodes()

    def OnGetLine(self, n):
        return self.items[n][:len(COLUMNS)]

    # for old versions of IDA
    def OnSelectLine(self, n):
        idc.jumpto(self.items[n][-1])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

    def OnGetEA(self, n):
        return self.items[n][-1]

    def OnInsertLine(self, sel):
        pass

    def OnDeleteLine(self, sel):
        pass

    def OnEditLine(self, sel):
        pass

    def OnSelectionChange(self, sel):
        # get inode and get the current dir and the cached entry
        inode = self.OnIndexToInode(sel)
        curr_dir, name = self.dirspec.get_name_idx(inode)
        parent_dir = dirtree_utils.get_parent_dir_by_inode(self.dirtree, inode) + "/"  # add slash at the end

        # need to update the directory in the cached inodes if the current dir and the parent dir of the selection are not matched.
        if parent_dir != curr_dir:
            self.dirspec.update_parent_dir(inode, parent_dir)

    def OnRefresh(self, sel):
        pass

    def OnGetDirTree(self):
        return self.dirspec, self.dirtree

    def OnIndexToInode(self, n):
        return n


def show_mc_tree_t(data, paths, icon=-1, modal=False):
    tree = mc_tree_t("[MethodClassifier]", data, paths, icon)
    tree.Show(modal=modal)
    return tree
