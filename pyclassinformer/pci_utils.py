import idautils
import ida_bytes
import ida_idaapi
import ida_segment
import ida_typeinf
import ida_nalt
import ida_idp

try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.ida_compat")
import pyclassinformer.ida_compat as ida_compat

ida_9_or_later = ida_compat.IS_IDA_9_OR_LATER


def get_member_by_name(tif, name):
    """Return the ida_typeinf.udm_t of the member ``name`` in ``tif``.

    IDA 8.5 removed ida_struct.get_member_by_name(), and IDA 9.0 removed
    ida_struct completely, so this helper works on every supported version.
    """
    if tif is None:
        return None
    if not tif.is_struct():
        return None

    udm = ida_typeinf.udm_t()
    udm.name = name
    idx = tif.find_udm(udm, ida_typeinf.STRMEM_NAME)
    if idx != -1:
        return udm
    # fall back to iterating the members (older IDAPython builds)
    udt = ida_typeinf.udt_type_data_t()
    if tif.get_udt_details(udt):
        for member in udt:
            if member.name == name:
                return member
    return None


def get_offset_ptr(v, force_bitness=False):
    """Read the pointer/offset stored at ``v``."""
    target_ea = ida_idaapi.BADADDR
    if v == ida_idaapi.BADADDR:
        return target_ea
    flags = ida_bytes.get_full_flags(v)
    if not force_bitness and ida_bytes.is_qword(flags):
        target_ea = ida_bytes.get_qword(v)
    elif not force_bitness and ida_bytes.is_dword(flags):
        target_ea = ida_bytes.get_dword(v)
    else:
        seg = ida_segment.getseg(v)
        if seg is None:
            return target_ea
        off_size = 1 << (seg.bitness + 1)
        if off_size == 8:
            target_ea = ida_bytes.get_qword(v)
        elif off_size == 4:
            target_ea = ida_bytes.get_dword(v)
        elif off_size == 2:
            target_ea = ida_bytes.get_word(v)
        else:
            target_ea = ida_bytes.get_byte(v)
    return target_ea


def get_offset_fptr(v, force_bitness=False, u=None):
    """Read the pointer at ``v`` and return it if it points to code."""
    target_ea = ida_idaapi.BADADDR
    tmp_ea = get_offset_ptr(v, force_bitness)
    if u is not None:
        tmp_ea = u.normalize_code_ptr(tmp_ea)
    if tmp_ea == ida_idaapi.BADADDR:
        return target_ea
    flags = ida_bytes.get_full_flags(tmp_ea)
    if ida_bytes.is_code(flags):
        target_ea = tmp_ea
    return target_ea


def get_vtbl_methods(target_ea, u=None, max_entries=8192):
    """Yield the addresses of the virtual methods stored in the vftable.

    A vftable is a run of pointers to code.  The run ends at the first slot
    that does not point to code anymore (e.g. the RTTI pointer of the next
    vftable, which points into a data section), at the end of the segment, or
    when a structure type starts.

    The previous implementation relied on ida_bytes.next_that(has_xref) to
    find the end of the vftable, which depends on whether IDA created offsets
    for the method slots - something that differs between IDA versions and
    analysis settings (and made the plugin report a single method per vftable
    in some databases).  Walking the slots is deterministic.
    """
    if u is None:
        u = utils.get()

    seg = ida_segment.getseg(target_ea)
    if seg is None:
        return

    item_diff = 1 << (seg.bitness + 1)
    ea = target_ea
    n = 0
    while ea != ida_idaapi.BADADDR and ea + item_diff <= seg.end_ea and n < max_entries:
        # stop when the slot does not hold a pointer to code anymore
        target = get_offset_fptr(ea, force_bitness=True, u=u)
        if target == ida_idaapi.BADADDR:
            break

        yield target
        n += 1

        nxt = ea + item_diff
        if nxt + item_diff > seg.end_ea:
            break
        # stop at the beginning of another (typed) structure such as the RTTI
        # pointer of the next vftable
        try:
            if ida_bytes.is_struct(ida_bytes.get_full_flags(nxt)):
                break
        except Exception:
            pass
        ea = nxt


class utils(object):
    text = 0
    data = 0
    rdata = 0
    valid_ranges = []
    within = lambda self, x, rl: any([True for r in rl if r[0] <= x <= r[1]])

    REF_OFF = 0
    x64 = 0
    PTR_TYPE = 0
    PTR_SIZE = 0

    #: cache of instances, keyed by the currently opened database
    _instances = {}

    #: cache for get_cols_by_col(): (result dict, {(tdea, chdea): [COL]})
    _cols_cache = None

    def __init__(self):
        self.text = ida_segment.get_segm_by_name(".text")
        if self.text is None:
            # some binaries rename sections (packed/protected samples).  Fall
            # back to the first code segment so that vftables can still be
            # validated.
            self.text = self._get_code_segment()

        self.data = ida_segment.get_segm_by_name(".data")
        self.rdata = ida_segment.get_segm_by_name(".rdata")
        # try to use rdata if there actually is an rdata segment, otherwise just use data
        if self.rdata is not None and self.data is not None:
            self.valid_ranges = [(self.rdata.start_ea, self.rdata.end_ea), (self.data.start_ea, self.data.end_ea)]
        # fail safe for renaming segment names
        else:
            self.valid_ranges = []
            for seg in utils.get_data_segments():
                self.valid_ranges.append((seg.start_ea, seg.end_ea))

        # importing the plugin does not require an open database
        seg0 = ida_segment.getnseg(0)
        self.x64 = (seg0 is not None and seg0.bitness == 2)
        if self.x64:
            self.PTR_TYPE = ida_bytes.FF_QWORD
            self.REF_OFF = ida_nalt.REF_OFF64
            self.PTR_SIZE = 8
            self.get_ptr = ida_bytes.get_64bit
        else:
            self.PTR_TYPE = ida_bytes.FF_DWORD
            self.REF_OFF = ida_nalt.REF_OFF32
            self.PTR_SIZE = 4
            self.get_ptr = ida_bytes.get_32bit

        # ARM (32 bit) stores the Thumb state in the lowest bit of function
        # pointers, as well as RTTI vftable entries.
        try:
            self.is_arm32 = (ida_idp.ph.id == ida_idp.PLFM_ARM and not self.x64)
        except Exception:
            self.is_arm32 = False

    @classmethod
    def get(cls, refresh=False):
        """Return the utils instance for the database that is currently open.

        ``ida_idaapi.require()`` caches Python modules, so a module level
        ``utils()`` instance would keep pointing to a database that the user
        has already closed.  Reusing a per-database instance fixes that.
        """
        try:
            key = (ida_nalt.get_input_file_path(), ida_nalt.get_imagebase())
        except Exception:
            key = None
        if key is not None and not refresh:
            inst = cls._instances.get(key)
            if inst is not None:
                return inst
        inst = cls()
        if key is not None:
            cls._instances = {key: inst}
        return inst

    @staticmethod
    def _get_code_segment():
        for n in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if seg and ida_segment.get_segm_class(seg) == "CODE":
                return seg
        return None

    @staticmethod
    def get_data_segments():
        for n in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if seg and ida_segment.get_segm_class(seg) == "DATA" and seg and not seg.is_header_segm():
                yield seg

    def update_valid_ranges(self):
        self.valid_ranges = []
        for seg in utils.get_data_segments():
            self.valid_ranges.append((seg.start_ea, seg.end_ea))

    def normalize_code_ptr(self, ea):
        """Clear the Thumb bit of a function pointer on 32 bit ARM."""
        if ea == ida_idaapi.BADADDR:
            return ea
        if self.is_arm32 and (ea & 1):
            return ea & ~1
        return ea

    def in_text(self, ea):
        if self.text is None:
            return True
        return self.text.start_ea <= ea < self.text.end_ea

    def valid_ptr(self, ea, rl=None):
        """Return True if ``ea`` points somewhere inside the database."""
        if ea is None or ea == ida_idaapi.BADADDR or ea == 0:
            return False
        if rl is None:
            rl = self.valid_ranges
        return self.within(ea, rl)

    # for 32-bit binaries, the RTTI structs contain absolute addresses, but for
    # 64-bit binaries, they're offsets from the image base.
    def x64_imagebase(self):
        if self.x64:
            return ida_nalt.get_imagebase()
        else:
            return 0

    def get_strlit(self, addr, max_len=8192):
        """Return the NUL terminated string at ``addr`` as bytes, or None.

        RTTI class names are mangled and can easily exceed a few hundred
        characters (template heavy STL code), so the whole string is read in
        one go instead of scanning bytes one by one.
        """
        if addr is None or addr == ida_idaapi.BADADDR:
            return None
        try:
            b = ida_bytes.get_strlit_contents(addr, -1, ida_nalt.STRTYPE_C)
        except Exception:
            b = None
        if b:
            if len(b) > max_len:
                return None
            return b

        # fall back to a byte wise scan (e.g. when the bytes are undefined)
        length = 0
        while length < max_len:
            c = ida_bytes.get_byte(addr + length)
            if c is None or c == 0 or c == ida_bytes.BADADDR:
                break
            length += 1
        if length == 0 or length >= max_len:
            return None
        try:
            return ida_bytes.get_bytes(addr, length)
        except Exception:
            return None

    def get_strlen(self, addr, max_len=8192):
        b = self.get_strlit(addr, max_len)
        if b is None:
            return None
        return len(b)

    def is_vtable(self, addr):
        """Is ``addr`` the first slot of a vftable (i.e. a pointer to code)?

        The slot in front of a vftable holds the pointer to the RTTI complete
        object locator, so the two slots are checked together.  This does not
        depend on the presence of xrefs, which makes the detection stable
        across IDA versions and analysis settings.
        """
        function = self.normalize_code_ptr(self.get_ptr(addr))
        if not self.in_text(function):
            return False
        # the slot in front of a vftable points to its RTTI in a data section
        if addr < self.PTR_SIZE:
            return False
        colptr = self.get_ptr(addr - self.PTR_SIZE)
        if not self.within(colptr, self.valid_ranges):
            return False
        return True

    @staticmethod
    def to_signed32(n):
        n = n & 0xffffffff
        return n | (-(n & 0x80000000))

    @staticmethod
    def get_refs_to(ea, exact=True):
        """Yield the addresses that reference ``ea``.

        IDA 9.5 also reports pointers to Thumb functions (function address+1)
        unless ida_xref.XREF_EXACT is used.  Passing XREF_EXACT keeps the
        behaviour identical on every version.
        """
        for xref in idautils.XrefsTo(ea, ida_compat.xref_flags(0, exact)):
            yield xref.frm

    @staticmethod
    def get_data_refs_to(ea, exact=True):
        """Yield the addresses that reference ``ea`` as data.

        This is what :func:`idautils.DataRefsTo` does (``XREF_DATA``), plus
        ``XREF_EXACT`` so that IDA 9.5's extra Thumb/MIPS16 aliases are not
        reported twice.
        """
        import ida_xref
        flags = ida_compat.xref_flags(getattr(ida_xref, "XREF_DATA", 0x02), exact)
        for xref in idautils.XrefsTo(ea, flags):
            yield xref.frm

    @classmethod
    def get_refs_to_by_type_name(cls, name):
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, name, ida_typeinf.BTF_STRUCT):
            for xref in cls.get_refs_to(tif.get_tid()):
                yield xref

    @staticmethod
    def get_moff_by_name(struc, name):
        """Return the byte offset of a member of a structure."""
        member = get_member_by_name(struc, name)
        if member is None:
            return -1
        try:
            return member.soff
        except AttributeError:
            # ida_typeinf.udm_t stores offsets in bits
            return member.offset // 8

    def get_cols_by_col(self, col, vftables):
        """Return every COL that belongs to the same class as ``col``.

        A class with multiple vftables (multiple inheritance) has one COL per
        vftable, and all of them share the same type descriptor and the same
        class hierarchy descriptor.  Grouping the COLs this way is much more
        reliable than the xref based detection alone, which depends on how IDA
        happened to create the references.

        The grouping is cached per result dictionary: without it, looking up
        the COLs of every vftable is quadratic (one full pass per vftable),
        which is slow on binaries with hundreds of classes.
        """
        tdea = getattr(col, "tdea", None)
        chdea = getattr(col, "chdea", None)

        cols = None
        if tdea is not None and chdea is not None:
            groups = self._col_groups(vftables)
            key = (tdea, chdea)
            cols = {}
            for other in groups.get(key, ()):
                cols[other.ea] = other
            for other in groups.get((tdea, None), ()):
                cols[other.ea] = other
            for other in groups.get((None, chdea), ()):
                cols[other.ea] = other
            cols[col.ea] = col
            if not cols:
                cols = None

        if cols is None:
            # generic fall back for objects without the RTTI descriptors
            cols = {}
            for other in vftables.values():
                if other is col:
                    cols[other.ea] = other
                    continue
                try:
                    same_td = other.tdea != ida_idaapi.BADADDR and other.tdea == col.tdea
                    same_chd = other.chdea != ida_idaapi.BADADDR and other.chdea == col.chdea
                except AttributeError:
                    continue
                if same_td or same_chd:
                    cols[other.ea] = other

        # xref based detection, as a fallback for caller provided COL objects
        try:
            x = set(self.get_refs_to(col.tdea))
            y = set(self.get_refs_to(col.tid))
            for other in vftables.values():
                if other.ea in (x & y):
                    cols[other.ea] = other
        except Exception:
            pass

        return sorted(cols.values(), key=lambda c: (c.offset, c.ea))

    def _col_groups(self, vftables):
        """Cache of ``(tdea, chdea) -> [COL]`` for the given result dictionary."""
        cache = getattr(self, "_cols_cache", None)
        if cache is not None and cache[0] is vftables:
            return cache[1]

        groups = {}
        for other in vftables.values():
            tdea = getattr(other, "tdea", None)
            chdea = getattr(other, "chdea", None)
            groups.setdefault((tdea, chdea), []).append(other)
        self._cols_cache = (vftables, groups)
        return groups

    def get_col_offs_by_cols(self, cols):
        col_offs = []
        for col in cols:
            # the offset of the "offset" member is known from the layout spec
            # (see pyclassinformer.msvc_rtti), so prefer it over the database
            off = None
            try:
                off = col.offsets.get("offset")
            except AttributeError:
                off = None
            if off is None:
                off = self.get_moff_by_name(getattr(col, "struc", None), "offset")
            if off is None or off < 0:
                # RTTICompleteObjectLocator::offset follows signature in both
                # bitnesses (0, then 4)
                off = 4
            col_offs.append(ida_bytes.get_32bit(col.ea + off))
        return col_offs

    def get_col_offs(self, col, vftables):
        cols = self.get_cols_by_col(col, vftables)
        # get the offsets in COLs
        col_offs = self.get_col_offs_by_cols(cols)
        return col_offs

    def get_col_bases(self, col, vftables):
        # for checking if a class has multiple vftables or not
        col_offs = self.get_col_offs(col, vftables)

        bases = []
        paths = col.chd.bca.paths.get(col.offset, [])
        for path in paths:
            append = False
            for bcd in path:
                # for SI and MI but there is only a vftable
                if len(col_offs) < 2:
                    append = True
                # for MI and there are multiple vftables
                elif bcd.mdisp == col.offset:
                    append = True
                elif bcd.pdisp >= 0:
                    append = True
                # if append flag is enabled, append it and subsequent BCDs after it
                if append and bcd not in bases:
                    bases.append(bcd)
        return bases
