"""Mock of idc (only the structure API and jumpto)."""
import image
import structstore

BADADDR = image.BADADDR

JUMPED = []


def jumpto(ea, opnum=-1, uFlags=0):
    JUMPED.append(ea)
    return True


# --------------------------------------------------------------------------
# structure API (still available in IDA 9.x as a compatibility wrapper)
# --------------------------------------------------------------------------
def get_struc_id(name):
    return structstore.get_tid(name)


def add_struc(index=BADADDR, name="", is_union=False):
    return structstore.new_struct(name)


def del_struc(sid):
    entry = structstore.get_by_tid(sid)
    if entry is None:
        return False
    for name, value in list(structstore.STRUCTS.items()):
        if value is entry:
            structstore.delete_struct(name)
            return True
    return False


def add_struc_member(sid, name, offset=BADADDR, flag=0, type=0, nbytes=0,
                     reftype=None, vtoff=None, **kwargs):
    entry = structstore.get_by_tid(sid)
    if entry is None:
        return 1
    struct_name = [n for n, v in structstore.STRUCTS.items() if v is entry][0]
    if offset == BADADDR:
        offset = None
    # a zero sized member (a string) does not advance the structure
    structstore.add_member(struct_name, name, nbytes, offset)
    return 0


def get_struc_size(sid):
    entry = structstore.get_by_tid(sid)
    if entry is None:
        return 0
    struct_name = [n for n, v in structstore.STRUCTS.items() if v is entry][0]
    return structstore.struct_size(struct_name)


def get_member_qty(sid):
    entry = structstore.get_by_tid(sid)
    return len(entry["members"]) if entry else 0


def get_member_offset(sid, member_name):
    entry = structstore.get_by_tid(sid)
    if entry is None:
        return BADADDR
    struct_name = [n for n, v in structstore.STRUCTS.items() if v is entry][0]
    member = structstore.get_member(struct_name, member_name)
    return member["offset"] if member else BADADDR


def get_struc_name(sid):
    entry = structstore.get_by_tid(sid)
    if entry is None:
        return ""
    return [n for n, v in structstore.STRUCTS.items() if v is entry][0]


def set_member_type(sid, offset, flag, type, nbytes, reftype=None):
    return 0


def get_func_name(ea):
    import ida_funcs
    return ida_funcs.get_func_name(ea)
