"""A tiny structure/type store shared by the idc and ida_typeinf mocks."""

BADADDR = 0xFFFFFFFFFFFFFFFF

#: name -> {"tid": int, "members": [ {name, offset (bytes), size (bytes), type} ]}
STRUCTS = {}
_BY_TID = {}
_NEXT_TID = [0x80000000]


def _new_tid():
    tid = _NEXT_TID[0]
    _NEXT_TID[0] += 1
    return tid


def new_struct(name):
    delete_struct(name)
    tid = _new_tid()
    STRUCTS[name] = {"tid": tid, "members": [], "cmt": ""}
    _BY_TID[tid] = name
    return tid


def delete_struct(name):
    entry = STRUCTS.pop(name, None)
    if entry is not None:
        _BY_TID.pop(entry["tid"], None)
        return True
    return False


def get_by_name(name):
    return STRUCTS.get(name)


def get_by_tid(tid):
    name = _BY_TID.get(tid)
    if name is None:
        return None
    return STRUCTS.get(name)


def get_tid(name):
    entry = STRUCTS.get(name)
    return entry["tid"] if entry else BADADDR


def add_member(name, member_name, size, offset=None, mtype="int"):
    entry = STRUCTS.get(name)
    if entry is None:
        return -1
    if offset is None:
        offset = struct_size(name)
    entry["members"].append({"name": member_name, "offset": offset, "size": size, "type": mtype})
    return offset


def struct_size(name):
    entry = STRUCTS.get(name)
    if entry is None:
        return 0
    end = 0
    for member in entry["members"]:
        end = max(end, member["offset"] + member["size"])
    return end


def get_member(name, member_name):
    entry = STRUCTS.get(name)
    if entry is None:
        return None
    for member in entry["members"]:
        if member["name"] == member_name:
            return member
    return None


def reset():
    STRUCTS.clear()
    _BY_TID.clear()
    _NEXT_TID[0] = 0x80000000
