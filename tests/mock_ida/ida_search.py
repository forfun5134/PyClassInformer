"""Mock of ida_search."""
import image

SEARCH_UP = 0x00
SEARCH_DOWN = 0x01
SEARCH_NEXT = 0x02
SEARCH_CASE = 0x04
SEARCH_UNICODE = 0x08
SEARCH_IDENT = 0x10

BADADDR = image.BADADDR


def find_data(ea, flags):
    """Return the next defined data item after ea (SEARCH_DOWN|SEARCH_NEXT)."""
    for item_ea in sorted(image.IMAGE.items):
        if item_ea <= ea:
            continue
        kind = image.IMAGE.items[item_ea][0]
        if kind in (image.KIND_DATA, image.KIND_STRUCT):
            return item_ea
    return BADADDR
