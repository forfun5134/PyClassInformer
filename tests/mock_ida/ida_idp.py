"""Mock of ida_idp."""

PLFM_386 = 0
PLFM_ARM = 9
PLFM_MIPS = 6
PLFM_PPC = 4


class _ph(object):
    id = PLFM_386


ph = _ph()
