"""Mock of ida_ida."""
import image

f_PE = 0x18
f_ELF = 0x12
f_MACHO = 0x1A

BADADDR = image.BADADDR


def inf_get_filetype():
    return f_PE


def inf_get_max_ea():
    if not image.IMAGE.segments:
        return 0
    return max(s.end_ea for s in image.IMAGE.segments)


def inf_get_min_ea():
    if not image.IMAGE.segments:
        return 0
    return min(s.start_ea for s in image.IMAGE.segments)


def inf_is_64bit():
    return image.IMAGE.bitness == 2
