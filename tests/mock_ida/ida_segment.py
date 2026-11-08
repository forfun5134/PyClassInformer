"""Mock of ida_segment."""
import image


def get_segm_by_name(name):
    return image.IMAGE.get_segment_by_name(name)


def get_segm_qty():
    return len(image.IMAGE.segments)


def getnseg(n):
    if 0 <= n < len(image.IMAGE.segments):
        return image.IMAGE.segments[n]
    return None


def getseg(ea):
    return image.IMAGE.get_segment(ea)


def get_segm_class(seg):
    return seg.sclass if seg is not None else None
