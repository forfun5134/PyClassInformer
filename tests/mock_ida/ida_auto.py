"""Mock of ida_auto."""

WAIT_CALLS = 0


def auto_wait():
    global WAIT_CALLS
    WAIT_CALLS += 1
    return True


def auto_mark_range(start, end, queuetype):
    return True
