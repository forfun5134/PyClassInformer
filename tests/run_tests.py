#!/usr/bin/env python3
"""Run the offline PyClassInformer test suite.

    python3 tests/run_tests.py          # quiet
    python3 tests/run_tests.py -v       # verbose

IDA is not required: ``tests/mock_ida`` provides a small model of the
IDAPython API (the one of IDA 9.5) and ``tests/fakepe.py`` builds synthetic
MSVC RTTI layouts for x86 and x64.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import harness  # noqa  (sets up sys.path)


def main():
    verbosity = 2 if ("-v" in sys.argv or "--verbose" in sys.argv) else 1
    suite = unittest.TestLoader().discover(harness.HERE, pattern="test_*.py",
                                           top_level_dir=harness.HERE)
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    print("")
    print("IDA version used by the mock: {}".format(
        ".".join(str(x) for x in __import__("pyclassinformer.ida_compat",
                                            fromlist=["IDA_VERSION"]).IDA_VERSION)))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
