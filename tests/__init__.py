# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc . All rights reserved. See COPYING file

import importlib
import os

# Load every test as a module in the system so that unittest's loader can find it
def _load_tests():
    res = []
    for fn in sorted(os.listdir(os.path.dirname(__file__))):
        if fn.endswith(".py") and fn.startswith("test_"):
            m  = importlib.import_module("." + os.path.basename(fn)[:-3], __name__)
            res.append(m)
    return res
__test_modules__ = _load_tests()

# unittest -v prints names like 'tests.test_foo', but it always starts
# searching from the tests module, adding the name 'tests.test' lets the user
# specify the same test name from logging on the command line to trivially run
# a single test.
tests = importlib.import_module(".", __name__)

def load_tests(loader, standard_tests, pattern):
    """Implement the loadTestsFromModule protocol"""
    for mod in __test_modules__:
        standard_tests.addTests(loader.loadTestsFromModule(mod, pattern))
    return standard_tests
