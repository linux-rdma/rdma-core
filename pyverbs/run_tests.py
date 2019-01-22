# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.  See COPYING file
import unittest,os,os.path,fnmatch
import tests


def test_all():
    # FIXME: This implementation is for older Python versions, will
    # be replaced with discover()
    return test_suite

module = __import__("tests")
fns = [os.path.splitext(I)[0] for I in fnmatch.filter(os.listdir(module.__path__[0]),"*.py")]
fns.remove("__init__")
for I in fns:
    __import__("tests." + I)
test_suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromNames(fns,module))

if __name__ == '__main__':
    unittest.main(defaultTest="test_all")


