# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc . All rights reserved. See COPYING file

import unittest
import os


def load_tests(loader, standard_tests, pattern):
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.dirname(__file__))
    return suite
#   To run only some test cases / parametrized tests:
#   1. Add RDMATestCase to the imports:
#    from tests.base import RDMATestCase
#   2. Replace the current TestSuite with a customized one and add tests to it
#      (parameters are optional)
#    suite = unittest.TestSuite()
#    suite.addTest(RDMATestCase.parametrize(YourTestCase, dev_name='rocep0s8f0', ...))
