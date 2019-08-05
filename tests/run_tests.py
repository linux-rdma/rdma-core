#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.  See COPYING file

import unittest
import os
from importlib.machinery import SourceFileLoader


def test_all():
    module_path = os.path.dirname(__file__) + '/__init__.py'
    module = SourceFileLoader('tests', module_path).load_module()
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(module)
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest="test_all")
