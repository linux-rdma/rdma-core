#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.  See COPYING file

import unittest
import os
from importlib.machinery import SourceFileLoader


module_path = os.path.join(os.path.dirname(__file__), '__init__.py')
tests = SourceFileLoader('tests', module_path).load_module()
unittest.main(module=tests)
