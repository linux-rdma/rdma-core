#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.  See COPYING file

from args_parser import parser
import importlib.util
import unittest
import sys
import os


module_path = os.path.join(os.path.dirname(__file__), '__init__.py')
spec = importlib.util.spec_from_file_location('tests', module_path)
tests = importlib.util.module_from_spec(spec)
sys.modules['tests'] = tests
spec.loader.exec_module(tests)
parser.parse_args()
unittest.main(module=tests)
