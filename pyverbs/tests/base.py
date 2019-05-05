# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc . All rights reserved. See COPYING file

import unittest

import pyverbs.device as d

class PyverbsTestCase(unittest.TestCase):
    def setUp(self):
        """
        Opens the devices and queries them
        """
        lst = d.get_device_list()
        self.devices = []
        for dev in lst:
            c = d.Context(name=dev.name.decode())
            attr = c.query_device()
            attr_ex = c.query_device_ex()
            self.devices.append((c, attr, attr_ex))

    def tearDown(self):
        for tup in self.devices:
            tup[0].close()
