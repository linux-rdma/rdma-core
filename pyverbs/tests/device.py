# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.  See COPYING file
import unittest
import pyverbs.device as d

class device_test(unittest.TestCase):
    """
    Test various functionalities of the Device class.
    """
    def test_dev_list(self):
        """
        Verify that it's possible to get IB devices list.
        """
        lst = d.get_device_list()

    def test_open_dev(self):
        """
        Test ibv_open_device()
        """
        lst = d.get_device_list()
        for dev in lst:
            ctx = d.Context(name=dev.name.decode())

    def test_query_device(self):
        """
        Test ibv_query_device()
        """
        lst = d.get_device_list()
        for dev in lst:
            ctx = d.Context(name=dev.name.decode())
            ctx.query_device()

    def test_query_gid(self):
        """
        Test ibv_query_gid()
        """
        lst = d.get_device_list()
        for dev in lst:
            ctx = d.Context(name=dev.name.decode())
            ctx.query_gid(port_num=1, index=0)

