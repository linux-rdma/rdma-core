# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.  See COPYING file
import unittest
import resource

import pyverbs.device as d


PAGE_SIZE = resource.getpagesize()


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
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device()
                self.verify_device_attr(attr)

    def test_query_gid(self):
        """
        Test ibv_query_gid()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                ctx.query_gid(port_num=1, index=0)

    @staticmethod
    def verify_device_attr(attr):
        assert attr.node_guid != 0
        assert attr.sys_image_guid != 0
        assert attr.max_mr_size > PAGE_SIZE
        assert attr.page_size_cap > PAGE_SIZE
        assert attr.vendor_id != 0
        assert attr.vendor_part_id != 0
        assert attr.max_qp > 0
        assert attr.max_qp_wr > 0
        assert attr.max_sge > 0
        assert attr.max_sge_rd > 0
        assert attr.max_cq > 0
        assert attr.max_cqe > 0
        assert attr.max_mr > 0
        assert attr.max_pd > 0
        assert attr.max_pkeys > 0

    def test_query_device_ex(self):
        """
        Test ibv_query_device_ex()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attr_ex = ctx.query_device_ex()
                self.verify_device_attr(attr_ex.orig_attr)
