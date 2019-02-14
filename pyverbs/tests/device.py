# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.  See COPYING file
import unittest
import resource
import random

from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
import pyverbs.tests.utils as u
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

    @staticmethod
    def verify_port_attr(attr):
        assert 'Invalid' not in d.phys_state_to_str(attr.state)
        assert 'Invalid' not in d.translate_mtu(attr.max_mtu)
        assert 'Invalid' not in d.translate_mtu(attr.active_mtu)
        assert 'Invalid' not in d.width_to_str(attr.active_width)
        assert 'Invalid' not in d.speed_to_str(attr.active_speed)
        assert 'Invalid' not in d.translate_link_layer(attr.link_layer)
        assert attr.max_msg_sz > 0x1000

    def test_query_port(self):
        """
        Test ibv_query_port
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                num_ports = ctx.query_device().phys_port_cnt
                for p in range(num_ports):
                    port_attr = ctx.query_port(p + 1)
                    self.verify_port_attr(port_attr)

    def test_query_port_bad_flow(self):
        """ Verify that querying non-existing ports fails as expected """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                num_ports = ctx.query_device().phys_port_cnt
                try:
                    port = num_ports + random.randint(1, 10)
                    ctx.query_port(port)
                except PyverbsRDMAError as e:
                    assert 'Failed to query port' in e.args[0]
                    assert 'Invalid argument' in e.args[0]
                else:
                    raise PyverbsRDMAError('Successfully queried non-existing port {p}'.\
                                           format(p=port))

class dm_test(unittest.TestCase):
    """
    Test various functionalities of the DM class.
    """
    def test_create_dm(self):
        """
        test ibv_alloc_dm()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device_ex()
                if attr.max_dm_size == 0:
                    return
                dm_len = random.randrange(u.MIN_DM_SIZE, attr.max_dm_size,
                                          u.DM_ALIGNMENT)
                dm_attrs = u.get_dm_attrs(dm_len)
                with d.DM(ctx, dm_attrs):
                    pass

    def test_destroy_dm(self):
        """
        test ibv_free_dm()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device_ex()
                if attr.max_dm_size == 0:
                    return
                dm_len = random.randrange(u.MIN_DM_SIZE, attr.max_dm_size,
                                          u.DM_ALIGNMENT)
                dm_attrs = u.get_dm_attrs(dm_len)
                dm = d.DM(ctx, dm_attrs)
                dm.close()

    def test_create_dm_bad_flow(self):
        """
        test ibv_alloc_dm() with an illegal size and comp mask
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device_ex()
                if attr.max_dm_size == 0:
                    return
                dm_len = attr.max_dm_size + 1
                dm_attrs = u.get_dm_attrs(dm_len)
                try:
                    dm = d.DM(ctx, dm_attrs)
                except PyverbsRDMAError as e:
                    assert 'Failed to allocate device memory of size' in e.args[0]
                    assert 'Max available size' in e.args[0]
                else:
                    raise PyverbsError('Created a DM with size larger than max reported')
                dm_attrs.comp_mask = random.randint(1, 100)
                try:
                    dm = d.DM(ctx, dm_attrs)
                except PyverbsRDMAError as e:
                    assert 'Failed to allocate device memory of size' in e.args[0]
                else:
                    raise PyverbsError('Created a DM with illegal comp mask {c}'.\
                                       format(c=dm_attrs.comp_mask))

    def test_destroy_dm_bad_flow(self):
        """
        test calling ibv_free_dm() twice
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device_ex()
                if attr.max_dm_size == 0:
                    return
                dm_len = random.randrange(u.MIN_DM_SIZE, attr.max_dm_size, u.DM_ALIGNMENT)
                dm_attrs = u.get_dm_attrs(dm_len)
                dm = d.DM(ctx, dm_attrs)
                dm.close()
                dm.close()

    def test_dm_write(self):
        """
        Test writing to the device memory
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device_ex()
                if attr.max_dm_size == 0:
                    return
                dm_len = random.randrange(u.MIN_DM_SIZE, attr.max_dm_size, u.DM_ALIGNMENT)
                dm_attrs = u.get_dm_attrs(dm_len)
                with d.DM(ctx, dm_attrs) as dm:
                    data_length = random.randrange(4, dm_len, u.DM_ALIGNMENT)
                    data_offset = random.randrange(0, dm_len - data_length, u.DM_ALIGNMENT)
                    data = u.get_data(data_length)
                    dm.copy_to_dm(data_offset, data.encode(), data_length)

    def test_dm_write_bad_flow(self):
        """
        Test writing to the device memory with bad offset and length
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device_ex()
                if attr.max_dm_size == 0:
                    return
                dm_len = random.randrange(u.MIN_DM_SIZE, attr.max_dm_size, u.DM_ALIGNMENT)
                dm_attrs = u.get_dm_attrs(dm_len)
                with d.DM(ctx, dm_attrs) as dm:
                    data_length = random.randrange(4, dm_len, u.DM_ALIGNMENT)
                    data_offset = random.randrange(0, dm_len - data_length, u.DM_ALIGNMENT)
                    data_offset += 1 # offset needs to be a multiple of 4
                    data = u.get_data(data_length)
                    try:
                        dm.copy_to_dm(data_offset, data.encode(), data_length)
                    except PyverbsRDMAError as e:
                            assert 'Failed to copy to dm' in e.args[0]
                    else:
                        raise PyverbsError('Wrote to device memory with a bad offset')

    def test_dm_read(self):
        """
        Test reading from the device memory
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device_ex()
                if attr.max_dm_size == 0:
                    return
                dm_len = random.randrange(u.MIN_DM_SIZE, attr.max_dm_size, u.DM_ALIGNMENT)
                dm_attrs = u.get_dm_attrs(dm_len)
                with d.DM(ctx, dm_attrs) as dm:
                    data_length = random.randrange(4, dm_len, u.DM_ALIGNMENT)
                    data_offset = random.randrange(0, dm_len - data_length, u.DM_ALIGNMENT)
                    data = u.get_data(data_length)
                    dm.copy_to_dm(data_offset, data.encode(), data_length)
                    read_str = dm.copy_from_dm(data_offset, data_length)
                    assert read_str.decode() == data
