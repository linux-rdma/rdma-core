# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018 Mellanox Technologies, Inc. All rights reserved. See COPYING file
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.
"""
Test module for pyverbs' device module.
"""
from multiprocessing import Process, Queue
import unittest
import resource
import random
import errno
import os

from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from tests.base import PyverbsAPITestCase
from pyverbs.device import Context, DM
import tests.utils as u
import pyverbs.device as d
import pyverbs.enums as e

PAGE_SIZE = resource.getpagesize()


class DeviceTest(PyverbsAPITestCase):
    """
    Test various functionalities of the Device class.
    """

    def get_device_list(self):
        lst = d.get_device_list()
        if len(lst) == 0:
            raise unittest.SkipTest('No IB device found')
        dev_name = self.config['dev']
        if dev_name:
            for dev in lst:
                if dev.name.decode() == dev_name:
                    lst = [dev]
                    break
            if len(lst) == 0:
                raise PyverbsRDMAError(f'No IB device with name {dev_name} found')
        return lst

    def test_dev_list(self):
        """
        Verify that it's possible to get IB devices list.
        """
        self.get_device_list()

    def test_open_dev(self):
        """
        Test ibv_open_device()
        """
        for dev in self.get_device_list():
            d.Context(name=dev.name.decode())

    def test_query_device(self):
        """
        Test ibv_query_device()
        """
        for dev in self.get_device_list():
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device()
                self.verify_device_attr(attr, dev)

    def test_query_pkey(self):
        """
        Test ibv_query_pkey()
        """
        for dev in self.get_device_list():
            with d.Context(name=dev.name.decode()) as ctx:
                if dev.node_type == e.IBV_NODE_CA:
                    ctx.query_pkey(port_num=self.ib_port, index=0)

    def test_query_gid(self):
        """
        Test ibv_query_gid()
        """
        for dev in self.get_device_list():
            with d.Context(name=dev.name.decode()) as ctx:
                gid_tbl_len = ctx.query_port(self.ib_port).gid_tbl_len
                if gid_tbl_len > 0:
                    ctx.query_gid(port_num=self.ib_port, index=0)

    def test_query_gid_table(self):
        """
        Test ibv_query_gid_table()
        """
        devs = self.get_device_list()
        with d.Context(name=devs[0].name.decode()) as ctx:
            device_attr = ctx.query_device()
            max_entries = 0
            for port_num in range(1, device_attr.phys_port_cnt + 1):
                port_attr = ctx.query_port(port_num)
                max_entries += port_attr.gid_tbl_len
            try:
                if max_entries > 0:
                    ctx.query_gid_table(max_entries)
            except PyverbsRDMAError as ex:
                if ex.error_code in [-errno.EOPNOTSUPP, -errno.EPROTONOSUPPORT]:
                    raise unittest.SkipTest('ibv_query_gid_table is not'\
                                            ' supported on this device')
                raise ex

    def test_query_gid_table_bad_flow(self):
        """
        Test ibv_query_gid_table() with too small a buffer
        """
        try:
            self.ctx.query_gid_table(0)
        except PyverbsRDMAError as ex:
            if ex.error_code in [-errno.EOPNOTSUPP, -errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('ibv_query_gid_table is not'
                                        ' supported on this device')
            self.assertEqual(ex.error_code, -errno.EINVAL,
                             f'Got -{os.strerror(-ex.error_code)} but '
                             f'Expected -{os.strerror(errno.EINVAL)} ')
        else:
            raise PyverbsRDMAError('Successfully queried '
                                   'gid_table with an insufficient buffer')

    def test_query_gid_ex(self):
        """
        Test ibv_query_gid_ex()
        """
        devs = self.get_device_list()
        with d.Context(name=devs[0].name.decode()) as ctx:
            try:
                gid_tbl_len = ctx.query_port(self.ib_port).gid_tbl_len
                if gid_tbl_len > 0:
                    ctx.query_gid_ex(port_num=self.ib_port, gid_index=0)
            except PyverbsRDMAError as ex:
                if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                    raise unittest.SkipTest('ibv_query_gid_ex is not'\
                                            ' supported on this device')
                raise ex

    def test_query_gid_ex_bad_flow(self):
        """
        Test ibv_query_gid_ex() with an empty index
        """
        try:
            port_attr = self.ctx.query_port(self.ib_port)
            max_entries = 0
            for port_num in range(1, self.attr.phys_port_cnt + 1):
                attr = self.ctx.query_port(port_num)
                max_entries += attr.gid_tbl_len
            if max_entries > 0:
                gid_indices = {gid_entry.gid_index for gid_entry in
                               self.ctx.query_gid_table(max_entries) if gid_entry.port_num == self.ib_port}
            else:
                gid_indices = {}

            possible_indices = set(range(port_attr.gid_tbl_len)) if port_attr.gid_tbl_len > 1 else set()
            try:
                no_gid_index = possible_indices.difference(gid_indices).pop()
            except KeyError:
                # all indices are populated by GIDs
                raise unittest.SkipTest('All gid indices populated,'
                                        ' cannot check bad flow')

            self.ctx.query_gid_ex(port_num=self.ib_port, gid_index=no_gid_index)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('ibv_query_gid_ex is not'
                                        ' supported on this device')
            self.assertEqual(ex.error_code, errno.ENODATA,
                             f'Got {os.strerror(ex.error_code)} but '
                             f'Expected {os.strerror(errno.ENODATA)}')
        else:
            raise PyverbsRDMAError('Successfully queried '
                                   f'non-existent gid index {no_gid_index}')

    @staticmethod
    def verify_device_attr(attr, device):
        """
        Helper method that verifies correctness of some members of DeviceAttr
        object.
        :param attr: A DeviceAttr object
        :param device: A Device object
        :return: None
        """
        if device.node_type != e.IBV_NODE_UNSPECIFIED and device.node_type != e.IBV_NODE_UNKNOWN:
            assert attr.node_guid != 0
            assert attr.sys_image_guid != 0
        assert attr.max_mr_size > PAGE_SIZE
        assert attr.page_size_cap >= PAGE_SIZE
        assert attr.vendor_id != 0
        assert attr.max_qp > 0
        assert attr.max_qp_wr > 0
        assert attr.max_sge > 0
        assert attr.max_sge_rd >= 0
        assert attr.max_cq > 0
        assert attr.max_cqe > 0
        assert attr.max_mr > 0
        assert attr.max_pd > 0
        if device.node_type == e.IBV_NODE_CA:
            assert attr.max_pkeys > 0

    def test_query_device_ex(self):
        """
        Test ibv_query_device_ex()
        """
        for dev in self.get_device_list():
            with d.Context(name=dev.name.decode()) as ctx:
                attr_ex = ctx.query_device_ex()
                self.verify_device_attr(attr_ex.orig_attr, dev)

    def test_phys_port_cnt_ex(self):
        """
        Test phys_port_cnt_ex
        """
        for dev in self.get_device_list():
            with d.Context(name=dev.name.decode()) as ctx:
                attr_ex = ctx.query_device_ex()
                phys_port_cnt = attr_ex.orig_attr.phys_port_cnt
                phys_port_cnt_ex = attr_ex.phys_port_cnt_ex
                if phys_port_cnt_ex > 255:
                    self.assertEqual(phys_port_cnt, 255,
                                     f'phys_port_cnt should be 255 if ' +
                                     f'phys_port_cnt_ex is bigger than 255')
                else:
                    self.assertEqual(phys_port_cnt, phys_port_cnt_ex,
                                     f'phys_port_cnt_ex and phys_port_cnt ' +
                                     f'should be equal if number of ports is ' +
                                     f'less than 256')

    @staticmethod
    def verify_port_attr(attr):
        """
        Helper method that verifies correctness of some members of PortAttr
        object.
        :param attr: A PortAttr object
        :return: None
        """
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
        for dev in self.get_device_list():
            with d.Context(name=dev.name.decode()) as ctx:
                port_attr = ctx.query_port(self.ib_port)
                self.verify_port_attr(port_attr)

    def test_query_port_bad_flow(self):
        """
        Verify that querying non-existing ports fails as expected
        """
        for dev in self.get_device_list():
            with d.Context(name=dev.name.decode()) as ctx:
                num_ports = ctx.query_device().phys_port_cnt
                try:
                    port = num_ports + random.randint(1, 10)
                    ctx.query_port(port)
                except PyverbsRDMAError as e:
                    assert 'Failed to query port' in e.args[0]
                    assert 'Invalid argument' in e.args[0]
                else:
                    raise PyverbsRDMAError(
                        'Successfully queried non-existing port {p}'. \
                        format(p=port))


class DMTest(PyverbsAPITestCase):
    """
    Test various functionalities of the DM class.
    """
    def setUp(self):
        super().setUp()
        if self.attr_ex.max_dm_size == 0:
            raise unittest.SkipTest('Device memory is not supported')

    def test_create_dm(self):
        """
        test ibv_alloc_dm()
        """
        dm_len = random.randrange(u.MIN_DM_SIZE, self.attr_ex.max_dm_size/2,
                                  u.DM_ALIGNMENT)
        dm_attrs = u.get_dm_attrs(dm_len)
        with d.DM(self.ctx, dm_attrs):
            pass

    def test_destroy_dm(self):
        """
        test ibv_free_dm()
        """
        dm_len = random.randrange(u.MIN_DM_SIZE, self.attr_ex.max_dm_size/2,
                                  u.DM_ALIGNMENT)
        dm_attrs = u.get_dm_attrs(dm_len)
        dm = d.DM(self.ctx, dm_attrs)
        dm.close()

    def test_create_dm_bad_flow(self):
        """
        test ibv_alloc_dm() with an illegal size and comp mask
        """
        dm_len = self.attr_ex.max_dm_size + 1
        dm_attrs = u.get_dm_attrs(dm_len)
        try:
            d.DM(self.ctx, dm_attrs)
        except PyverbsRDMAError as e:
            assert 'Failed to allocate device memory of size' in \
                   e.args[0]
            assert 'Max available size' in e.args[0]
        else:
            raise PyverbsError(
                'Created a DM with size larger than max reported')
        dm_attrs.comp_mask = random.randint(1, 100)
        try:
            d.DM(self.ctx, dm_attrs)
        except PyverbsRDMAError as e:
            assert 'Failed to allocate device memory of size' in \
                   e.args[0]
        else:
            raise PyverbsError(
                'Created a DM with illegal comp mask {c}'. \
                format(c=dm_attrs.comp_mask))

    def test_destroy_dm_bad_flow(self):
        """
        Test calling ibv_free_dm() twice
        """
        dm_len = random.randrange(u.MIN_DM_SIZE, self.attr_ex.max_dm_size/2,
                                  u.DM_ALIGNMENT)
        dm_attrs = u.get_dm_attrs(dm_len)
        dm = d.DM(self.ctx, dm_attrs)
        dm.close()
        dm.close()

    def test_dm_write(self):
        """
        Test writing to the device memory
        """
        dm_len = random.randrange(u.MIN_DM_SIZE, self.attr_ex.max_dm_size/2,
                                  u.DM_ALIGNMENT)
        dm_attrs = u.get_dm_attrs(dm_len)
        with d.DM(self.ctx, dm_attrs) as dm:
            data_length = random.randrange(4, dm_len, u.DM_ALIGNMENT)
            data_offset = random.randrange(0, dm_len - data_length,
                                           u.DM_ALIGNMENT)
            data = 'a' * data_length
            dm.copy_to_dm(data_offset, data.encode(), data_length)

    def test_dm_write_bad_flow(self):
        """
        Test writing to the device memory with bad offset and length
        """
        dm_len = random.randrange(u.MIN_DM_SIZE, self.attr_ex.max_dm_size/2,
                                  u.DM_ALIGNMENT)
        dm_attrs = u.get_dm_attrs(dm_len)
        with d.DM(self.ctx, dm_attrs) as dm:
            data_length = random.randrange(4, dm_len, u.DM_ALIGNMENT)
            data_offset = random.randrange(0, dm_len - data_length,
                                           u.DM_ALIGNMENT)
            data_offset += 1  # offset needs to be a multiple of 4
            data = 'a' * data_length
            try:
                dm.copy_to_dm(data_offset, data.encode(), data_length)
            except PyverbsRDMAError as e:
                assert 'Failed to copy to dm' in e.args[0]
            else:
                raise PyverbsError(
                    'Wrote to device memory with a bad offset')

    def test_dm_read(self):
        """
        Test reading from the device memory
        """
        dm_len = random.randrange(u.MIN_DM_SIZE, self.attr_ex.max_dm_size/2,
                                  u.DM_ALIGNMENT)
        dm_attrs = u.get_dm_attrs(dm_len)
        with d.DM(self.ctx, dm_attrs) as dm:
            data_length = random.randrange(4, dm_len, u.DM_ALIGNMENT)
            data_offset = random.randrange(0, dm_len - data_length,
                                           u.DM_ALIGNMENT)
            data = 'a' * data_length
            dm.copy_to_dm(data_offset, data.encode(), data_length)
            read_str = dm.copy_from_dm(data_offset, data_length)
            assert read_str.decode() == data

    def alloc_dm(self, res_queue, size):
        """
        Alloc device memory. Used by multiple processes that allocate DMs in
        parallel.
        :param res_queue: Result Queue to return the result to the parent
                            process.
        :param size: The DM allocation size.
        :return: None
        """
        try:
            d.DM(self.ctx, d.AllocDmAttr(length=size))
        except PyverbsError as err:
            res_queue.put(err.error_code)
        res_queue.put(0)

    def test_multi_process_alloc_dm(self):
        """
        Several processes try to allocate device memory simultaneously.
        """
        res_queue = Queue()
        processes = []
        processes_num = 5
        # Dividing the max dm size by 2 since we're not
        # guaranteed to have the max size free for us.
        total_size = self.attr_ex.max_dm_size / 2 / processes_num
        for i in range(processes_num):
            processes.append(Process(target=self.alloc_dm,
                                     args=(res_queue, total_size)))
        for i in range(processes_num):
            processes[i].start()
        for i in range(processes_num):
            processes[i].join()
            rc = res_queue.get()
            self.assertEqual(rc, 0, f'Parallel device memory allocation failed with errno: {rc}')


class SharedDMTest(PyverbsAPITestCase):
    """
    Tests shared device memory by importing DMs
    """
    def setUp(self):
        super().setUp()
        if self.attr_ex.max_dm_size == 0:
            raise unittest.SkipTest('Device memory is not supported')
        self.dm_size = int(self.attr_ex.max_dm_size / 2)

    def test_import_dm(self):
        """
        Creates a DM and imports it from a different (duplicated) Context.
        Then writes some data to the original DM, reads it from the imported DM
        and verifies that the read data is as expected.
        """
        with d.DM(self.ctx, d.AllocDmAttr(length=self.dm_size)) as dm:
            cmd_fd_dup = os.dup(self.ctx.cmd_fd)
            try:
                imported_ctx = Context(cmd_fd=cmd_fd_dup)
                imported_dm = DM(imported_ctx, handle=dm.handle)
            except PyverbsRDMAError as ex:
                if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                    raise unittest.SkipTest('Some object imports are not supported')
                raise ex
            original_data = b'\xab' * self.dm_size
            dm.copy_to_dm(0, original_data, self.dm_size)
            read_data = imported_dm.copy_from_dm(0, self.dm_size)
            self.assertEqual(original_data, read_data)
            imported_dm.unimport()
