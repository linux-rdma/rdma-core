# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for pyverbs' mr module.
"""
import unittest
import random
import errno

from tests.base import PyverbsAPITestCase, RCResources, RDMATestCase
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.mr import MR, MW, DMMR, MWBindInfo, MWBind
from pyverbs.qp import QPCap, QPInitAttr, QPAttr, QP
from pyverbs.wr import SendWR
import pyverbs.device as d
from pyverbs.pd import PD
import pyverbs.enums as e
import tests.utils as u

MAX_IO_LEN = 1048576


class MRTest(PyverbsAPITestCase):
    """
    Test various functionalities of the MR class.
    """
    def test_reg_mr(self):
        """
        Test ibv_reg_mr()
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, u.get_mr_length(), f) as mr:
                        pass

    def test_dereg_mr(self):
        """
        Test ibv_dereg_mr()
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, u.get_mr_length(), f) as mr:
                        mr.close()

    def test_dereg_mr_twice(self):
        """
        Verify that explicit call to MR's close() doesn't fail
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, u.get_mr_length(), f) as mr:
                        # Pyverbs supports multiple destruction of objects,
                        # we are not expecting an exception here.
                        mr.close()
                        mr.close()

    def test_reg_mr_bad_flags(self):
        """
        Verify that illegal flags combination fails as expected
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                for i in range(5):
                    flags = random.sample([e.IBV_ACCESS_REMOTE_WRITE,
                                           e.IBV_ACCESS_REMOTE_ATOMIC],
                                          random.randint(1, 2))
                    mr_flags = 0
                    for i in flags:
                        mr_flags += i.value
                    try:
                        MR(pd, u.get_mr_length(), mr_flags)
                    except PyverbsRDMAError as err:
                        assert 'Failed to register a MR' in err.args[0]
                    else:
                        raise PyverbsRDMAError('Registered a MR with illegal falgs')

    def test_write(self):
        """
        Test writing to MR's buffer
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                for i in range(10):
                    mr_len = u.get_mr_length()
                    flags = u.get_access_flags(ctx)
                    for f in flags:
                        with MR(pd, mr_len, f) as mr:
                            write_len = min(random.randint(1, MAX_IO_LEN),
                                            mr_len)
                            mr.write('a' * write_len, write_len)

    def test_read(self):
        """
        Test reading from MR's buffer
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                for i in range(10):
                    mr_len = u.get_mr_length()
                    flags = u.get_access_flags(ctx)
                    for f in flags:
                        with MR(pd, mr_len, f) as mr:
                            write_len = min(random.randint(1, MAX_IO_LEN),
                                            mr_len)
                            write_str = 'a' * write_len
                            mr.write(write_str, write_len)
                            read_len = random.randint(1, write_len)
                            offset = random.randint(0, write_len-read_len)
                            read_str = mr.read(read_len, offset).decode()
                            assert read_str in write_str

    def test_lkey(self):
        """
        Test reading lkey property
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                length = u.get_mr_length()
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, length, f) as mr:
                        mr.lkey

    def test_rkey(self):
        """
        Test reading rkey property
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                length = u.get_mr_length()
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, length, f) as mr:
                        mr.rkey

    def test_buffer(self):
        """
        Test reading buf property
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                length = u.get_mr_length()
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, length, f) as mr:
                        mr.buf


class MWRC(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, mw_type):
        """
        Initialize Memory Window resources based on RC resources that include RC
        QP.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param mw_type: The MW type to use
        """
        super().__init__(dev_name=dev_name, ib_port=ib_port,
                                   gid_index=gid_index)
        self.mw_type = mw_type
        access = e.IBV_ACCESS_REMOTE_WRITE | e.IBV_ACCESS_LOCAL_WRITE
        self.mw_bind_info = MWBindInfo(self.mr, self.mr.buf, self.msg_size,
                                       access)
        self.mw_bind = MWBind(self.mw_bind_info, e.IBV_SEND_SIGNALED)
        try:
            self.mw = MW(self.pd, self.mw_type)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create MW is not supported')
            raise ex

    def create_mr(self):
        access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_MW_BIND
        try:
            self.mr = MR(self.pd, self.msg_size, access)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Reg MR with MW access is not supported')
            raise ex

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        qp_attr.qp_access_flags = qp_access
        return qp_attr


class MWTest(RDMATestCase):
    """
    Test various functionalities of the MW class.
    """
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

    def create_players(self, resource, **resource_arg):
        """
        Init memory window tests resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
        attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)

    def tearDown(self):
        if self.server:
            self.server.mw.close()
        if self.client:
            self.client.mw.close()
        return super().tearDown()

    def bind_mw_type_1(self):
        self.server.qp.bind_mw(self.server.mw, self.server.mw_bind)
        self.client.qp.bind_mw(self.client.mw, self.client.mw_bind)
        # Poll the bind MW action completion.
        u.poll_cq(self.server.cq)
        u.poll_cq(self.client.cq)
        self.server.rkey = self.client.mw.rkey
        self.server.remote_addr = self.client.mr.buf
        self.client.rkey = self.server.mw.rkey
        self.client.remote_addr = self.server.mr.buf

    def bind_mw_type_2(self):
        client_send_wr = SendWR(opcode=e.IBV_WR_BIND_MW)
        client_send_wr.set_bind_wr(self.client.mw, self.client.mw_bind_info)
        server_send_wr = SendWR(opcode=e.IBV_WR_BIND_MW)
        server_send_wr.set_bind_wr(self.server.mw, self.server.mw_bind_info)
        self.server.qp.post_send(server_send_wr)
        self.client.qp.post_send(client_send_wr)
        # Poll the bind MW WR.
        u.poll_cq(self.server.cq)
        u.poll_cq(self.client.cq)
        self.server.rkey = client_send_wr.rkey
        self.server.remote_addr = self.client.mr.buf
        self.client.rkey = server_send_wr.rkey
        self.client.remote_addr = self.server.mr.buf

    def invalidate_mw_type1(self):
        """
        Invalidate the MWs by rebind this MW with zero length.
        :return: None
        """
        for player in [self.server, self.client]:
            mw_bind_info = MWBindInfo(player.mr, player.mr.buf, 0, 0)
            mw_bind = MWBind(mw_bind_info, e.IBV_SEND_SIGNALED)
            player.qp.bind_mw(player.mw, mw_bind)
            # Poll the bound MW action request completion.
            u.poll_cq(player.cq)

    def invalidate_mw_type2_local(self):
        """
        Invalidate the MWs by post invalidation send WR from the local QP.
        :return: None
        """
        inv_send_wr = SendWR(opcode=e.IBV_WR_LOCAL_INV)
        inv_send_wr.imm_data = self.server.rkey
        self.client.qp.post_send(inv_send_wr)
        inv_send_wr = SendWR(opcode=e.IBV_WR_LOCAL_INV)
        inv_send_wr.imm_data = self.client.rkey
        self.server.qp.post_send(inv_send_wr)
        # Poll the invalidate MW WR.
        u.poll_cq(self.server.cq)
        u.poll_cq(self.client.cq)

    def invalidate_mw_type2_remote(self):
        """
        Invalidate the MWs by sending invalidation send WR from the remote QP.
        :return: None
        """
        server_recv_wr = u.get_recv_wr(self.server)
        client_recv_wr = u.get_recv_wr(self.client)
        self.server.qp.post_recv(server_recv_wr)
        self.client.qp.post_recv(client_recv_wr)
        inv_send_wr = SendWR(opcode=e.IBV_WR_SEND_WITH_INV)
        inv_send_wr.imm_data = self.client.rkey
        self.client.qp.post_send(inv_send_wr)
        inv_send_wr = SendWR(opcode=e.IBV_WR_SEND_WITH_INV)
        inv_send_wr.imm_data = self.server.rkey
        self.server.qp.post_send(inv_send_wr)
        # Poll the invalidate MW send WR.
        u.poll_cq(self.server.cq)
        u.poll_cq(self.client.cq)
        # Poll the invalidate MW recv WR.
        u.poll_cq(self.server.cq)
        u.poll_cq(self.client.cq)

    def test_mw_type1(self):
        self.create_players(MWRC, mw_type=e.IBV_MW_TYPE_1)
        self.bind_mw_type_1()
        u.rdma_traffic(self.client, self.server, self.iters, self.gid_index,
                       self.ib_port, send_op=e.IBV_WR_RDMA_WRITE)

    def test_mw_type2(self):
        self.create_players(MWRC, mw_type=e.IBV_MW_TYPE_2)
        self.bind_mw_type_2()
        u.rdma_traffic(self.client, self.server, self.iters, self.gid_index,
                       self.ib_port, send_op=e.IBV_WR_RDMA_WRITE)

    def test_reg_mw_wrong_type(self):
        """
        Verify that trying to create a MW of a wrong type fails
        """
        with d.Context(name=self.dev_name) as ctx:
            with PD(ctx) as pd:
                try:
                    mw_type = 3
                    MW(pd, mw_type)
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Create memory window of type {} is not supported'.format(mw_type))
                else:
                    raise PyverbsError('Created a MW with type {t}'.\
                                       format(t=mw_type))


class DMMRTest(PyverbsAPITestCase):
    """
    Test various functionalities of the DMMR class.
    """
    def test_create_dm_mr(self):
        """
        Test ibv_reg_dm_mr
        """
        for ctx, attr, attr_ex in self.devices:
            if attr_ex.max_dm_size == 0:
                raise unittest.SkipTest('Device memory is not supported')
            with PD(ctx) as pd:
                for i in range(10):
                    dm_len = random.randrange(u.MIN_DM_SIZE, attr_ex.max_dm_size/2,
                                              u.DM_ALIGNMENT)
                    dm_attrs = u.get_dm_attrs(dm_len)
                    with d.DM(ctx, dm_attrs) as dm:
                        dm_mr_len = random.randint(1, dm_len)
                        dm_mr_offset = random.randint(0, (dm_len - dm_mr_len))
                        DMMR(pd, dm_mr_len, e.IBV_ACCESS_ZERO_BASED, dm=dm,
                             offset=dm_mr_offset)

    def test_destroy_dm_mr(self):
        """
        Test freeing of dm_mr
        """
        for ctx, attr, attr_ex in self.devices:
            if attr_ex.max_dm_size == 0:
                raise unittest.SkipTest('Device memory is not supported')
            with PD(ctx) as pd:
                for i in range(10):
                    dm_len = random.randrange(u.MIN_DM_SIZE, attr_ex.max_dm_size/2,
                                              u.DM_ALIGNMENT)
                    dm_attrs = u.get_dm_attrs(dm_len)
                    with d.DM(ctx, dm_attrs) as dm:
                        dm_mr_len = random.randint(1, dm_len)
                        dm_mr_offset = random.randint(0, (dm_len - dm_mr_len))
                        dm_mr = DMMR(pd, dm_mr_len, e.IBV_ACCESS_ZERO_BASED,
                                     dm=dm, offset=dm_mr_offset)
                        dm_mr.close()
