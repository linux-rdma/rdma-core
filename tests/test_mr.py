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
from pyverbs.mem_alloc import posix_memalign, free
from pyverbs.wr import SendWR
import pyverbs.device as d
from pyverbs.pd import PD
import pyverbs.enums as e
import tests.utils as u


class MRRes(RCResources):
    def __init__(self, dev_name, ib_port, gid_index,
                 mr_access=e.IBV_ACCESS_LOCAL_WRITE):
        """
        Initialize MR resources based on RC resources that include RC QP.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param mr_access: The MR access
        """
        self.mr_access = mr_access
        super().__init__(dev_name=dev_name, ib_port=ib_port, gid_index=gid_index)

    def create_mr(self):
        try:
            self.mr = MR(self.pd, self.msg_size, self.mr_access)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest(f'Reg MR with access ({self.mr_access}) is not supported')
            raise ex

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        qp_attr.qp_access_flags = qp_access
        return qp_attr

    def rereg_mr(self, flags, pd=None, addr=0, length=0, access=0):
        try:
            self.mr.rereg(flags, pd, addr, length, access)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest(f'Rereg MR is not supported ({str(ex)})')
            raise ex


class MRTest(RDMATestCase):
    """
    Test various functionalities of the MR class.
    """
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None
        self.server_qp_attr = None
        self.client_qp_attr = None
        self.traffic_args = None

    def create_players(self, resource, **resource_arg):
        """
        Init MR tests resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
        attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)
        self.sync_remote_attr()
        self.server_qp_attr, _ = self.server.qp.query(0x1ffffff)
        self.client_qp_attr, _ = self.client.qp.query(0x1ffffff)
        self.traffic_args = {'client': self.client, 'server': self.server,
                             'iters': self.iters, 'gid_idx': self.gid_index,
                             'port': self.ib_port}

    def sync_remote_attr(self):
        """
        Exchange the MR remote attributes between the server and the client.
        """
        self.server.rkey = self.client.mr.rkey
        self.server.remote_addr = self.client.mr.buf
        self.client.rkey = self.server.mr.rkey
        self.client.remote_addr = self.server.mr.buf

    def restate_qps(self):
        """
        Restate the resources QPs from ERR back to RTS state.
        """
        self.server.qp.modify(QPAttr(qp_state=e.IBV_QPS_RESET), e.IBV_QP_STATE)
        self.server.qp.to_rts(self.server_qp_attr)
        self.client.qp.modify(QPAttr(qp_state=e.IBV_QPS_RESET), e.IBV_QP_STATE)
        self.client.qp.to_rts(self.client_qp_attr)

    def test_mr_rereg_access(self):
        self.create_players(MRRes)
        access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        self.server.rereg_mr(flags=e.IBV_REREG_MR_CHANGE_ACCESS, access=access)
        self.client.rereg_mr(flags=e.IBV_REREG_MR_CHANGE_ACCESS, access=access)
        u.rdma_traffic(**self.traffic_args, send_op=e.IBV_WR_RDMA_WRITE)

    def test_mr_rereg_access_bad_flow(self):
        """
        Test that cover rereg MR's access with this flow:
        Run remote traffic on MR with compatible access, then rereg the MR
        without remote access and verify that traffic fails with the relevant
        error.
        """
        remote_access = e.IBV_ACCESS_LOCAL_WRITE |e.IBV_ACCESS_REMOTE_WRITE
        self.create_players(MRRes, mr_access=remote_access)
        u.rdma_traffic(**self.traffic_args, send_op=e.IBV_WR_RDMA_WRITE)
        access = e.IBV_ACCESS_LOCAL_WRITE
        self.server.rereg_mr(flags=e.IBV_REREG_MR_CHANGE_ACCESS, access=access)
        with self.assertRaisesRegex(PyverbsRDMAError, 'Remote access error'):
            u.rdma_traffic(**self.traffic_args, send_op=e.IBV_WR_RDMA_WRITE)

    def test_mr_rereg_pd(self):
        """
        Test that cover rereg MR's PD with this flow:
        Use MR with QP that was created with the same PD. Then rereg the MR's PD
        and use the MR with the same QP, expect the traffic to fail with "remote
        operation error". Restate the QP from ERR state, rereg the MR back
        to its previous PD and use it again with the QP, verify that it now
        succeeds.
        """
        self.create_players(MRRes)
        u.traffic(**self.traffic_args)
        server_new_pd = PD(self.server.ctx)
        self.server.rereg_mr(flags=e.IBV_REREG_MR_CHANGE_PD, pd=server_new_pd)
        with self.assertRaisesRegex(PyverbsRDMAError, 'Remote operation error'):
            u.traffic(**self.traffic_args)
        self.restate_qps()
        self.server.rereg_mr(flags=e.IBV_REREG_MR_CHANGE_PD, pd=self.server.pd)
        u.traffic(**self.traffic_args)
        # Rereg the MR again with the new PD to cover
        # destroying a PD with a re-registered MR.
        self.server.rereg_mr(flags=e.IBV_REREG_MR_CHANGE_PD, pd=server_new_pd)

    def test_mr_rereg_addr(self):
        self.create_players(MRRes)
        s_recv_wr = u.get_recv_wr(self.server)
        self.server.qp.post_recv(s_recv_wr)
        server_addr = posix_memalign(self.server.msg_size)
        self.server.rereg_mr(flags=e.IBV_REREG_MR_CHANGE_TRANSLATION,
                             addr=server_addr,
                             length=self.server.msg_size)
        with self.assertRaisesRegex(PyverbsRDMAError, 'Remote operation error'):
            # The server QP receive queue has WR with the old MR address,
            # therefore traffic should fail.
            u.traffic(**self.traffic_args)
        self.restate_qps()
        u.traffic(**self.traffic_args)
        free(server_addr)

    def test_reg_mr_bad_flags(self):
        """
        Verify that illegal flags combination fails as expected
        """
        with d.Context(name=self.dev_name) as ctx:
            with PD(ctx) as pd:
                with self.assertRaisesRegex(PyverbsRDMAError,
                                            'Failed to register a MR'):
                    MR(pd, u.get_mr_length(), e.IBV_ACCESS_REMOTE_WRITE)
                with self.assertRaisesRegex(PyverbsRDMAError,
                                            'Failed to register a MR'):
                    MR(pd, u.get_mr_length(), e.IBV_ACCESS_REMOTE_ATOMIC)


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

    def test_invalidate_mw_type1(self):
        self.test_mw_type1()
        self.invalidate_mw_type1()
        with self.assertRaisesRegex(PyverbsRDMAError, 'Remote access error'):
            u.rdma_traffic(self.client, self.server, self.iters, self.gid_index,
                           self.ib_port, send_op=e.IBV_WR_RDMA_WRITE)

    def test_mw_type2(self):
        self.create_players(MWRC, mw_type=e.IBV_MW_TYPE_2)
        self.bind_mw_type_2()
        u.rdma_traffic(self.client, self.server, self.iters, self.gid_index,
                       self.ib_port, send_op=e.IBV_WR_RDMA_WRITE)

    def test_mw_type2_invalidate_local(self):
        self.test_mw_type2()
        self.invalidate_mw_type2_local()
        with self.assertRaisesRegex(PyverbsRDMAError, 'Remote access error'):
            u.rdma_traffic(self.client, self.server, self.iters, self.gid_index,
                           self.ib_port, send_op=e.IBV_WR_RDMA_WRITE)

    def test_mw_type2_invalidate_remote(self):
        self.test_mw_type2()
        self.invalidate_mw_type2_remote()
        with self.assertRaisesRegex(PyverbsRDMAError, 'Remote access error'):
            u.rdma_traffic(self.client, self.server, self.iters, self.gid_index,
                           self.ib_port, send_op=e.IBV_WR_RDMA_WRITE)

    def test_mw_type2_invalidate_dealloc(self):
        self.test_mw_type2()
        # Dealloc the MW by closing the pyverbs objects.
        self.server.mw.close()
        self.client.mw.close()
        with self.assertRaisesRegex(PyverbsRDMAError, 'Remote access error'):
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
