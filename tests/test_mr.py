# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
# Copyright (c) 2020 Intel Corporation. All rights reserved. See COPYING file
"""
Test module for pyverbs' mr module.
"""
import unittest
import random
import errno

from tests.base import PyverbsAPITestCase, RCResources, RDMATestCase
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.mr import MR, MW, DMMR, DmaBufMR, MWBindInfo, MWBind
from pyverbs.mem_alloc import posix_memalign, free
from pyverbs.dmabuf import DmaBuf
from pyverbs.qp import QPAttr
from pyverbs.wr import SendWR
import pyverbs.device as d
from pyverbs.pd import PD
import pyverbs.enums as e
import tests.utils as u

MAX_IO_LEN = 1048576
DM_INVALID_ALIGNMENT = 3


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


class DeviceMemoryAPITest(PyverbsAPITestCase):
    """
    Test various API usages of the DMMR class.
    """
    def setUp(self):
        super().setUp()
        if self.attr_ex.max_dm_size == 0:
            raise unittest.SkipTest('Device memory is not supported')

    def test_create_dm_mr(self):
        max_dm_size = self.attr_ex.max_dm_size
        dm_access = e.IBV_ACCESS_ZERO_BASED | e.IBV_ACCESS_LOCAL_WRITE
        for dm_size in [4, max_dm_size/4, max_dm_size/2]:
            dm_size = dm_size - (dm_size % u.DM_ALIGNMENT)
            for dmmr_factor_size in [0.1, 0.5, 1]:
                dmmr_size = dm_size * dmmr_factor_size
                dmmr_size = dmmr_size - (dmmr_size % u.DM_ALIGNMENT)
                with d.DM(self.ctx, d.AllocDmAttr(length=dm_size)) as dm:
                    DMMR(PD(self.ctx), dmmr_size, dm_access, dm, 0)

    def test_dm_bad_access(self):
        """
        Test multiple types of bad access to the Device Memory. Device memory
        access requests a 4B alignment. The test tries to access the DM
        with bad alignment or outside of the allocated memory.
        """
        dm_size = 100
        with d.DM(self.ctx, d.AllocDmAttr(length=dm_size)) as dm:
            dm_access = e.IBV_ACCESS_ZERO_BASED | e.IBV_ACCESS_LOCAL_WRITE
            dmmr = DMMR(PD(self.ctx), dm_size, dm_access, dm, 0)
            access_cases = [(DM_INVALID_ALIGNMENT, 4), # Valid length with unaligned offset
                            (4, DM_INVALID_ALIGNMENT), # Valid offset with unaligned length
                            (dm_size + 4, 4), # Offset out of allocated memory
                            (0, dm_size + 4)] # Length out of allocated memory
            for case in access_cases:
                offset, length = case
                with self.assertRaisesRegex(PyverbsRDMAError, 'Failed to copy from dm'):
                    dmmr.read(offset=offset, length=length)
                with self.assertRaisesRegex(PyverbsRDMAError, 'Failed to copy to dm'):
                    dmmr.write(data='s'*length, offset=offset, length=length)

    def test_dm_bad_registration(self):
        """
        Test bad Device Memory registration when trying to register bigger DMMR
        than the allocated DM.
        """
        dm_size = 100
        with d.DM(self.ctx, d.AllocDmAttr(length=dm_size)) as dm:
            dm_access = e.IBV_ACCESS_ZERO_BASED | e.IBV_ACCESS_LOCAL_WRITE
            with self.assertRaisesRegex(PyverbsRDMAError, 'Failed to register a device MR'):
                DMMR(PD(self.ctx), dm_size + 4, dm_access, dm, 0)


def check_dmabuf_support(gpu=0):
    """
    Check if dma-buf allocation is supported by the system.
    Skip the test on failure.
    """
    device_num = 128 + gpu
    try:
        DmaBuf(1, gpu=gpu)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.ENOENT:
            raise unittest.SkipTest(f'Device /dev/dri/renderD{device_num} is not present')
        if ex.error_code == errno.EACCES:
            raise unittest.SkipTest(f'Lack of permission to access /dev/dri/renderD{device_num}')
        if ex.error_code == errno.EOPNOTSUPP:
            raise unittest.SkipTest(f'Allocating dmabuf is not supported by /dev/dri/renderD{device_num}')


def check_dmabuf_mr_support(pd, gpu=0):
    """
    Check if dma-buf MR registration is supported by the driver.
    Skip the test on failure
    """
    try:
        DmaBufMR(pd, 1, 0, gpu=gpu)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EOPNOTSUPP:
            raise unittest.SkipTest('Reg dma-buf MR is not supported by the RDMA driver')


class DmaBufMRTest(PyverbsAPITestCase):
    """
    Test various functionalities of the DmaBufMR class.
    """
    def setUp(self):
        super().setUp()
        self.gpu = self.config['gpu']
        self.gtt = self.config['gtt']

    def test_dmabuf_reg_mr(self):
        """
        Test ibv_reg_dmabuf_mr()
        """
        check_dmabuf_support(self.gpu)
        with PD(self.ctx) as pd:
            check_dmabuf_mr_support(pd, self.gpu)
            flags = u.get_dmabuf_access_flags(self.ctx)
            for f in flags:
                len = u.get_mr_length()
                for off in [0, len//2]:
                    with DmaBufMR(pd, len, f, offset=off, unit=self.gpu,
                                  gtt=self.gtt) as mr:
                        pass

    def test_dmabuf_dereg_mr(self):
        """
        Test ibv_dereg_mr() with DmaBufMR
        """
        check_dmabuf_support(self.gpu)
        with PD(self.ctx) as pd:
            check_dmabuf_mr_support(pd, self.gpu)
            flags = u.get_dmabuf_access_flags(self.ctx)
            for f in flags:
                len = u.get_mr_length()
                for off in [0, len//2]:
                    with DmaBufMR(pd, len, f, offset=off, unit=self.gpu,
                                  gtt=self.gtt) as mr:
                        mr.close()

    def test_dmabuf_dereg_mr_twice(self):
        """
        Verify that explicit call to DmaBufMR's close() doesn't fail
        """
        check_dmabuf_support(self.gpu)
        with PD(self.ctx) as pd:
            check_dmabuf_mr_support(pd, self.gpu)
            flags = u.get_dmabuf_access_flags(self.ctx)
            for f in flags:
                len = u.get_mr_length()
                for off in [0, len//2]:
                    with DmaBufMR(pd, len, f, offset=off, unit=self.gpu,
                                  gtt=self.gtt) as mr:
                        # Pyverbs supports multiple destruction of objects,
                        # we are not expecting an exception here.
                        mr.close()
                        mr.close()

    def test_dmabuf_reg_mr_bad_flags(self):
        """
        Verify that illegal flags combination fails as expected
        """
        check_dmabuf_support(self.gpu)
        with PD(self.ctx) as pd:
            check_dmabuf_mr_support(pd, self.gpu)
            for i in range(5):
                flags = random.sample([e.IBV_ACCESS_REMOTE_WRITE,
                                       e.IBV_ACCESS_REMOTE_ATOMIC],
                                      random.randint(1, 2))
                mr_flags = 0
                for i in flags:
                    mr_flags += i.value
                try:
                    DmaBufMR(pd, u.get_mr_length(), mr_flags,
                             unit=self.gpu, gtt=self.gtt)
                except PyverbsRDMAError as err:
                    assert 'Failed to register a dma-buf MR' in err.args[0]
                else:
                    raise PyverbsRDMAError('Registered a dma-buf MR with illegal falgs')

    def test_dmabuf_write(self):
        """
        Test writing to DmaBufMR's buffer
        """
        check_dmabuf_support(self.gpu)
        with PD(self.ctx) as pd:
            check_dmabuf_mr_support(pd, self.gpu)
            for i in range(10):
                mr_len = u.get_mr_length()
                flags = u.get_dmabuf_access_flags(self.ctx)
                for f in flags:
                    for mr_off in [0, mr_len//2]:
                        with DmaBufMR(pd, mr_len, f, offset=mr_off,
                                      unit=self.gpu, gtt=self.gtt) as mr:
                            write_len = min(random.randint(1, MAX_IO_LEN),
                                            mr_len)
                            mr.write('a' * write_len, write_len)

    def test_dmabuf_read(self):
        """
        Test reading from DmaBufMR's buffer
        """
        check_dmabuf_support(self.gpu)
        with PD(self.ctx) as pd:
            check_dmabuf_mr_support(pd, self.gpu)
            for i in range(10):
                mr_len = u.get_mr_length()
                flags = u.get_dmabuf_access_flags(self.ctx)
                for f in flags:
                    for mr_off in [0, mr_len//2]:
                        with DmaBufMR(pd, mr_len, f, offset=mr_off,
                                      unit=self.gpu, gtt=self.gtt) as mr:
                            write_len = min(random.randint(1, MAX_IO_LEN),
                                            mr_len)
                            write_str = 'a' * write_len
                            mr.write(write_str, write_len)
                            read_len = random.randint(1, write_len)
                            offset = random.randint(0, write_len-read_len)
                            read_str = mr.read(read_len, offset).decode()
                            assert read_str in write_str

    def test_dmabuf_lkey(self):
        """
        Test reading lkey property
        """
        check_dmabuf_support(self.gpu)
        with PD(self.ctx) as pd:
            check_dmabuf_mr_support(pd, self.gpu)
            length = u.get_mr_length()
            flags = u.get_dmabuf_access_flags(self.ctx)
            for f in flags:
                with DmaBufMR(pd, length, f, unit=self.gpu,
                              gtt=self.gtt) as mr:
                    mr.lkey

    def test_dmabuf_rkey(self):
        """
        Test reading rkey property
        """
        check_dmabuf_support(self.gpu)
        with PD(self.ctx) as pd:
            check_dmabuf_mr_support(pd, self.gpu)
            length = u.get_mr_length()
            flags = u.get_dmabuf_access_flags(self.ctx)
            for f in flags:
                with DmaBufMR(pd, length, f, unit=self.gpu,
                              gtt=self.gtt) as mr:
                    mr.rkey


class DmaBufRC(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, gpu, gtt):
        """
        Initialize an DmaBufRC object.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param gpu: GPU unit to allocate dmabuf from
        :gtt: Allocate dmabuf from GTT instead og VRAM
        """
        self.gpu = gpu
        self.gtt = gtt
        super(DmaBufRC, self).__init__(dev_name=dev_name, ib_port=ib_port,
                                       gid_index=gid_index)

    def create_mr(self):
        check_dmabuf_support(self.gpu)
        check_dmabuf_mr_support(self.pd, self.gpu)
        access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        mr = DmaBufMR(self.pd, self.msg_size, access, gpu=self.gpu,
                      gtt=self.gtt)
        self.mr = mr

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        qp_attr.qp_access_flags = qp_access
        return qp_attr


class DmaBufTestCase(RDMATestCase):
    def setUp(self):
        super(DmaBufTestCase, self).setUp()
        self.iters = 100
        self.gpu = self.config['gpu']
        self.gtt = self.config['gtt']

    def create_players(self, resource, **resource_arg):
        """
        Init dma-buf tests resources.
        :param resource: The RDMA resources to use. A class of type
                         BaseResources.
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        :return: The (client, server) resources.
        """
        client = resource(**self.dev_info, **resource_arg)
        server = resource(**self.dev_info, **resource_arg)
        client.pre_run(server.psns, server.qps_num)
        server.pre_run(client.psns, client.qps_num)
        return client, server

    def test_dmabuf_rc_traffic(self):
        """
        Test send/recv using dma-buf MR over RC
        """
        client, server = self.create_players(DmaBufRC, gpu=self.gpu,
                                             gtt=self.gtt)
        u.traffic(client, server, self.iters, self.gid_index, self.ib_port)

    def test_dmabuf_rdma_traffic(self):
        """
        Test rdma write using dma-buf MR
        """
        client, server = self.create_players(DmaBufRC, gpu=self.gpu,
                                             gtt=self.gtt)
        server.rkey = client.mr.rkey
        server.remote_addr = client.mr.offset
        client.rkey = server.mr.rkey
        client.remote_addr = server.mr.offset
        u.rdma_traffic(client, server, self.iters, self.gid_index, self.ib_port,
                       send_op=e.IBV_WR_RDMA_WRITE)


class DeviceMemoryRes(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, remote_access=False):
        """
        Initialize DM resources based on RC resources that include RC
        QP.
        :param dev_name: Device name to be used.
        :param ib_port: IB port of the device to use.
        :param gid_index: Which GID index to use.
        :param remote_access: If True, enable remote access.
        """
        self.remote_access = remote_access
        super().__init__(dev_name=dev_name, ib_port=ib_port,
                         gid_index=gid_index)

    def create_mr(self):
        try:
            self.dm = d.DM(self.ctx, d.AllocDmAttr(length=self.msg_size))
            access = e.IBV_ACCESS_ZERO_BASED | e.IBV_ACCESS_LOCAL_WRITE
            if self.remote_access:
                access |= e.IBV_ACCESS_REMOTE_WRITE
            self.mr = DMMR(self.pd, self.msg_size, access, self.dm, 0)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest(f'Reg DMMR with access={access} is not supported')
            raise ex

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_attr.qp_access_flags = e.IBV_ACCESS_LOCAL_WRITE
        if self.remote_access:
            qp_attr.qp_access_flags |= e.IBV_ACCESS_REMOTE_WRITE
        return qp_attr


class DeviceMemoryTest(RDMATestCase):
    """
    Test various functionalities of the DM class.
    """
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None
        self.traffic_args = None
        ctx = d.Context(name=self.dev_name)
        if ctx.query_device_ex().max_dm_size == 0:
            raise unittest.SkipTest('Device memory is not supported')
        # Device memory can not work in scatter to cqe mode in MLX5 devices,
        # therefore disable it and restore the default value at the end of the
        # test.
        self.set_env_variable('MLX5_SCATTER_TO_CQE', '0')

    def create_players(self, resource, **resource_arg):
        """
        Init Device Memory tests resources.
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

    def test_dm_traffic(self):
        self.create_players(DeviceMemoryRes)
        u.traffic(**self.traffic_args)

    def test_dm_remote_traffic(self):
        self.create_players(DeviceMemoryRes, remote_access=True)
        u.rdma_traffic(**self.traffic_args, send_op=e.IBV_WR_RDMA_WRITE)
