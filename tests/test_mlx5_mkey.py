# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

import unittest
import random
import errno

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, \
    Mlx5DVQPInitAttr, Mlx5QP
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError, \
    PyverbsError
from pyverbs.providers.mlx5.mlx5dv_mkey import Mlx5Mkey, Mlx5MrInterleaved, \
    Mlx5MkeyConfAttr
from tests.base import RCResources, RDMATestCase
import pyverbs.providers.mlx5.mlx5_enums as dve
from pyverbs.wr import SGE, SendWR, RecvWR
from pyverbs.qp import QPInitAttrEx, QPCap
import pyverbs.enums as e
import tests.utils as u


class Mlx5MkeyResources(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, dv_send_ops_flags=0):
        self.dv_send_ops_flags = dv_send_ops_flags
        if dv_send_ops_flags & dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE:
            self.max_inline_data = 512
        else:
            self.max_inline_data = 0
        super().__init__(dev_name, ib_port, gid_index)
        self.create_mkey()

    def create_context(self):
        mlx5dv_attr = Mlx5DVContextAttr()
        try:
            self.ctx = Mlx5Context(mlx5dv_attr, name=self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 context is not supported')

    def create_mkey(self):
        try:
            self.mkey = Mlx5Mkey(self.pd, dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT, 3)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create Mkey is not supported')
            raise ex

    def create_qp_cap(self):
        return QPCap(max_send_wr=self.num_msgs, max_recv_wr=self.num_msgs,
                     max_inline_data=self.max_inline_data)

    def create_qp_init_attr(self):
        comp_mask = e.IBV_QP_INIT_ATTR_PD | e.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
        send_ops_flags = e.IBV_QP_EX_WITH_SEND
        return QPInitAttrEx(cap=self.create_qp_cap(), pd=self.pd, scq=self.cq,
                            rcq=self.cq, qp_type=e.IBV_QPT_RC,
                            send_ops_flags=send_ops_flags, comp_mask=comp_mask)

    def create_qps(self):
        try:
            qp_init_attr = self.create_qp_init_attr()
            dv_create_flags = dve.MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE
            comp_mask = dve.MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS |\
                 dve.MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS
            attr = Mlx5DVQPInitAttr(comp_mask=comp_mask,
                                    create_flags=dv_create_flags,
                                    send_ops_flags=self.dv_send_ops_flags)
            qp = Mlx5QP(self.ctx, qp_init_attr, attr)
            self.qps.append(qp)
            self.qps_num.append(qp.qp_num)
            self.psns.append(random.getrandbits(24))
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create Mlx5DV QP is not supported')
            raise ex


class Mlx5MkeyTest(RDMATestCase):
    """
    Test various functionalities of the mlx5 mkeys.
    """
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

    def create_players(self, resource, **resource_arg):
        """
        Init Mkey test resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)

    def reg_mr_list(self, configure_mkey=False):
        """
        Register a list of SGEs using the player's mkeys.
        :param configure_mkey: If True, use the mkey configuration API.
        """
        for player in [self.server, self.client]:
            player.qp.wr_start()
            player.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
            sge_1 = SGE(player.mr.buf, 8, player.mr.lkey)
            sge_2 = SGE(player.mr.buf + 64, 8, player.mr.lkey)
            if configure_mkey:
                player.qp.wr_mkey_configure(player.mkey, 2, Mlx5MkeyConfAttr())
                player.qp.wr_set_mkey_access_flags(e.IBV_ACCESS_LOCAL_WRITE)
                player.qp.wr_set_mkey_layout_list([sge_1, sge_2])
            else:
                player.qp.wr_mr_list(player.mkey, e.IBV_ACCESS_LOCAL_WRITE,
                                     sge_list=[sge_1, sge_2])
            player.qp.wr_complete()
            u.poll_cq(player.cq)

    def reg_mr_interleaved(self, configure_mkey=False):
        """
        Register an interleaved memory layout using the player's mkeys.
        :param configure_mkey: Use the mkey configuration API.
        """
        for player in [self.server, self.client]:
            player.qp.wr_start()
            player.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
            mr_interleaved_1 = Mlx5MrInterleaved(addr=player.mr.buf, bytes_count=8,
                                                 bytes_skip=2, lkey=player.mr.lkey)
            mr_interleaved_2 = Mlx5MrInterleaved(addr=player.mr.buf + 64, bytes_count=8,
                                                 bytes_skip=2, lkey=player.mr.lkey)
            mr_interleaved_lst = [mr_interleaved_1, mr_interleaved_2]
            mkey_access = e.IBV_ACCESS_LOCAL_WRITE
            if configure_mkey:
                player.qp.wr_mkey_configure(player.mkey, 2, Mlx5MkeyConfAttr())
                player.qp.wr_set_mkey_access_flags(mkey_access)
                player.qp.wr_set_mkey_layout_interleaved(3, mr_interleaved_lst)
            else:
                player.qp.wr_mr_interleaved(player.mkey, e.IBV_ACCESS_LOCAL_WRITE,
                                            repeat_count=3, mr_interleaved_lst=mr_interleaved_lst)
            player.qp.wr_complete()
            u.poll_cq(player.cq)

    def build_traffic_elements(self, sge_size):
        """
        Build the server and client send/recv work requests.
        :param sge_size: The sge send size using the mkey.
        """
        opcode = e.IBV_WR_SEND
        server_sge = SGE(0, sge_size, self.server.mkey.lkey)
        self.server_recv_wr = RecvWR(sg=[server_sge], num_sge=1)
        client_sge = SGE(0, sge_size, self.client.mkey.lkey)
        self.client_send_wr = SendWR(opcode=opcode, num_sge=1, sg=[client_sge])

    def traffic(self, sge_size=16):
        """
        Perform RC traffic using the mkey.
        :param sge_size: The sge size using the mkey.
        """
        self.build_traffic_elements(sge_size)
        self.server.qp.post_recv(self.server_recv_wr)
        exp_buffer = (('c' * 8 + 's' * 56) *2)[:100]
        for _ in range(self.iters):
            self.server.mr.write('s' * 100, 100)
            self.client.mr.write('c' * 100, 100)
            self.client.qp.post_send(self.client_send_wr)
            u.poll_cq(self.client.cq)
            u.poll_cq(self.server.cq)
            self.server.qp.post_recv(self.server_recv_wr)
            act_buffer = self.server.mr.read(100, 0).decode()
            if act_buffer != exp_buffer:
                raise PyverbsError('Data validation failed: expected '
                                   f'{exp_buffer}, received {act_buffer}')

    def invalidate_mkeys(self):
        """
        Invalidate the players mkey.
        """
        for player in [self.server, self.client]:
            inv_send_wr = SendWR(opcode=e.IBV_WR_LOCAL_INV)
            inv_send_wr.imm_data = player.mkey.lkey
            player.qp.post_send(inv_send_wr)
            u.poll_cq(player.cq)

    def test_mkey_interleaved(self):
        """
        Create Mkeys, register an interleaved memory layout using this mkey and
        then perform traffic using it.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MR_INTERLEAVED)
        self.reg_mr_interleaved()
        self.traffic()
        self.invalidate_mkeys()

    def test_mkey_list(self):
        """
        Create Mkeys, register a memory layout using this mkey and then perform
        traffic using this mkey.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MR_LIST)
        self.reg_mr_list()
        self.traffic()
        self.invalidate_mkeys()

    def test_mkey_list_new_api(self):
        """
        Create Mkeys, configure it with memory layout using the new API and
        traffic using this mkey.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE)
        self.reg_mr_list(configure_mkey=True)
        self.traffic()
        self.invalidate_mkeys()

    def test_mkey_interleaved_new_api(self):
        """
        Create Mkeys, configure it with interleaved memory layout using the new
        API and then perform traffic using it.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE)
        self.reg_mr_interleaved(configure_mkey=True)
        self.traffic()
        self.invalidate_mkeys()

    def test_mkey_list_bad_flow(self):
        """
        Create Mkeys, register a memory layout using this mkey and then try to
        access the memory out of the mkey defined region. Expect this case to
        fail.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MR_LIST)
        self.reg_mr_list()
        with self.assertRaises(PyverbsRDMAError) as ex:
            self.traffic(sge_size=100)
