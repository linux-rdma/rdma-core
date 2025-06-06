# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.providers.mlx5.mlx5dv import Wqe, WqeDataSeg, WqeCtrlSeg
from pyverbs.pyverbs_error import PyverbsError
from pyverbs.providers.mlx5.mlx5_enums import mlx5dv_qp_create_send_ops_flags, MLX5_WQE_CTRL_CQ_UPDATE, MLX5_OPCODE_SEND
from tests.mlx5_base import Mlx5RDMATestCase, Mlx5RcResources
from pyverbs.qp import QPCap
from pyverbs.wr import SGE
from pyverbs.libibverbs_enums import ibv_qp_create_send_ops_flags, ibv_send_flags, ibv_wc_opcode
import tests.utils as u


class Mlx5RawWqeResources(Mlx5RcResources):
    def create_send_ops_flags(self):
        self.dv_send_ops_flags = mlx5dv_qp_create_send_ops_flags.MLX5DV_QP_EX_WITH_RAW_WQE
        self.send_ops_flags = ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND

    def create_qp_cap(self):
        """
        Create QPCap such that work queue elements will wrap around the send
        work queue, this happens due to the iteration count being higher
        than the max_send_wr.
        :return:
        """
        return QPCap(max_send_wr=1, max_recv_wr=4, max_recv_sge=2, max_send_sge=2)


class RawWqeTest(Mlx5RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

    def prepare_send_elements(self):
        mr = self.client.mr
        sge_count = 2
        unit_size = mr.length / 2
        data_segs = [WqeDataSeg(unit_size, mr.lkey, mr.buf + i * unit_size) for
                     i in range(sge_count)]
        ctrl_seg = WqeCtrlSeg()
        ctrl_seg.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE
        segment_num = 1 + len(data_segs)
        ctrl_seg.opmod_idx_opcode = MLX5_OPCODE_SEND
        ctrl_seg.qpn_ds = segment_num | int(self.client.qp.qp_num) << 8
        self.raw_send_wqe = Wqe([ctrl_seg] + data_segs)
        self.regular_send_sge = SGE(mr.buf, mr.length, mr.lkey)

    def mixed_traffic(self):
        s_recv_wr = u.get_recv_wr(self.server)
        u.post_recv(self.server, s_recv_wr)
        self.prepare_send_elements()

        for i in range(self.iters):
            self.client.qp.wr_start()
            if i % 2:
                self.client.mr.write('c' * self.client.mr.length, self.client.mr.length)
                self.client.qp.wr_flags = ibv_send_flags.IBV_SEND_SIGNALED
                self.client.qp.wr_send()
                self.client.qp.wr_set_sge(self.regular_send_sge)
            else:
                self.client.mr.write('s' * self.client.mr.length, self.client.mr.length)
                self.client.qp.wr_raw_wqe(self.raw_send_wqe)
            self.client.qp.wr_complete()
            u.poll_cq_ex(self.client.cq)
            u.poll_cq_ex(self.server.cq)
            u.post_recv(self.server, s_recv_wr)
            expected_opcode = ibv_wc_opcode.IBV_WC_SEND if i % 2 else ibv_wc_opcode.IBV_WC_DRIVER2

            if self.client.cq.read_opcode() != expected_opcode:
                raise PyverbsError('Opcode validation failed: expected '
                                   f'{expected_opcode}, received {self.client.cq.read_opcode()}')

            act_buffer = self.server.mr.read(self.server.mr.length, 0)
            u.validate(act_buffer, i % 2, self.server.mr.length)

    def test_mixed_raw_wqe_traffic(self):
        """
        Runs traffic with a mix of SEND opcode regular WQEs and SEND opcode RAW
        WQEs.
        """
        self.create_players(Mlx5RawWqeResources)
        self.mixed_traffic()
