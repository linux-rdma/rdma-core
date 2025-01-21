# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2024 NVIDIA Corporation . All rights reserved. See COPYING file

import unittest
import random
import errno

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, \
    Mlx5DVQPInitAttr, Mlx5QP, Mlx5DVCQInitAttr, Mlx5CQ
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError, \
    PyverbsError
from pyverbs.cq import CQ, CQEX, PollCqAttr, CqInitAttrEx
from pyverbs.qp import QPInitAttrEx, QPCap, QPAttr
import pyverbs.providers.mlx5.mlx5_enums as dve
from pyverbs.wr import SGE, SendWR, RecvWR
from pyverbs.mr import MR
import pyverbs.enums as e

from tests.base import RCResources, RDMATestCase
from tests.mlx5_base import Mlx5RcResources
import tests.utils as u


def create_ooo_dv_qp(res, max_recv_wr=1000, qp_type=e.IBV_QPT_RC):
    dv_ctx = res.ctx.query_mlx5_device()
    if not dv_ctx.comp_mask & dve.MLX5DV_CONTEXT_MASK_OOO_RECV_WRS:
        raise unittest.SkipTest('DV QP OOO feature is not supported')
    send_ops_flags = e.IBV_QP_EX_WITH_SEND | e.IBV_QP_EX_WITH_SEND_WITH_IMM | \
                     e.IBV_QP_EX_WITH_RDMA_WRITE | e.IBV_QP_EX_WITH_RDMA_READ |\
                     e.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM
    qp_cap = QPCap(max_recv_wr=max_recv_wr, max_send_wr=max_recv_wr)
    comp_mask = e.IBV_QP_INIT_ATTR_PD | e.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
    qp_init_attr =  QPInitAttrEx(cap=qp_cap, pd=res.pd, scq=res.cq,
                                 rcq=res.cq, qp_type=qp_type,
                                 send_ops_flags=send_ops_flags,
                                 comp_mask=comp_mask)
    dv_comp_mask = dve.MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS
    attr = Mlx5DVQPInitAttr(comp_mask=dv_comp_mask,
                            create_flags=res.dvqp_create_flags)
    try:
        qp = Mlx5QP(res.ctx, qp_init_attr, attr)
        res.qps.append(qp)
        res.qps_num.append(qp.qp_num)
        res.psns.append(random.getrandbits(24))
    except PyverbsRDMAError as ex:
        raise ex


class Mlx5OOORcRes(Mlx5RcResources):
    def __init__(self, dev_name, ib_port, gid_index, msg_size=1024, dvqp_create_flags=0, **kwargs):
        """
        Initialize mlx5 DV QP resources based on RCResources.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param msg_size: The resource msg size
        :param dvqp_create_flags: DV QP create flags
        :param kwargs: General arguments
        """
        self.qp_access_flags = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE | \
                               e.IBV_ACCESS_REMOTE_READ
        self.dvqp_create_flags = dvqp_create_flags
        super().__init__(dev_name, ib_port, gid_index, msg_size=msg_size, **kwargs)


    def create_qp_attr(self):
        attr = super().create_qp_attr()
        attr.qp_access_flags = self.qp_access_flags
        return attr

    def create_qps(self):
        for _ in range(self.qp_count):
            create_ooo_dv_qp(self)

    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size, self.qp_access_flags)

    def create_cq(self):
        wc_flags = e.IBV_WC_STANDARD_FLAGS
        cia = CqInitAttrEx(cqe=2000, wc_flags=wc_flags)
        dvcq_init_attr = Mlx5DVCQInitAttr()
        dvcq_init_attr.comp_mask |= dve.MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE
        dvcq_init_attr.cqe_size = 64
        dvcq_init_attr.comp_mask |= dve.MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE
        try:
            self.cq = Mlx5CQ(self.ctx, cia, dvcq_init_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create Mlx5DV CQ is not supported')
            raise ex


class DvOOOQPTest(RDMATestCase):

    def test_ooo_qp_bad_flow(self):
        """
        DDP - OOO Recv WRs bad flow test
        1. Create QP with max recv WRs possible and validate it with querying the QP
        2. Try to create QP with more then max recv wr supported
        3. Try to create QP with unsupported QP type
        """
        self.create_players(Mlx5OOORcRes, dvqp_create_flags=dve.MLX5DV_QP_CREATE_OOO_DP)
        dv_ctx = self.server.ctx.query_mlx5_device()
        max_rc_rwrs = dv_ctx.ooo_recv_wrs_caps['max_rc']
        create_ooo_dv_qp(self.server, max_recv_wr=max_rc_rwrs)
        attr, init_attr = self.server.qps[-1].query(0x1ffffff)
        self.assertEqual(max_rc_rwrs, init_attr.cap.max_recv_wr)
        # Try to create QP with more then max recv wr supported
        with self.assertRaises(PyverbsRDMAError) as ex:
            create_ooo_dv_qp(self.server, max_rc_rwrs + 1)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)
        # Try to create QP with unsupported QP type
        with self.assertRaises(PyverbsRDMAError) as ex:
            create_ooo_dv_qp(self.server, qp_type=e.IBV_QPT_RAW_PACKET)
        self.assertEqual(ex.exception.error_code, errno.EOPNOTSUPP)

    def test_ooo_qp_send_traffic(self):
        """
        DV QP OOO traffic opcode SEND
        """
        self.create_players(Mlx5OOORcRes, dvqp_create_flags=dve.MLX5DV_QP_CREATE_OOO_DP)
        u.traffic_poll_at_once(self, msg_size=int(self.server.msg_size / self.iters),
                               iterations=self.iters)

    def test_ooo_qp_rdma_write_imm_traffic(self):
        """
        DV QP OOO traffic opcode RDMA_WRITE_WITH_IMM
        """
        self.create_players(Mlx5OOORcRes, dvqp_create_flags=dve.MLX5DV_QP_CREATE_OOO_DP)
        u.traffic_poll_at_once(self, msg_size=int(self.server.msg_size / self.iters),
                               iterations=self.iters, opcode=e.IBV_WR_RDMA_WRITE_WITH_IMM)
