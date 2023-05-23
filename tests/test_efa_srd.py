# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020-2023 Amazon.com, Inc. or its affiliates. All rights reserved.

import unittest
import errno

from pyverbs.pyverbs_error import PyverbsRDMAError
import pyverbs.enums as e

from tests.efa_base import EfaRDMATestCase
from tests.efa_base import SRDResources
import tests.utils as u



class QPSRDTestCase(EfaRDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 100
        self.server = None
        self.client = None

    def create_players(self, send_ops_flags=0, qp_count=8):
        try:
            self.client = SRDResources(self.dev_name, self.ib_port, self.gid_index, send_ops_flags, qp_count)
            self.server = SRDResources(self.dev_name, self.ib_port, self.gid_index, send_ops_flags, qp_count)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create SRD Resources is not supported')
            raise ex
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)

    def full_sq_bad_flow(self):
        """
        Check post_send while qp's sq is full.
        - Find qp's sq length
        - Fill the qp with work requests until overflow
        """
        qp_idx = 0
        send_op = e.IBV_WR_SEND
        ah = u.get_global_ah(self.client, self.gid_index, self.ib_port)
        qp_attr, _ = self.client.qps[qp_idx].query(e.IBV_QP_CAP)
        max_send_wr = qp_attr.cap.max_send_wr
        with self.assertRaises(PyverbsRDMAError) as ex:
            for _ in range (max_send_wr + 1):
                _, c_sg = u.get_send_elements(self.client, False)
                u.send(self.client, c_sg, send_op, new_send=True, qp_idx=qp_idx, ah=ah)
        self.assertEqual(ex.exception.error_code, errno.ENOMEM)

    def test_qp_ex_srd_send(self):
        self.create_players(e.IBV_QP_EX_WITH_SEND)
        u.traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port,
                  new_send=True, send_op=e.IBV_WR_SEND)

    def test_qp_ex_srd_send_imm(self):
        self.create_players(e.IBV_QP_EX_WITH_SEND_WITH_IMM)
        u.traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port,
                  new_send=True, send_op=e.IBV_WR_SEND_WITH_IMM)

    def test_qp_ex_srd_rdma_read(self):
        self.create_players(e.IBV_QP_EX_WITH_RDMA_READ)
        self.client.rkey = self.server.mr.rkey
        self.server.rkey = self.client.mr.rkey
        self.client.raddr = self.server.mr.buf
        self.server.raddr = self.client.mr.buf
        self.server.mr.write('s' * self.server.msg_size, self.server.msg_size)
        u.rdma_traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port,
                       new_send=True, send_op=e.IBV_WR_RDMA_READ)

    def test_qp_ex_srd_rdma_write(self):
        self.create_players(e.IBV_QP_EX_WITH_RDMA_WRITE)
        self.client.rkey = self.server.mr.rkey
        self.server.rkey = self.client.mr.rkey
        self.client.raddr = self.server.mr.buf
        self.server.raddr = self.client.mr.buf
        u.rdma_traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port,
                       new_send=True, send_op=e.IBV_WR_RDMA_WRITE)

    def test_qp_ex_srd_rdma_write_with_imm(self):
        self.create_players(e.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM)
        self.client.rkey = self.server.mr.rkey
        self.server.rkey = self.client.mr.rkey
        self.client.raddr = self.server.mr.buf
        self.server.raddr = self.client.mr.buf
        u.traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port,
                  new_send=True, send_op=e.IBV_WR_RDMA_WRITE_WITH_IMM)

    def test_qp_ex_srd_old_send(self):
        self.create_players()
        u.traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port,
                  new_send=False)

    def test_qp_ex_srd_old_send_imm(self):
        self.create_players()
        u.traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port,
                  new_send=False, send_op=e.IBV_WR_SEND_WITH_IMM)

    def test_qp_ex_srd_zero_size(self):
        self.create_players(e.IBV_QP_EX_WITH_SEND)
        self.client.msg_size = 0
        self.server.msg_size = 0
        u.traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port,
                  new_send=True, send_op=e.IBV_WR_SEND)

    def test_post_receive_qp_state_bad_flow(self):
        self.create_players(e.IBV_QP_EX_WITH_SEND, qp_count=1)
        u.post_rq_state_bad_flow(self)

    def test_post_send_qp_state_bad_flow(self):
        self.create_players(e.IBV_QP_EX_WITH_SEND, qp_count=1)
        u.post_sq_state_bad_flow(self)

    def test_full_rq_bad_flow(self):
        self.create_players(e.IBV_QP_EX_WITH_SEND, qp_count=1)
        u.full_rq_bad_flow(self)

    def test_full_sq_bad_flow(self):
        self.create_players(e.IBV_QP_EX_WITH_SEND, qp_count=1)
        self.full_sq_bad_flow()

    def test_rq_with_larger_sgl_bad_flow(self):
        self.create_players(e.IBV_QP_EX_WITH_SEND, qp_count=1)
        u.create_rq_with_larger_sgl_bad_flow(self)
