# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 NVIDIA Corporation . All rights reserved. See COPYING file

import unittest
import errno

from tests.mlx5_base import Mlx5DcResources, Mlx5RDMATestCase, Mlx5DcStreamsRes
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.providers.mlx5.mlx5dv import Mlx5QP
from pyverbs.libibverbs_enums import ibv_access_flags, ibv_qp_create_send_ops_flags, ibv_wr_opcode, \
    ibv_odp_transport_cap_bits, ibv_qp_attr_mask, ibv_qp_state
import tests.utils as u


class OdpDc(Mlx5DcResources):
    def create_mr(self):
        try:
            self.mr = u.create_custom_mr(self, ibv_access_flags.IBV_ACCESS_ON_DEMAND)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Reg ODP MR is not supported')
            raise ex


class DCTest(Mlx5RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None
        self.traffic_args = None

    def sync_remote_attr(self):
        """
        Exchange the remote attributes between the server and the client.
        """
        super().sync_remote_attr()
        self.client.remote_dct_num = self.server.dct_qp.qp_num
        self.server.remote_dct_num = self.client.dct_qp.qp_num

    def test_dc_rdma_write(self):
        self.create_players(Mlx5DcResources, qp_count=2,
                            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE)
        u.rdma_traffic(**self.traffic_args, new_send=True,
                       send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE)

    def test_dc_send(self):
        self.create_players(Mlx5DcResources, qp_count=2,
                            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND)
        u.traffic(**self.traffic_args, new_send=True,
                  send_op=ibv_wr_opcode.IBV_WR_SEND)

    def test_dc_atomic(self):
        self.create_players(Mlx5DcResources, qp_count=2,
                            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD)
        client_max_log = self.client.ctx.query_mlx5_device().max_dc_rd_atom
        server_max_log = self.server.ctx.query_mlx5_device().max_dc_rd_atom
        u.atomic_traffic(**self.traffic_args, new_send=True,
                         send_op=ibv_wr_opcode.IBV_WR_ATOMIC_FETCH_AND_ADD,
                         client_wr=client_max_log, server_wr=server_max_log)

    def test_dc_ah_to_qp_mapping(self):
        self.create_players(Mlx5DcResources, qp_count=2,
                            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND)
        client_ah = u.get_global_ah(self.client, self.gid_index, self.ib_port)
        try:
            Mlx5QP.map_ah_to_qp(client_ah, self.server.qps[0].qp_num)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Mapping AH to QP is not supported')
            raise ex
        u.traffic(**self.traffic_args, new_send=True,
                  send_op=ibv_wr_opcode.IBV_WR_SEND)

    def check_odp_dc_support(self):
        """
        Check if the device supports ODP with DC.
        :raises SkipTest: In case ODP is not supported with DC
        """
        dc_odp_caps = self.server.ctx.query_mlx5_device().dc_odp_caps
        required_odp_caps = ibv_odp_transport_cap_bits.IBV_ODP_SUPPORT_SEND | \
                            ibv_odp_transport_cap_bits.IBV_ODP_SUPPORT_SRQ_RECV
        if required_odp_caps & dc_odp_caps != required_odp_caps:
            raise unittest.SkipTest('ODP is not supported using DC')

    def test_odp_dc_traffic(self):
        send_ops_flag = ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND
        self.create_players(OdpDc, qp_count=2, send_ops_flags=send_ops_flag)
        self.check_odp_dc_support()
        u.traffic(**self.traffic_args, new_send=True,
                  send_op=ibv_wr_opcode.IBV_WR_SEND)

    def test_dc_rdma_write_stream(self):
        """
        Check good flow of DCS.
        Calculate stream_id for DCS test by setting same stream id
        twice for WR and after increase it. Setting goes by loop
        and after stream_id is more than number of concurrent
        streams + 1 then stream_id returns to 1.
        :raises SkipTest: In case DCI is not supported with HW
        """
        self.create_players(Mlx5DcStreamsRes, qp_count=2,
                            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE)
        u.rdma_traffic(**self.traffic_args, new_send=True,
                       send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE)

    def test_dc_stream_qp_recovery(self):
        """
        Test DC QP error state transition with stream channel error accumulation.
        Creates DC QPs with restricted MR access and generates remote access errors
        via RDMA_WRITE operations. Verifies QP transitions to ERR state after enough
        channels entered error mode. Validates QP recovery after reset.
        """
        self.create_players(Mlx5DcStreamsRes, qp_count=2,
                            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE,
                            mr_access=ibv_access_flags.IBV_ACCESS_LOCAL_WRITE)
        qp_idx = 0
        error_threshold = self.client.dcis[qp_idx]['errored']
        u.traffic(**self.traffic_args, new_send=True, send_op=ibv_wr_opcode.IBV_WR_SEND)
        for _ in range(error_threshold):
            with self.assertRaisesRegex(PyverbsRDMAError, r'Remote access error'):
                u.rdma_traffic(**self.traffic_args, new_send=True,
                               send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE)
        # Retry mechanism: QP state update to ERR takes time after errors occur
        qp_in_err_state = False
        for _ in range(3):
            qp_attr, _ = self.client.qps[qp_idx].query(ibv_qp_attr_mask.IBV_QP_STATE)
            if qp_attr.cur_qp_state == ibv_qp_state.IBV_QPS_ERR:
                qp_in_err_state = True
                break
        if not qp_in_err_state:
            raise PyverbsRDMAError(f'QP is not in ERR state after {error_threshold} errors')
        for qp_idx in range(self.client.qp_count):
            self.client.reset_qp(qp_idx)
        for qp_idx in range(self.server.qp_count):
            self.server.reset_qp(qp_idx)
        u.traffic(**self.traffic_args, new_send=True, send_op=ibv_wr_opcode.IBV_WR_SEND)

    def test_dc_stream_ids_recovery(self):
        """
        Test DC stream ID reset functionality after remote access errors.
        Creates DC QPs with restricted MR access and generates
        remote access errors via RDMA_WRITE operations. After each error, resets
        the stream ID and verifies QP remains functional.
        Validates normal SEND traffic continues to work after stream resets.
        """
        self.create_players(Mlx5DcStreamsRes, qp_count=2,
                            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE,
                            mr_access=ibv_access_flags.IBV_ACCESS_LOCAL_WRITE)
        qp_idx = 0
        error_threshold = self.client.dcis[qp_idx]['errored']
        u.traffic(**self.traffic_args, new_send=True, send_op=ibv_wr_opcode.IBV_WR_SEND)
        for _ in range(error_threshold):
            with self.assertRaisesRegex(PyverbsRDMAError, r'Remote access error'):
                u.rdma_traffic(**self.traffic_args, new_send=True,
                            send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE)
            self.client.dci_reset_stream_id(qp_idx)
        qp_attr, _ = self.client.qps[qp_idx].query(ibv_qp_attr_mask.IBV_QP_STATE)
        if qp_attr.cur_qp_state == ibv_qp_state.IBV_QPS_ERR:
            raise PyverbsRDMAError('QP is in ERR state after reset stream id')
        u.traffic(**self.traffic_args, new_send=True, send_op=ibv_wr_opcode.IBV_WR_SEND)
