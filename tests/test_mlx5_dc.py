# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 NVIDIA Corporation . All rights reserved. See COPYING file

import unittest
import errno

import pyverbs.providers.mlx5.mlx5_enums as me
from tests.mlx5_base import Mlx5DcResources, Mlx5RDMATestCase, Mlx5DcStreamsRes,\
    DCI_TEST_GOOD_FLOW, DCI_TEST_BAD_FLOW_WITH_RESET,\
    DCI_TEST_BAD_FLOW_WITHOUT_RESET
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.providers.mlx5.mlx5dv import Mlx5QP
import pyverbs.enums as e
import tests.utils as u


class OdpDc(Mlx5DcResources):
    def create_mr(self):
        try:
            self.mr = u.create_custom_mr(self, e.IBV_ACCESS_ON_DEMAND)
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
        self.server.rkey = self.client.mr.rkey
        self.server.raddr = self.client.mr.buf
        self.client.rkey = self.server.mr.rkey
        self.client.raddr = self.server.mr.buf
        self.client.remote_dct_num = self.server.dct_qp.qp_num
        self.server.remote_dct_num = self.client.dct_qp.qp_num

    def create_players(self, resource, bad_flow=DCI_TEST_GOOD_FLOW, **resource_arg):
        """
        Init DC tests resources.
        :param resource: The RDMA resources to use.
        :param bad_flow: Test bad flows (relevant for DCS tests only)
        :param resource_arg: Dict of args that specify the resource specific
        attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        if bad_flow:
            self.client.set_bad_flow(bad_flow)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)
        self.sync_remote_attr()
        self.traffic_args = {'client': self.client, 'server': self.server,
                             'iters': self.iters, 'gid_idx': self.gid_index,
                             'port': self.ib_port}

    def test_dc_rdma_write(self):
        self.create_players(Mlx5DcResources, qp_count=2,
                            send_ops_flags=e.IBV_QP_EX_WITH_RDMA_WRITE)
        u.rdma_traffic(**self.traffic_args, new_send=True,
                       send_op=e.IBV_QP_EX_WITH_RDMA_WRITE)

    def test_dc_send(self):
        self.create_players(Mlx5DcResources, qp_count=2,
                            send_ops_flags=e.IBV_QP_EX_WITH_SEND)
        u.traffic(**self.traffic_args, new_send=True,
                  send_op=e.IBV_QP_EX_WITH_SEND)

    def test_dc_ah_to_qp_mapping(self):
        self.create_players(Mlx5DcResources, qp_count=2,
                            send_ops_flags=e.IBV_QP_EX_WITH_SEND)
        client_ah = u.get_global_ah(self.client, self.gid_index, self.ib_port)
        try:
            Mlx5QP.map_ah_to_qp(client_ah, self.server.qps[0].qp_num)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Mapping AH to QP is not supported')
            raise ex
        u.traffic(**self.traffic_args, new_send=True,
                  send_op=e.IBV_QP_EX_WITH_SEND)

    def check_odp_dc_support(self):
        """
        Check if the device supports ODP with DC.
        :raises SkipTest: In case ODP is not supported with DC
        """
        dc_odp_caps = self.server.ctx.query_mlx5_device().dc_odp_caps
        required_odp_caps = e.IBV_ODP_SUPPORT_SEND | e.IBV_ODP_SUPPORT_SRQ_RECV
        if required_odp_caps & dc_odp_caps != required_odp_caps:
            raise unittest.SkipTest('ODP is not supported using DC')

    def test_odp_dc_traffic(self):
        send_ops_flag = e.IBV_QP_EX_WITH_SEND
        self.create_players(OdpDc, qp_count=2, send_ops_flags=send_ops_flag)
        self.check_odp_dc_support()
        u.traffic(**self.traffic_args, new_send=True,
                  send_op=e.IBV_QP_EX_WITH_SEND)

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
                            send_ops_flags=e.IBV_QP_EX_WITH_RDMA_WRITE)
        u.rdma_traffic(**self.traffic_args, new_send=True,
                       send_op=e.IBV_QP_EX_WITH_RDMA_WRITE)

    def test_dc_send_stream_bad_flow(self):
        """
        Check bad flow of DCS with reset stream id.
        Create error in dci stream by setting invalid PD so dci stream goes to error.
        In the end, the test verifies that the number of errors is as expected.
        :raises SkipTest: In case DCI is not supported with HW
        """
        self.create_players(Mlx5DcStreamsRes, bad_flow=DCI_TEST_BAD_FLOW_WITH_RESET,
                            qp_count=1, send_ops_flags=e.IBV_QP_EX_WITH_SEND)
        self.client.traffic_with_bad_flow(**self.traffic_args)

    def test_dc_send_stream_bad_flow_qp(self):
        """
        Check bad flow of DCS with reset qp.
        Checked if resetting of wrong dci stream id produces an exception.
        This bad flow creates enough errors without resetting the streams,
        enforcing the QP to get into ERR state. Then the checking is stopped.
        Also has feature that after QP goes in ERR state test will
        reset QP to RTS state.
        :raises SkipTest: In case DCI is not supported with HW
        """
        self.iters = 20
        self.create_players(Mlx5DcStreamsRes, bad_flow=DCI_TEST_BAD_FLOW_WITHOUT_RESET,
                            qp_count=1, send_ops_flags=e.IBV_QP_EX_WITH_SEND)
        self.client.traffic_with_bad_flow(**self.traffic_args)
