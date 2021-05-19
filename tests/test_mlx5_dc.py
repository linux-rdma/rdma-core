# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 NVIDIA Corporation . All rights reserved. See COPYING file

import unittest
import errno

from tests.mlx5_base import Mlx5DcResources, Mlx5RDMATestCase
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

    def create_players(self, resource, **resource_arg):
        """
        Init DC tests resources.
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
