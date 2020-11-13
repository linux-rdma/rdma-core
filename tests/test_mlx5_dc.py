# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 NVIDIA Corporation . All rights reserved. See COPYING file

from tests.mlx5_base import Mlx5DcResources
from tests.base import RDMATestCase
import pyverbs.enums as e
import tests.utils as u


class DCTest(RDMATestCase):
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
