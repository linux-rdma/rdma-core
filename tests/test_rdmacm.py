# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

import unittest
import os

from tests.rdmacm_utils import  CMSyncConnection, CMAsyncConnection
from tests.base import RDMATestCase, RDMACMBaseTest
from tests.utils import requires_mcast_support
import pyverbs.cm_enums as ce
import pyverbs.device as d
import pyverbs.enums as e


class CMTestCase(RDMACMBaseTest):
    """
    RDMACM Test class. Include all the native RDMACM functionalities.
    """
    def get_port_space(self):
        ctx = d.Context(name=self.dev_name)
        dev_attrs = ctx.query_port(self.ib_port)
        port_space = ce.RDMA_PS_IPOIB \
            if dev_attrs.link_layer == e.IBV_LINK_LAYER_INFINIBAND \
                else ce.RDMA_PS_UDP
        return port_space


    def test_rdmacm_sync_traffic(self):
        self.two_nodes_rdmacm_traffic(CMSyncConnection, self.rdmacm_traffic)

    def test_rdmacm_async_traffic(self):
        # QP ack timeout formula: 4.096 * 2^(ack_timeout) [usec]
        self.two_nodes_rdmacm_traffic(CMAsyncConnection, self.rdmacm_traffic,
                                      qp_timeout=21)

    def test_rdmacm_async_reject_traffic(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection, self.rdmacm_traffic,
                                      reject_conn=True)

    @requires_mcast_support()
    def test_rdmacm_async_multicast_traffic(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_multicast_traffic,
                                      port_space=self.get_port_space())

    @requires_mcast_support()
    def test_rdmacm_async_ex_multicast_traffic(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_multicast_traffic,
                                      port_space=self.get_port_space(), extended=True)

    def test_rdmacm_async_traffic_external_qp(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection, self.rdmacm_traffic,
                                      with_ext_qp=True)

    def test_rdmacm_async_udp_traffic(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection, self.rdmacm_traffic,
                                      port_space=self.get_port_space())

    def test_rdmacm_async_read(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_remote_traffic,
                                      remote_op='read')

    def test_rdmacm_async_write(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_remote_traffic,
                                      remote_op='write')
