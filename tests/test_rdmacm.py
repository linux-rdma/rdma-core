# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

import unittest
import os

from tests.rdmacm_utils import  CMSyncConnection, CMAsyncConnection
from tests.base import RDMATestCase, RDMACMBaseTest
from tests.utils import requires_mcast_support
import tests.irdma_base as irdma
import pyverbs.cm_enums as ce
import pyverbs.device as d
import pyverbs.enums as e


class CMTestCase(RDMACMBaseTest):
    """
    RDMACM Test class. Include all the native RDMACM functionalities.
    """
    @staticmethod
    def get_port_space():
        # IPoIB currently is not supported
        return ce.RDMA_PS_UDP


    def test_rdmacm_sync_traffic(self):
        self.two_nodes_rdmacm_traffic(CMSyncConnection, self.rdmacm_traffic)

    def test_rdmacm_async_traffic(self):
        # QP ack timeout formula: 4.096 * 2^(ack_timeout) [usec]
        irdma.skip_if_irdma_dev(d.Context(name=self.dev_name))
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

    @requires_mcast_support()
    def test_rdmacm_async_ex_leave_multicast_traffic(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_multicast_traffic,
                                      port_space=self.get_port_space(), extended=True,
                                      leave_test=True, bad_flow=True)

    def test_rdmacm_async_traffic_external_qp(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection, self.rdmacm_traffic,
                                      with_ext_qp=True)

    def test_rdmacm_async_udp_traffic(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection, self.rdmacm_traffic,
                                      port_space=self.get_port_space(), ib_port=self.ib_port)

    def test_rdmacm_async_read(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_remote_traffic,
                                      remote_op='read')

    def test_rdmacm_async_write(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_remote_traffic,
                                      remote_op='write')
