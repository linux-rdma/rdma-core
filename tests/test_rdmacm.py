# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

import multiprocessing as mp
import unittest
import os

from tests.rdmacm_utils import  CMSyncConnection, CMAsyncConnection
from pyverbs.pyverbs_error import PyverbsError
from tests.utils import requires_mcast_support
from tests.base import RDMATestCase
import pyverbs.cm_enums as ce


NUM_OF_PROCESSES = 2
MC_IP_PREFIX = '230'


class RDMACMBaseTest(RDMATestCase):
    """
    Base RDMACM test class.
    This class does not include any test, but rather implements generic
    connection and traffic methods that are needed by RDMACM tests in general.
    Each RDMACM test should have a class that inherits this class and extends
    its functionalities if needed.
    """
    def setUp(self):
        super().setUp()
        if not self.ip_addr:
            raise unittest.SkipTest('Device {} doesn\'t have net interface'
                                    .format(self.dev_name))

    def two_nodes_rdmacm_traffic(self, connection_resources, test_flow,
                                 **resource_kwargs):
        """
        Init and manage the rdmacm test processes. If needed, terminate those
        processes and raise an exception.
        :param connection_resources: The CMConnection resources to use.
        :param test_flow: The target RDMACM flow method to run.
        :param resource_kwargs: Dict of args that specify the CMResources
                                specific attributes. Each test case can pass
                                here as key words the specific CMResources
                                attributes that are requested.
        :return: None
        """
        if resource_kwargs.get('port_space', None) == ce.RDMA_PS_UDP and \
            self.is_eth_and_has_roce_hw_bug():
            raise unittest.SkipTest('Device {} doesn\'t support UDP with RoCEv2'
                                    .format(self.dev_name))
        ctx = mp.get_context('fork')
        self.syncer = ctx.Barrier(NUM_OF_PROCESSES, timeout=15)
        self.notifier = ctx.Queue()
        passive = ctx.Process(target=test_flow,
                              kwargs={'connection_resources': connection_resources,
                                      'passive':True, **resource_kwargs})
        active = ctx.Process(target=test_flow,
                              kwargs={'connection_resources': connection_resources,
                                      'passive':False, **resource_kwargs})
        passive.start()
        active.start()
        proc_raised_ex = False
        for i in range(15):
            if proc_raised_ex:
                break
            for proc in [passive, active]:
                proc.join(1)
                if not proc.is_alive() and not self.notifier.empty():
                    proc_raised_ex = True
                    break

        # If the processes is still alive kill them and fail the test.
        proc_killed = False
        for proc in [passive, active]:
            if proc.is_alive():
                proc.terminate()
                proc_killed = True
        # Check if the test processes raise exceptions.
        proc_res = {}
        while not self.notifier.empty():
            res, side = self.notifier.get()
            proc_res[side] = res
        for ex in proc_res.values():
            if isinstance(ex, unittest.case.SkipTest):
                raise(ex)
        if proc_res:
            print(f'Received the following exceptions: {proc_res}')
            if isinstance(res, Exception):
                raise(res)
            raise PyverbsError(res)
        # Raise exeption if the test proceses was terminate.
        if proc_killed:
            raise Exception('RDMA CM test procces is stuck, kill the test')

    def rdmacm_traffic(self, connection_resources=None, passive=None, **kwargs):
        """
        Run RDMACM traffic between two CMIDs.
        :param connection_resources: The connection resources to use.
        :param passive: Indicate if this CMID is this the passive side.
        :return: None
        """
        try:
            player = connection_resources(ip_addr=self.ip_addr,
                                          syncer=self.syncer,
                                          notifier=self.notifier,
                                          passive=passive, **kwargs)
            player.establish_connection()
            player.rdmacm_traffic()
            player.disconnect()
        except Exception as ex:
            side = 'passive' if passive else 'active'
            self.notifier.put((ex, side))

    def rdmacm_multicast_traffic(self, connection_resources=None, passive=None,
                                 extended=False, **kwargs):
        """
        Run RDMACM multicast traffic between two CMIDs.
        :param connection_resources: The connection resources to use.
        :param passive: Indicate if this CMID is the passive side.
        :param extended: Use exteneded multicast join request. This request
                         allows CMID to join with specific join flags.
        :param kwargs: Arguments to be passed to the connection_resources.
        :return: None
        """
        try:
            player = connection_resources(ip_addr=self.ip_addr, syncer=self.syncer,
                                          notifier=self.notifier, passive=False,
                                          **kwargs)
            mc_addr = MC_IP_PREFIX + self.ip_addr[self.ip_addr.find('.'):]
            player.join_to_multicast(src_addr=self.ip_addr, mc_addr=mc_addr,
                                     extended=extended)
            player.rdmacm_traffic(server=passive, multicast=True)
            player.leave_multicast(mc_addr=mc_addr)
        except Exception as ex:
            side = 'passive' if passive else 'active'
            self.notifier.put((ex, side))

    def rdmacm_remote_traffic(self, connection_resources=None, passive=None,
                              remote_op='write', **kwargs):
        """
        Run RDMACM remote traffic between two CMIDs.
        :param connection_resources: The connection resources to use.
        :param passive: Indicate if this CMID is the passive side.
        :param remote_op: The remote operation in the traffic.
        :param kwargs: Arguments to be passed to the connection_resources.
        :return: None
        """
        try:
            player = connection_resources(ip_addr=self.ip_addr,
                                          syncer=self.syncer,
                                          notifier=self.notifier,
                                          passive=passive,
                                          remote_op=remote_op, **kwargs)
            player.establish_connection()
            player.remote_traffic(passive=passive, remote_op=remote_op)
            player.disconnect()
        except Exception as ex:
            while not self.notifier.empty():
                self.notifier.get()
            side = 'passive' if passive else 'active'
            self.notifier.put((ex, side))


class CMTestCase(RDMACMBaseTest):
    """
    RDMACM Test class. Include all the native RDMACM functionalities.
    """
    def test_rdmacm_sync_traffic(self):
        self.two_nodes_rdmacm_traffic(CMSyncConnection, self.rdmacm_traffic)

    def test_rdmacm_async_traffic(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection, self.rdmacm_traffic)

    @requires_mcast_support()
    def test_rdmacm_async_multicast_traffic(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_multicast_traffic,
                                      port_space=ce.RDMA_PS_UDP)

    @requires_mcast_support()
    def test_rdmacm_async_ex_multicast_traffic(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_multicast_traffic,
                                      port_space=ce.RDMA_PS_UDP, extended=True)

    def test_rdmacm_async_traffic_external_qp(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection, self.rdmacm_traffic,
                                      with_ext_qp=True)

    def test_rdmacm_async_udp_traffic(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection, self.rdmacm_traffic,
                                      port_space=ce.RDMA_PS_UDP)

    def test_rdmacm_async_read(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_remote_traffic,
                                      remote_op='read')

    def test_rdmacm_async_write(self):
        self.two_nodes_rdmacm_traffic(CMAsyncConnection,
                                      self.rdmacm_remote_traffic,
                                      remote_op='write')
