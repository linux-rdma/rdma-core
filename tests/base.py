# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc . All rights reserved. See COPYING file

import unittest
import random

from pyverbs.qp import QPCap, QPInitAttr, QPAttr, QP
from pyverbs.addr import AHAttr, GlobalRoute
from pyverbs.device import Context
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.pd import PD
from pyverbs.cq import CQ
from pyverbs.mr import MR


class PyverbsAPITestCase(unittest.TestCase):
    def setUp(self):
        """
        Opens the devices and queries them
        """
        lst = d.get_device_list()
        self.devices = []
        for dev in lst:
            c = d.Context(name=dev.name.decode())
            attr = c.query_device()
            attr_ex = c.query_device_ex()
            self.devices.append((c, attr, attr_ex))

    def tearDown(self):
        for tup in self.devices:
            tup[0].close()


class RDMATestCase(unittest.TestCase):
    """
    A base class for test cases which provides the option for user parameters.
    These can be provided by manually adding the test case to the runner:
    suite = unittest.TestSuite()
    ... # Regular auto-detection of test cases, no parameters used.
    # Now follows your manual addition of test cases e.g:
    suite.addTest(RDMATestCase.parametrize(<TestCaseName>, dev_name='..',
                                           ib_port=1, gid_index=3,
                                           pkey_index=42))
    """
    ZERO_GID = '0000:0000:0000:0000'

    def __init__(self, methodName='runTest', dev_name=None, ib_port=None,
                 gid_index=None, pkey_index=None):
        super(RDMATestCase, self).__init__(methodName)
        self.dev_name = dev_name
        self.ib_port = ib_port
        self.gid_index = gid_index
        self.pkey_index = pkey_index

    @staticmethod
    def parametrize(testcase_klass, dev_name=None, ib_port=None, gid_index=None,
                    pkey_index=None):
        """
        Create a test suite containing all the tests from the given subclass
        with the given dev_name, port, gid index and pkey_index.
        """
        loader = unittest.TestLoader()
        names = loader.getTestCaseNames(testcase_klass)
        suite = unittest.TestSuite()
        for n in names:
            suite.addTest(testcase_klass(n, dev_name=dev_name, ib_port=ib_port,
                                         gid_index=gid_index,
                                         pkey_index=pkey_index))
        return suite

    def setUp(self):
        """
        Verify that the test case has dev_name, ib_port, gid_index and pkey index.
        If not provided by the user, a random valid combination will be used.
        """
        if self.pkey_index is None:
            # To avoid iterating the entire pkeys table, if a pkey index wasn't
            # provided, use index 0 which is always valid
            self.pkey_index = 0

        self.args = []
        if self.dev_name is not None:
            ctx = d.Context(name=self.dev_name)
            if self.ib_port is not None:
                if self.gid_index is not None:
                    # We have all we need, return
                    return
                else:
                    # Add avaiable GIDs of the given dev_name + port
                    self._add_gids_per_port(ctx, self.dev_name, self.ib_port)
            else:
                # Add available GIDs for each port of the given dev_name
                self._add_gids_per_device(ctx, self.dev_name)
        else:
            # Iterate available devices, add available GIDs for each of
            # their ports
            lst = d.get_device_list()
            for dev in lst:
                dev_name = dev.name.decode()
                ctx = d.Context(name=dev_name)
                self._add_gids_per_device(ctx, dev_name)

        if not self.args:
            raise unittest.SkipTest('No port is up, can\'t run traffic')
        # Choose one combination and use it
        args = random.choice(self.args)
        self.dev_name = args[0]
        self.ib_port = args[1]
        self.gid_index = args[2]

    def _add_gids_per_port(self, ctx, dev, port):
        # Don't add ports which are not active
        if ctx.query_port(port).state != e.IBV_PORT_ACTIVE:
            return
        idx = 0
        while True:
            gid = ctx.query_gid(port, idx)
            if gid.gid[-19:] == self.ZERO_GID:
                # No point iterating on
                break
            else:
                self.args.append([dev, port, idx])
                idx += 1

    def _add_gids_per_device(self, ctx, dev):
        port_count = ctx.query_device().phys_port_cnt
        for port in range(port_count):
            self._add_gids_per_port(ctx, dev, port+1)


class BaseResources(object):
    """
    BaseResources class is a base aggregator object which contains basic
    resources like Context and PD. It opens a context over the given device
    and port and allocates a PD.
    """
    def __init__(self, dev_name, ib_port, gid_index):
        """
        Initializes a BaseResources object.
        :param dev_name: Device name to be used (default: 'ibp0s8f0')
        :param ib_port: IB port of the device to use (default: 1)
        :param gid_index: Which GID index to use (default: 0)
        """
        self.ctx = Context(name=dev_name)
        self.gid_index = gid_index
        self.pd = PD(self.ctx)
        self.ib_port = ib_port


class TrafficResources(BaseResources):
    """
    Basic traffic class. It provides the basic RDMA resources and operations
    needed for traffic.
    """
    def __init__(self, dev_name, ib_port, gid_index):
        """
        Initializes a TrafficResources object with the given values and creates
        basic RDMA resources.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        """
        super(TrafficResources, self).__init__(dev_name=dev_name,
                                               ib_port=ib_port,
                                               gid_index=gid_index)
        self.psn = random.getrandbits(24)
        self.msg_size = 1024
        self.num_msgs = 1000
        self.port_attr = None
        self.mr = None
        self.cq = None
        self.qp = None
        self.rqpn = 0
        self.rpsn = 0
        self.init_resources()

    @property
    def qpn(self):
        return self.qp.qp_num

    def init_resources(self):
        """
        Initializes a CQ, MR and an RC QP.
        :return: None
        """
        self.port_attr = self.ctx.query_port(self.ib_port)
        self.create_cq()
        self.create_mr()
        self.create_qp()

    def create_cq(self):
        """
        Initializes self.cq with a CQ of depth <num_msgs> - defined by each
        test.
        :return: None
        """
        self.cq = CQ(self.ctx, self.num_msgs, None, None, 0)

    def create_mr(self):
        """
        Initializes self.mr with an MR of length <msg_size> - defined by each
        test.
        :return: None
        """
        self.mr = MR(self.pd, self.msg_size, e.IBV_ACCESS_LOCAL_WRITE)

    def create_qp(self):
        """
        Initializes self.qp with an RC QP.
        :return: None
        """
        qp_caps = QPCap(max_recv_wr=self.num_msgs)
        qp_init_attr = QPInitAttr(qp_type=e.IBV_QPT_RC, scq=self.cq,
                                  rcq=self.cq, cap=qp_caps)
        qp_attr = QPAttr(port_num=self.ib_port)
        self.qp = QP(self.pd, qp_init_attr, qp_attr)

    def pre_run(self, rpsn, rqpn):
        """
        Modify the QP's state to RTS and fill receive queue with <num_msgs> work
        requests.
        This method is not implemented in this class.
        :param rpsn: Remote PSN
        :param rqpn: Remote QPN
        :return: None
        """
        raise NotImplementedError()


class RCResources(TrafficResources):
    PATH_MTU = e.IBV_MTU_1024
    MAX_DEST_RD_ATOMIC = 1
    MAX_RD_ATOMIC = 1
    MIN_RNR_TIMER =12
    RETRY_CNT = 7
    RNR_RETRY = 7
    TIMEOUT = 14

    def to_rts(self, rpsn, rqpn):
        """
        Set the QP attributes' values to arbitrary values (same values used in
        ibv_rc_pingpong).
        :param rpsn: Remote PSN (packet serial number)
        :param rqpn: Remote QP number
        :return: None
        """
        attr = QPAttr(port_num=self.ib_port)
        attr.dest_qp_num = rqpn
        attr.path_mtu = self.PATH_MTU
        attr.max_dest_rd_atomic = self.MAX_DEST_RD_ATOMIC
        attr.min_rnr_timer = self.MIN_RNR_TIMER
        attr.rq_psn = rpsn
        attr.sq_psn = self.psn
        attr.timeout = self.TIMEOUT
        attr.retry_cnt = self.RETRY_CNT
        attr.rnr_retry = self.RNR_RETRY
        attr.max_rd_atomic = self.MAX_RD_ATOMIC
        gr = GlobalRoute(dgid=self.ctx.query_gid(self.ib_port, self.gid_index),
                         sgid_index=self.gid_index)
        ah_attr = AHAttr(port_num=self.ib_port, is_global=1, gr=gr,
                         dlid=self.port_attr.lid)
        attr.ah_attr = ah_attr
        self.qp.to_rts(attr)

    def pre_run(self, rpsn, rqpn):
        self.rqpn = rqpn
        self.rpsn = rpsn
        self.to_rts(rpsn, rqpn)


class UDResources(TrafficResources):
    UD_QKEY = 0x11111111
    UD_PKEY_INDEX = 0

    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size + self.GRH_SIZE,
                     e.IBV_ACCESS_LOCAL_WRITE)

    def create_qp(self):
        qp_caps = QPCap(max_recv_wr=self.num_msgs)
        qp_init_attr = QPInitAttr(qp_type=e.IBV_QPT_UD, cap=qp_caps,
                                  scq=self.cq, rcq=self.cq)
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_attr.qkey = self.UD_QKEY
        qp_attr.pkey_index = self.UD_PKEY_INDEX
        self.qp = QP(self.pd, qp_init_attr, qp_attr)

    def pre_run(self, rpsn, rqpn):
        self.rqpn = rqpn
        self.rpsn = rpsn