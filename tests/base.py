# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc . All rights reserved. See COPYING file

import subprocess
import unittest
import tempfile
import random
import errno
import stat
import json
import os

from pyverbs.qp import QPCap, QPInitAttrEx, QPInitAttr, QPAttr, QP
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.addr import AHAttr, GlobalRoute
from pyverbs.xrcd import XRCD, XRCDInitAttr
from pyverbs.srq import SRQ, SrqInitAttrEx
from pyverbs.device import Context
from args_parser import parser
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.pd import PD
from pyverbs.cq import CQ
from pyverbs.mr import MR


PATH_MTU = e.IBV_MTU_1024
MAX_DEST_RD_ATOMIC = 1
MAX_RD_ATOMIC = 1
MIN_RNR_TIMER =12
RETRY_CNT = 7
RNR_RETRY = 7
TIMEOUT = 14
# Devices that don't support RoCEv2 should be added here
MLNX_VENDOR_ID = 0x02c9
CX3_MLNX_PART_ID = 4099
CX3Pro_MLNX_PART_ID = 4103
# Dictionary: vendor_id -> array of part_ids of devices that lack RoCEv2 support
ROCEV2_UNSUPPORTED_DEVS = {MLNX_VENDOR_ID: [CX3Pro_MLNX_PART_ID,
                                            CX3_MLNX_PART_ID]}


def has_roce_hw_bug(vendor_id, vendor_part_id):
    return vendor_part_id in ROCEV2_UNSUPPORTED_DEVS.get(vendor_id, [])


class PyverbsAPITestCase(unittest.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        # Hold the command line arguments
        self.config = parser.get_config()

    def setUp(self):
        """
        Opens the devices and queries them
        """
        self.devices = []

        dev_name = self.config['dev']
        if dev_name:
            c = d.Context(name=dev_name)
            attr = c.query_device()
            attr_ex = c.query_device_ex()
            self.devices.append((c, attr, attr_ex))
        else:
            for dev in d.get_device_list():
                c = d.Context(name=dev.name.decode())
                attr = c.query_device()
                attr_ex = c.query_device_ex()
                self.devices.append((c, attr, attr_ex))

        if len(self.devices) == 0:
            raise unittest.SkipTest('No IB devices found')

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
        # Hold the command line arguments
        self.config = parser.get_config()
        dev = self.config['dev']
        self.dev_name = dev_name if dev_name else dev
        self.ib_port = ib_port
        self.gid_index = gid_index
        self.pkey_index = pkey_index
        self.ip_addr = None

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

    @staticmethod
    def get_net_name(dev):
        out = subprocess.check_output(['ls',
                                       '/sys/class/infiniband/{}/device/net/'
                                      .format(dev)])
        return out.decode().split('\n')[0]

    @staticmethod
    def get_ip_address(ifname):
        out = subprocess.check_output(['ip', '-j', 'addr', 'show', ifname])
        loaded_json = json.loads(out.decode())
        interface = loaded_json[0]['addr_info'][0]['local']
        if 'fe80::' in interface:
            interface = interface + '%' + ifname
        return interface

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
        self._select_config()

    def _add_gids_per_port(self, ctx, dev, port):
        # Don't add ports which are not active
        port_attrs = ctx.query_port(port)
        if port_attrs.state != e.IBV_PORT_ACTIVE:
            return
        dev_attrs = ctx.query_device()
        vendor_id = dev_attrs.vendor_id
        vendor_pid = dev_attrs.vendor_part_id
        for idx in range(port_attrs.gid_tbl_len):
            gid = ctx.query_gid(port, idx)
            # Avoid adding ZERO GIDs
            if gid.gid[-19:] == self.ZERO_GID:
                continue
            # Avoid RoCEv2 GIDs on unsupported devices
            if port_attrs.link_layer == e.IBV_LINK_LAYER_ETHERNET and \
                    ctx.query_gid_type(port, idx) == e.IBV_GID_TYPE_ROCE_V2 and \
                    has_roce_hw_bug(vendor_id, vendor_pid):
                continue
            net_name = self.get_net_name(dev)
            try:
                ip_addr = self.get_ip_address(net_name)
            except (KeyError, IndexError):
                self.args.append([dev, port, idx, None])
            else:
                self.args.append([dev, port, idx, ip_addr])

    def _add_gids_per_device(self, ctx, dev):
        port_count = ctx.query_device().phys_port_cnt
        for port in range(port_count):
            self._add_gids_per_port(ctx, dev, port+1)

    def _select_config(self):
        args_with_inet_ip = []
        for arg in self.args:
            if arg[3]:
                args_with_inet_ip.append(arg)
        if args_with_inet_ip:
            args = random.choice(args_with_inet_ip)
        else:
            args = random.choice(self.args)
        self.dev_name = args[0]
        self.ib_port = args[1]
        self.gid_index = args[2]
        self.ip_addr = args[3]


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

    def to_rts(self):
        """
        Set the QP attributes' values to arbitrary values (same values used in
        ibv_rc_pingpong).
        :return: None
        """
        attr = QPAttr(port_num=self.ib_port)
        attr.dest_qp_num = self.rqpn
        attr.path_mtu = PATH_MTU
        attr.max_dest_rd_atomic = MAX_DEST_RD_ATOMIC
        attr.min_rnr_timer = MIN_RNR_TIMER
        attr.rq_psn = self.psn
        attr.sq_psn = self.rpsn
        attr.timeout = TIMEOUT
        attr.retry_cnt = RETRY_CNT
        attr.rnr_retry = RNR_RETRY
        attr.max_rd_atomic = MAX_RD_ATOMIC
        gr = GlobalRoute(dgid=self.ctx.query_gid(self.ib_port, self.gid_index),
                         sgid_index=self.gid_index)
        ah_attr = AHAttr(port_num=self.ib_port, is_global=1, gr=gr,
                         dlid=self.port_attr.lid)
        attr.ah_attr = ah_attr
        self.qp.to_rts(attr)

    def pre_run(self, rpsn, rqpn):
        """
        Configure Resources before running traffic
        :param rpsn: Remote PSN (packet serial number)
        :param rqpn: Remote QP number
        :return: None
        """
        self.rqpn = rqpn
        self.rpsn = rpsn
        self.to_rts()


class UDResources(TrafficResources):
    UD_QKEY = 0x11111111
    UD_PKEY_INDEX = 0
    GRH_SIZE = 40

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


class XRCResources(TrafficResources):
    def __init__(self, dev_name, ib_port, gid_index, qp_count=2):
        self.temp_file = None
        self.xrcd_fd = -1
        self.xrcd = None
        self.srq = None
        self.qp_count = qp_count
        self.sqp_lst = []
        self.rqp_lst = []
        self.qps_num = []
        self.psns = []
        self.rqps_num = None
        self.rpsns = None
        super(XRCResources, self).__init__(dev_name, ib_port, gid_index)

    def close(self):
        os.close(self.xrcd_fd)
        self.temp_file.close()

    def create_qp(self):
        """
        Initializes self.qp with an XRC SEND/RECV QP.
        :return: None
        """
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_attr.pkey_index = 0

        for _ in range(self.qp_count):
            attr_ex = QPInitAttrEx(qp_type=e.IBV_QPT_XRC_RECV,
                                   comp_mask=e.IBV_QP_INIT_ATTR_XRCD,
                                   xrcd=self.xrcd)
            qp_attr.qp_access_flags = e.IBV_ACCESS_REMOTE_WRITE | \
                                      e.IBV_ACCESS_REMOTE_READ
            recv_qp = QP(self.ctx, attr_ex, qp_attr)
            self.rqp_lst.append(recv_qp)

            qp_caps = QPCap(max_send_wr=self.num_msgs, max_recv_sge=0,
                            max_recv_wr=0)
            attr_ex = QPInitAttrEx(qp_type=e.IBV_QPT_XRC_SEND, sq_sig_all=1,
                                   comp_mask=e.IBV_QP_INIT_ATTR_PD,
                                   pd=self.pd, scq=self.cq, cap=qp_caps)
            qp_attr.qp_access_flags = 0
            send_qp =QP(self.ctx, attr_ex, qp_attr)
            self.sqp_lst.append(send_qp)
            self.qps_num.append((recv_qp.qp_num, send_qp.qp_num))
            self.psns.append(random.getrandbits(24))

    def create_xrcd(self):
        """
        Initializes self.xrcd with an XRC Domain object.
        :return: None
        """
        self.temp_file = tempfile.NamedTemporaryFile()
        self.xrcd_fd = os.open(self.temp_file.name, os.O_RDONLY | os.O_CREAT,
                               stat.S_IRUSR | stat.S_IRGRP)
        init = XRCDInitAttr(
            e.IBV_XRCD_INIT_ATTR_FD | e.IBV_XRCD_INIT_ATTR_OFLAGS,
            os.O_CREAT, self.xrcd_fd)
        try:
            self.xrcd = XRCD(self.ctx, init)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create XRCD is not supported')
            raise ex

    def create_srq(self):
        """
        Initializes self.srq with a Shared Receive QP object.
        :return: None
        """
        srq_attr = SrqInitAttrEx(max_wr=self.qp_count*self.num_msgs)
        srq_attr.srq_type = e.IBV_SRQT_XRC
        srq_attr.pd = self.pd
        srq_attr.xrcd = self.xrcd
        srq_attr.cq = self.cq
        srq_attr.comp_mask = e.IBV_SRQ_INIT_ATTR_TYPE | e.IBV_SRQ_INIT_ATTR_PD | \
                             e.IBV_SRQ_INIT_ATTR_CQ | e.IBV_SRQ_INIT_ATTR_XRCD
        self.srq = SRQ(self.ctx, srq_attr)

    def to_rts(self):
        gid = self.ctx.query_gid(self.ib_port, self.gid_index)
        gr = GlobalRoute(dgid=gid, sgid_index=self.gid_index)
        ah_attr = AHAttr(port_num=self.ib_port, is_global=True,
                         gr=gr, dlid=self.port_attr.lid)
        qp_attr = QPAttr()
        qp_attr.path_mtu = PATH_MTU
        qp_attr.timeout = TIMEOUT
        qp_attr.retry_cnt = RETRY_CNT
        qp_attr.rnr_retry = RNR_RETRY
        qp_attr.min_rnr_timer = MIN_RNR_TIMER
        qp_attr.ah_attr = ah_attr
        for i in range(self.qp_count):
            qp_attr.dest_qp_num = self.rqps_num[i][1]
            qp_attr.rq_psn = self.psns[i]
            qp_attr.sq_psn = self.rpsns[i]
            self.rqp_lst[i].to_rts(qp_attr)
            qp_attr.dest_qp_num = self.rqps_num[i][0]
            self.sqp_lst[i].to_rts(qp_attr)

    def init_resources(self):
        self.create_xrcd()
        super(XRCResources, self).init_resources()
        self.create_srq()

    def pre_run(self, rpsns, rqps_num):
        self.rqps_num = rqps_num
        self.rpsns = rpsns
        self.to_rts()
