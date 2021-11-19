# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc . All rights reserved. See COPYING file

import multiprocessing as mp
import subprocess
import unittest
import tempfile
import random
import errno
import stat
import json
import os

from pyverbs.qp import QPCap, QPInitAttrEx, QPInitAttr, QPAttr, QP
from pyverbs.srq import SRQ, SrqInitAttrEx, SrqInitAttr, SrqAttr
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.addr import AHAttr, GlobalRoute
from pyverbs.xrcd import XRCD, XRCDInitAttr
from pyverbs.device import Context
from args_parser import parser
import pyverbs.cm_enums as ce
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.pd import PD
from pyverbs.cq import CQ
from pyverbs.mr import MR


PATH_MTU = e.IBV_MTU_1024
MAX_DEST_RD_ATOMIC = 1
NUM_OF_PROCESSES = 2
MC_IP_PREFIX = '230'
MAX_RDMA_ATOMIC = 20
MAX_RD_ATOMIC = 1
MIN_RNR_TIMER =12
RETRY_CNT = 7
RNR_RETRY = 7
TIMEOUT = 14
# Devices that don't support RoCEv2 should be added here
MLNX_VENDOR_ID = 0x02c9
CX3_MLNX_PART_ID = 4099
CX3Pro_MLNX_PART_ID = 4103
DCT_KEY = 0xbadc0de
# Dictionary: vendor_id -> array of part_ids of devices that lack RoCEv2 support
ROCEV2_UNSUPPORTED_DEVS = {MLNX_VENDOR_ID: [CX3Pro_MLNX_PART_ID,
                                            CX3_MLNX_PART_ID]}


def has_roce_hw_bug(vendor_id, vendor_part_id):
    return vendor_part_id in ROCEV2_UNSUPPORTED_DEVS.get(vendor_id, [])


def set_rnr_attributes(qp_attr):
    """
    Set default QP RNR attributes.
    :param qp_attr: The QPAttr to set its attributes
    :return: None
    """
    qp_attr.min_rnr_timer = MIN_RNR_TIMER
    qp_attr.timeout = TIMEOUT
    qp_attr.retry_cnt = RETRY_CNT
    qp_attr.rnr_retry = RNR_RETRY


class PyverbsAPITestCase(unittest.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        # Hold the command line arguments
        self.config = parser.get_config()
        self.dev_name = None
        self.ctx = None
        self.attr = None
        self.attr_ex = None

    def setUp(self):
        """
        Opens the device and queries it.
        The results of the query and query_ex are stored in attr and attr_ex
        instance attributes respectively.
        If the user didn't pass a device name, the first device is chosen by
        default.
        """
        self.ib_port = self.config['port']
        self.dev_name = self.config['dev']
        if not self.dev_name:
            dev_list = d.get_device_list()
            if not dev_list:
                raise unittest.SkipTest('No IB devices found')
            self.dev_name = dev_list[0].name.decode()

        self.create_context()
        self.attr = self.ctx.query_device()
        self.attr_ex = self.ctx.query_device_ex()

    def create_context(self):
        self.ctx = d.Context(name=self.dev_name)

    def tearDown(self):
        self.ctx.close()


class RDMATestCase(unittest.TestCase):
    ZERO_GID = '0000:0000:0000:0000'

    def __init__(self, methodName='runTest', dev_name=None, ib_port=None,
                 gid_index=None, pkey_index=None, gid_type=None):
        """
        Initialize a RDMA test unit based on unittest.TestCase.
        If no device was provided, it iterates over the existing devices, for
        each port of each device, it checks which GID indexes are valid (in RoCE,
        only IPv4 and IPv6 based GIDs are used). Each <dev, port, gid> is added
        to an array and one entry is selected.
        If a device was provided, the same process is done for all ports of this
        device (in case they're not provided), and so on.
        If gid_type is provided by the user, only GIDs of that type would be
        be chosen (valid only if gid_index was not provided).
        :param methodName: The base method to be used by the unittest
        :param dev_name: Device name to use
        :param ib_port: IB port of the device to use
        :param gid_index: GID index to use
        :param pkey_index: PKEY index to use
        :param gid_type: If provided, only GIDs of gid_type will be chosen
                         (ignored if gid_index is provided by the user)
        """
        super(RDMATestCase, self).__init__(methodName)
        # Hold the command line arguments
        self.config = parser.get_config()
        dev = self.config['dev']
        self.dev_name = dev_name if dev_name else dev
        self.ib_port = ib_port if ib_port else self.config['port']
        self.gid_index = gid_index if gid_index else self.config['gid']
        self.pkey_index = pkey_index
        self.gid_type = gid_type if gid_index is None else None
        self.ip_addr = None
        self.mac_addr = None
        self.pre_environment = {}
        self.server = None
        self.client = None

    def set_env_variable(self, var, value):
        """
        Set environment variable. The current value for each variable is stored
        and is set back at the end of the test.
        :param var: The name of the environment variable
        :param value: The requested new value of this environment variable
        """
        if var not in self.pre_environment.keys():
            self.pre_environment[var] = os.environ.get(var)
        os.environ[var] = value

    def is_eth_and_has_roce_hw_bug(self):
        """
        Check if the link layer is Ethernet and the device lacks RoCEv2 support
        with a known HW bug.
        return: True if the link layer is Ethernet and device is not supported
        """
        ctx = d.Context(name=self.dev_name)
        port_attrs = ctx.query_port(self.ib_port)
        dev_attrs = ctx.query_device()
        vendor_id = dev_attrs.vendor_id
        vendor_pid = dev_attrs.vendor_part_id
        return port_attrs.link_layer == e.IBV_LINK_LAYER_ETHERNET and \
            has_roce_hw_bug(vendor_id, vendor_pid)

    @staticmethod
    def get_net_name(dev):
        out = subprocess.check_output(['ls',
                                       '/sys/class/infiniband/{}/device/net/'
                                      .format(dev)])
        return out.decode().split('\n')[0]

    @staticmethod
    def get_ip_mac_address(ifname):
        out = subprocess.check_output(['ip', '-j', 'addr', 'show', ifname])
        loaded_json = json.loads(out.decode())
        interface = loaded_json[0]['addr_info'][0]['local']
        mac = loaded_json[0]['address']
        if 'fe80::' in interface:
            interface = interface + '%' + ifname
        return interface, mac

    def setUp(self):
        """
        Verify that the test case has dev_name, ib_port, gid_index and pkey index.
        If not provided by the user, the first valid combination will be used.
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
                    self._get_ip_mac(self.dev_name, self.ib_port, self.gid_index)
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
            raise unittest.SkipTest('No supported port is up, can\'t run traffic')
        # Choose one combination and use it
        self._select_config()
        self.dev_info = {'dev_name': self.dev_name, 'ib_port': self.ib_port,
                         'gid_index': self.gid_index}

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
                    ctx.query_gid_type(port, idx) == \
                    e.IBV_GID_TYPE_SYSFS_ROCE_V2 and \
                    has_roce_hw_bug(vendor_id, vendor_pid):
                continue
            if self.gid_type is not None and ctx.query_gid_type(port, idx) != \
                    self.gid_type:
                continue
            self._get_ip_mac(dev, port, idx)

    def _add_gids_per_device(self, ctx, dev):
        self._add_gids_per_port(ctx, dev, self.ib_port)

    def _get_ip_mac(self, dev, port, idx):
        if not os.path.exists('/sys/class/infiniband/{}/device/net/'.format(dev)):
            self.args.append([dev, port, idx, None, None])
            return
        net_name = self.get_net_name(dev)
        try:
            ip_addr, mac_addr = self.get_ip_mac_address(net_name)
        except (KeyError, IndexError):
            self.args.append([dev, port, idx, None, None])
        else:
            self.args.append([dev, port, idx, ip_addr, mac_addr])

    def _select_config(self):
        args_with_inet_ip = []
        for arg in self.args:
            if arg[3]:
                args_with_inet_ip.append(arg)
        if args_with_inet_ip:
            args = args_with_inet_ip[0]
        else:
            args = self.args[0]
        self.dev_name = args[0]
        self.ib_port = args[1]
        self.gid_index = args[2]
        self.ip_addr = args[3]
        self.mac_addr = args[4]

    def set_env_variable(self, var, value):
        """
        Set environment variable. The current value for each variable is stored
        and is set back at the end of the test.
        :param var: The name of the environment variable
        :param value: The requested new value of this environment variable
        """
        if var not in self.pre_environment.keys():
            self.pre_environment[var] = os.environ.get(var)
        os.environ[var] = value

    def tearDown(self):
        """
        Restore the previous environment variables values before ending the test.
        """
        for k, v in self.pre_environment.items():
            if v is None:
                os.environ.pop(k)
            else:
                os.environ[k] = v
        if self.server:
            self.server.ctx.close()
        if self.client:
            self.client.ctx.close()
        super().tearDown()


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
        :param kwargs: Arguments to be passed to the connection_resources.
        :return: None
        """
        try:
            player = connection_resources(ip_addr=self.ip_addr,
                                          syncer=self.syncer,
                                          notifier=self.notifier,
                                          passive=passive, **kwargs)
            player.establish_connection()
            if kwargs.get('reject_conn'):
                return
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
        self.dev_name = dev_name
        self.gid_index = gid_index
        self.ib_port = ib_port
        self.create_context()
        self.create_pd()

    def create_context(self):
        self.ctx = Context(name=self.dev_name)

    def create_pd(self):
        self.pd = PD(self.ctx)


class TrafficResources(BaseResources):
    """
    Basic traffic class. It provides the basic RDMA resources and operations
    needed for traffic.
    """
    def __init__(self, dev_name, ib_port, gid_index, with_srq=False,
                 qp_count=1, msg_size=1024):
        """
        Initializes a TrafficResources object with the given values and creates
        basic RDMA resources.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param with_srq: If True, create SRQ and attach to QPs
        :param qp_count: Number of QPs to create
        :param msg_size: Size of resource msg. If None, use 1024 as default.
        """
        super(TrafficResources, self).__init__(dev_name=dev_name,
                                               ib_port=ib_port,
                                               gid_index=gid_index)
        self.msg_size = msg_size
        self.num_msgs = 1000
        self.port_attr = None
        self.mr = None
        self.use_mr_prefetch = None
        self.srq = None
        self.cq = None
        self.qps = []
        self.qps_num = []
        self.psns = []
        self.rqps_num = None
        self.rpsns = None
        self.with_srq = with_srq
        self.qp_count = qp_count
        self.init_resources()

    @property
    def qp(self):
        return self.qps[0]

    @property
    def mr_lkey(self):
        if self.mr:
            return self.mr.lkey

    def init_resources(self):
        """
        Initializes a CQ, MR and an RC QP.
        :return: None
        """
        self.port_attr = self.ctx.query_port(self.ib_port)
        if self.with_srq:
            self.create_srq()
        self.create_cq()
        self.create_mr()
        self.create_qps()

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

    def create_qp_cap(self):
        return QPCap(max_recv_wr=self.num_msgs)

    def create_qp_init_attr(self):
        return QPInitAttr(qp_type=e.IBV_QPT_RC, scq=self.cq, rcq=self.cq,
                          srq=self.srq, cap=self.create_qp_cap())

    def create_qp_attr(self):
        return QPAttr(port_num=self.ib_port)

    def create_qps(self):
        """
        Initializes self.qps with RC QPs.
        :return: None
        """
        qp_init_attr = self.create_qp_init_attr()
        qp_attr = self.create_qp_attr()
        for _ in range(self.qp_count):
            try:
                qp = QP(self.pd, qp_init_attr, qp_attr)
                self.qps.append(qp)
                self.qps_num.append(qp.qp_num)
                self.psns.append(random.getrandbits(24))
            except PyverbsRDMAError as ex:
                if ex.error_code == errno.EOPNOTSUPP:
                    raise unittest.SkipTest(f'Create QP type {qp_init_attr.qp_type} is not supported')
                raise ex

    def create_srq_attr(self):
        return SrqAttr(max_wr=self.num_msgs*self.qp_count)

    def create_srq_init_attr(self):
        return SrqInitAttr(self.create_srq_attr())

    def create_srq(self):
        srq_init_attr = self.create_srq_init_attr()
        try:
            self.srq = SRQ(self.pd, srq_init_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create SRQ is not supported')
            raise ex

    def pre_run(self, rpsns, rqps_num):
        """
        Modify the QP's states to RTS and fill receive queue with <num_msgs> work
        requests.
        This method is not implemented in this class.
        :param rpsns: Remote PSNs
        :param rqps_num: Remote QPs Number
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
        attr = self.create_qp_attr()
        attr.path_mtu = PATH_MTU
        attr.max_dest_rd_atomic = MAX_DEST_RD_ATOMIC
        set_rnr_attributes(attr)
        attr.max_rd_atomic = MAX_RD_ATOMIC
        gr = GlobalRoute(dgid=self.ctx.query_gid(self.ib_port, self.gid_index),
                         sgid_index=self.gid_index)
        ah_attr = AHAttr(port_num=self.ib_port, is_global=1, gr=gr,
                         dlid=self.port_attr.lid)
        attr.ah_attr = ah_attr
        for i in range(self.qp_count):
            attr.dest_qp_num = self.rqps_num[i]
            attr.rq_psn = self.psns[i]
            attr.sq_psn = self.rpsns[i]
            self.qps[i].to_rts(attr)

    def pre_run(self, rpsns, rqps_num):
        """
        Configure Resources before running traffic
        :param rpsns: Remote PSNs (packet serial number)
        :param rqps_num: Remote QPs number
        :return: None
        """
        self.rpsns = rpsns
        self.rqps_num = rqps_num
        self.to_rts()


class UDResources(TrafficResources):
    UD_QKEY = 0x11111111
    UD_PKEY_INDEX = 0
    GRH_SIZE = 40

    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size + self.GRH_SIZE,
                     e.IBV_ACCESS_LOCAL_WRITE)

    def create_qp_init_attr(self):
        return QPInitAttr(qp_type=e.IBV_QPT_UD, scq=self.cq,
                          rcq=self.cq, srq=self.srq, cap=self.create_qp_cap())

    def create_qps(self):
        qp_init_attr = self.create_qp_init_attr()
        qp_attr = self.create_qp_attr()
        qp_attr.qkey = self.UD_QKEY
        qp_attr.pkey_index = self.UD_PKEY_INDEX
        for _ in range(self.qp_count):
            qp = QP(self.pd, qp_init_attr, qp_attr)
            self.qps.append(qp)
            self.qps_num.append(qp.qp_num)
            self.psns.append(random.getrandbits(24))

    def pre_run(self, rpsns, rqps_num):
        self.rpsns = rpsns
        self.rqps_num = rqps_num


class RawResources(TrafficResources):
    def create_qp_init_attr(self):
        return QPInitAttr(qp_type=e.IBV_QPT_RAW_PACKET, scq=self.cq,
                          rcq=self.cq, srq=self.srq, cap=self.create_qp_cap())


class XRCResources(TrafficResources):
    def __init__(self, dev_name, ib_port, gid_index, qp_count=2):
        self.temp_file = None
        self.xrcd_fd = -1
        self.xrcd = None
        self.sqp_lst = []
        self.rqp_lst = []
        super(XRCResources, self).__init__(dev_name, ib_port, gid_index,
                                           qp_count=qp_count)

    def close(self):
        os.close(self.xrcd_fd)
        self.temp_file.close()

    def create_qps(self):
        """
        Initializes self.qps with an XRC SEND/RECV QPs.
        :return: None
        """
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_attr.pkey_index = 0

        for _ in range(self.qp_count):
            attr_ex = QPInitAttrEx(qp_type=e.IBV_QPT_XRC_RECV,
                                   comp_mask=e.IBV_QP_INIT_ATTR_XRCD,
                                   xrcd=self.xrcd)
            qp_attr.qp_access_flags = e.IBV_ACCESS_LOCAL_WRITE | \
                                      e.IBV_ACCESS_REMOTE_READ | \
                                      e.IBV_ACCESS_REMOTE_WRITE | \
                                      e.IBV_ACCESS_REMOTE_ATOMIC
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
        qp_attr.max_rd_atomic = MAX_RD_ATOMIC
        qp_attr.max_dest_rd_atomic = MAX_DEST_RD_ATOMIC
        qp_attr.path_mtu = PATH_MTU
        set_rnr_attributes(qp_attr)
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
