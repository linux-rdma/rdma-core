import unittest
import random
import errno

from pyverbs.wq import WQInitAttr, WQAttr, WQ, RwqIndTableInitAttr, RwqIndTable, RxHashConf
from tests.utils import requires_root_on_eth, PacketConsts
from tests.base import RDMATestCase, PyverbsRDMAError, MLNX_VENDOR_ID, \
    CX3_MLNX_PART_ID, CX3Pro_MLNX_PART_ID
from pyverbs.qp import QPInitAttrEx, QPEx
from tests.test_flow import FlowRes
from pyverbs.flow import Flow
from pyverbs.cq import CQ
import pyverbs.enums as e
import tests.utils as u


WRS_PER_ROUND = 512
CQS_NUM = 2
TOEPLITZ_KEY_LEN = 40
HASH_KEY = [0x2c, 0xc6, 0x81, 0xd1, 0x5b, 0xdb, 0xf4, 0xf7,
            0xfc, 0xa2, 0x83, 0x19, 0xdb, 0x1a, 0x3e, 0x94,
            0x6b, 0x9e, 0x38, 0xd9, 0x2c, 0x9c, 0x03, 0xd1,
            0xad, 0x99, 0x44, 0xa7, 0xd9, 0x56, 0x3d, 0x59,
            0x06, 0x3c, 0x25, 0xf3, 0xfc, 0x1f, 0xdc, 0x2a]


def requires_indirection_table_support(func):
    def wrapper(instance):
        dev_attrs = instance.ctx.query_device()
        vendor_id = dev_attrs.vendor_id
        vendor_pid = dev_attrs.vendor_part_id
        if vendor_id == MLNX_VENDOR_ID and vendor_pid in [CX3_MLNX_PART_ID,
                                                          CX3Pro_MLNX_PART_ID]:
            raise unittest.SkipTest('WQN must be aligned with the Indirection Table size in CX3')
        return func(instance)
    return wrapper


class RssRes(FlowRes):
    def __init__(self, dev_name, ib_port, gid_index, log_ind_tbl_size=3):
        """
        Initialize rss resources based on Flow resources that include RSS Raw QP.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        """
        self.log_ind_tbl_size = log_ind_tbl_size
        self.wqs = []
        self.cqs = []
        self.ind_table = None
        super().__init__(dev_name=dev_name, ib_port=ib_port,
                         gid_index=gid_index)

    def create_cq(self):
        self.cqs = [CQ(self.ctx, WRS_PER_ROUND) for _ in range(CQS_NUM)]

    @requires_root_on_eth()
    def create_qps(self):
        """
        Initializes self.qps with RSS QPs.
        :return: None
        """
        qp_init_attr = self.create_qp_init_attr()
        for _ in range(self.qp_count):
            try:
                qp = QPEx(self.ctx, qp_init_attr)
                self.qps.append(qp)
                self.qps_num.append(qp.qp_num)
                self.psns.append(random.getrandbits(24))
            except PyverbsRDMAError as ex:
                if ex.error_code == errno.EOPNOTSUPP:
                    raise unittest.SkipTest(f'Create QPEx type {qp_init_attr.qp_type} is not '
                                            'supported')
                raise ex

    def create_qp_init_attr(self):
        self.create_ind_table()
        mask = e.IBV_QP_INIT_ATTR_CREATE_FLAGS | e.IBV_QP_INIT_ATTR_PD | \
                    e.IBV_QP_INIT_ATTR_RX_HASH | e.IBV_QP_INIT_ATTR_IND_TABLE
        return QPInitAttrEx(qp_type=e.IBV_QPT_RAW_PACKET, comp_mask=mask, pd=self.pd,
                            hash_conf=self.hash_conf, ind_table=self.ind_tbl)

    @requires_indirection_table_support
    def create_ind_table(self):
        self.ind_tbl = RwqIndTable(self.ctx, self.initiate_table_attr())
        self.hash_conf = self.init_rx_hash_config()

    def initiate_table_attr(self):
        self.create_wqs()
        return RwqIndTableInitAttr(self.log_ind_tbl_size, self.wqs)

    def create_wqs(self):
        wqias = [self.initiate_wq_attr(cq) for cq in self.cqs]
        for i in range(1 << self.log_ind_tbl_size):
            wq = WQ(self.ctx, wqias[i % CQS_NUM])
            wq.modify(WQAttr(attr_mask=e.IBV_WQ_ATTR_STATE, wq_state=e.IBV_WQS_RDY))
            self.wqs.append(wq)
        return self.wqs

    def initiate_wq_attr(self, cq):
        return WQInitAttr(wq_context=None, wq_pd=self.pd, wq_cq=cq, wq_type=e.IBV_WQT_RQ,
                          max_wr=WRS_PER_ROUND, max_sge=self.ctx.query_device().max_sge,
                          comp_mask=0, create_flags=0)

    def init_rx_hash_config(self):
        return RxHashConf(rx_hash_function=e.IBV_RX_HASH_FUNC_TOEPLITZ,
                          rx_hash_key_len=len(HASH_KEY),
                          rx_hash_key=HASH_KEY,
                          rx_hash_fields_mask=e.IBV_RX_HASH_DST_IPV4 | e.IBV_RX_HASH_SRC_IPV4)

    def _create_flow(self, flow_attr):
        return [Flow(qp, flow_attr) for qp in self.qps]


class RSSTrafficTest(RDMATestCase):
    """
    Test various functionalities of the RSS QPs.
    """
    def setUp(self):
        super().setUp()
        self.iters = 1
        self.server = None
        self.client = None

    def create_players(self):
        """
        Init RSS tests resources.
        RSS-QP can recive traffic only, so client will be based on Flow tests resources.
        """
        self.client = FlowRes(**self.dev_info)
        self.server = RssRes(**self.dev_info)

    def flow_traffic(self, specs, l3=PacketConsts.IP_V4,
                     l4=PacketConsts.UDP_PROTO):
        """
        Execute raw ethernet traffic with given specs flow.
        :param specs: List of flow specs to match on the QP
        :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
        :param l4: Packet layer 4 type: 'tcp' or 'udp'
        :return: None
        """
        self.flows = self.server.create_flow(specs)
        u.raw_rss_traffic(self.client, self.server, self.iters, l3, l4,
                          num_packets=32)

    def test_rss_traffic(self):
        self.create_players()
        self.flow_traffic([self.server.create_eth_spec()])
