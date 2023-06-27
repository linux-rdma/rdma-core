# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved. See COPYING file
"""
Test module for pyverbs' mlx5 dr module.
"""

import unittest
import os.path
import struct
import socket
import errno
import math

from pyverbs.providers.mlx5.dr_action import DrActionQp, DrActionModify, \
    DrActionFlowCounter, DrActionDrop, DrActionTag, DrActionDestTable, \
    DrActionPopVLan, DrActionPushVLan, DrActionDestAttr, DrActionDestArray, \
    DrActionDefMiss, DrActionVPort, DrActionIBPort, DrActionDestTir, DrActionPacketReformat,\
    DrFlowSamplerAttr, DrActionFlowSample
from pyverbs.providers.mlx5.mlx5dv import Mlx5DevxObj, Mlx5Context, Mlx5DVContextAttr
from tests.utils import skip_unsupported, requires_root_on_eth, requires_eswitch_on, \
    PacketConsts
from tests.mlx5_base import Mlx5RDMATestCase, PyverbsAPITestCase, MELLANOX_VENDOR_ID
from pyverbs.providers.mlx5.mlx5dv_flow import Mlx5FlowMatchParameters
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
from pyverbs.providers.mlx5.dr_matcher import DrMatcher
from pyverbs.providers.mlx5.dr_domain import DrDomain
from pyverbs.providers.mlx5.dr_table import DrTable
from pyverbs.providers.mlx5.dr_rule import DrRule
import pyverbs.providers.mlx5.mlx5_enums as dve

from tests.test_mlx5_flow import requires_reformat_support
from pyverbs.cq import CqInitAttrEx, CQEX, CQ
from pyverbs.wq import WQInitAttr, WQ, WQAttr
from tests.base import RawResources
import pyverbs.enums as e
import tests.utils as u

SET_ACTION = 0x1
MAX_MATCH_PARAM_SIZE = 0x180
PF_VPORT = 0x0
GENEVE_PACKET_OUTER_LENGTH = 50
ROCE_PACKET_OUTER_LENGTH = 58

SAMPLER_ERROR_MARGIN = 0.2
SAMPLE_RATIO = 4
REG_C_DATA = 0x1234


class ModifyFields:
    """
    Supported SW steering modify fields.
    """
    OUT_SMAC_47_16 = 0x1
    OUT_SMAC_15_0 = 0x2
    META_DATA_REG_C_0 = 0x51
    META_DATA_REG_C_1 = 0x52


class ModifyFieldsLen:
    """
    Supported SW steering modify fields length.
    """
    MAC_47_16 = 32
    MAC_15_0 = 16
    META_DATA_REG_C = 32


def skip_if_has_geneve_tx_bug(ctx):
    """
    Some mlx5 devices such as CX5 and CX6 has a bug matching on Geneve fields
    on TX side.
    Raises unittest.SkipTest if that's the case.
    :param ctx: Mlx5 Context
    """
    dev_attrs = ctx.query_device()
    mlx5_cx5_cx6 = [0x1017, 0x1018, 0x1019, 0x101a, 0x101b]
    if dev_attrs.vendor_id == MELLANOX_VENDOR_ID and \
            dev_attrs.vendor_part_id in mlx5_cx5_cx6:
        raise unittest.SkipTest('This test is not supported on cx5/6')


class Mlx5DrResources(RawResources):
    """
    Test various functionalities of the mlx5 direct rules class.
    """
    def create_context(self):
        mlx5dv_attr = Mlx5DVContextAttr()
        try:
            self.ctx = Mlx5Context(mlx5dv_attr, name=self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 context is not supported')

    def __init__(self, dev_name, ib_port, gid_index=0, wc_flags=0, msg_size=1024, qp_count=1):
        self.wc_flags = wc_flags
        super().__init__(dev_name=dev_name, ib_port=ib_port, gid_index=gid_index,
                         msg_size=msg_size, qp_count=qp_count)

    @requires_root_on_eth()
    def create_qps(self):
        super().create_qps()

    def create_cq(self):
        """
        Create an Extended CQ.
        """
        wc_flags = e.IBV_WC_STANDARD_FLAGS | self.wc_flags
        cia = CqInitAttrEx(cqe=self.num_msgs, wc_flags=wc_flags)
        try:
            self.cq = CQEX(self.ctx, cia)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create Extended CQ is not supported')
            raise ex


class Mlx5DrTirResources(Mlx5DrResources):
    def __init__(self, dev_name, ib_port, gid_index=0, wc_flags=0, msg_size=1024,
                 qp_count=1, server=False):
        self.server = server
        super().__init__(dev_name=dev_name, ib_port=ib_port, gid_index=gid_index,
                         wc_flags=wc_flags, msg_size=msg_size, qp_count=qp_count)

    def create_cq(self):
        self.cq = CQ(self.ctx, cqe=self.num_msgs)

    @requires_root_on_eth()
    def create_qps(self):
        if not self.server:
            super().create_qps()
        else:
            from tests.mlx5_prm_structs import Tirc, CreateTirIn, CreateTirOut
            self.qps = [WQ(self.ctx, WQInitAttr(wq_pd=self.pd, wq_cq=self.cq))]
            self.qps[0].modify(WQAttr(attr_mask=e.IBV_WQ_ATTR_STATE, wq_state=e.IBV_WQS_RDY))
            tir_ctx = Tirc(inline_rqn=self.qps[0].wqn)
            self.tir = Mlx5DevxObj(self.ctx, CreateTirIn(tir_context=tir_ctx), len(CreateTirOut()))


class Mlx5DrTest(Mlx5RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None
        self.rules = []

    def tearDown(self):
        if self.server:
            self.server.ctx.close()
        if self.client:
            self.client.ctx.close()

    @skip_unsupported
    def create_rx_recv_rules_based_on_match_params(self, mask_param, val_param, actions,
                                                   match_criteria=u.MatchCriteriaEnable.OUTER,
                                                   domain=None, log_matcher_size=None):
        """
        Creates a rule on RX domain that forwards packets that match on the provided parameters
        to the SW steering flow table and another rule on that table
        with provided actions.
        :param mask_param: The FlowTableEntryMatchParam mask matcher value.
        :param val_param: The FlowTableEntryMatchParam value matcher value.
        :param actions: List of actions to attach to the recv rule.
        :param match_criteria: the match criteria enable flag to match on
        :param domain: RX DR domain to use if provided, otherwise create default RX domain.
        :param log_matcher_size: Size of the matcher table
        :return: Non root table and dest table action to it
        """
        self.domain_rx = domain if domain else DrDomain(self.server.ctx,
                                                        dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        root_table = DrTable(self.domain_rx, 0)
        table = DrTable(self.domain_rx, 1)
        root_matcher = DrMatcher(root_table, 0, match_criteria, mask_param)
        self.matcher = DrMatcher(table, 1, match_criteria, mask_param)
        if log_matcher_size:
            self.matcher.set_layout(log_matcher_size)
        self.dest_table_action = DrActionDestTable(table)
        self.rules.append(DrRule(root_matcher, val_param, [self.dest_table_action]))
        self.rules.append(DrRule(self.matcher, val_param, actions))
        return table, self.dest_table_action

    @skip_unsupported
    def create_rx_recv_rules(self, smac_value, actions, log_matcher_size=None, domain=None):
        """
        Creates a rule on RX domain that forwards packets that match the smac in the matcher
        to the SW steering flow table and another rule on that table with provided actions.
        :param smac_value: The smac matcher value.
        :param actions: List of actions to attach to the recv rule.
        :param log_matcher_size: Size of the matcher table
        :param domain: RX DR domain to use if provided, otherwise create default RX domain.
        :return: Non root table and dest table action to it
        """
        smac_mask = bytes([0xff] * 6) + bytes(2)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        # Size of the matcher value should be modulo 4
        smac_value += bytes(2)
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        return self.create_rx_recv_rules_based_on_match_params(mask_param, value_param, actions,
                                                               u.MatchCriteriaEnable.OUTER,
                                                               domain, log_matcher_size)

    @skip_unsupported
    def create_tx_modify_rule(self):
        """
        Creares a rule on TX domain that modifies smac in the packet and sends
        it to the wire.
        """
        from tests.mlx5_prm_structs import SetActionIn
        self.domain_tx = DrDomain(self.client.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_TX)
        table = DrTable(self.domain_tx, 0)
        smac_mask = bytes([0xff] * 6)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        matcher = DrMatcher(table, 0, u.MatchCriteriaEnable.OUTER, mask_param)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        action1 = SetActionIn(action_type=SET_ACTION, field=ModifyFields.OUT_SMAC_47_16,
                              data=0x88888888, length=ModifyFieldsLen.MAC_47_16)
        action2 = SetActionIn(action_type=SET_ACTION, field=ModifyFields.OUT_SMAC_15_0,
                              data=0x8888, length=ModifyFieldsLen.MAC_15_0)
        self.modify_actions = DrActionModify(self.domain_tx, dve.MLX5DV_DR_ACTION_FLAGS_ROOT_LEVEL,
                                             [action1, action2])
        self.rules.append(DrRule(matcher, value_param, [self.modify_actions]))

    @skip_unsupported
    def create_client_send_rule(self, actions):
        """
        Create rule over the client TX domain.
        :param actions: List of actions to attach to the send rule.
        """
        self.domain_tx = DrDomain(self.client.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_TX)
        table = DrTable(self.domain_tx, 0)
        mask_param = Mlx5FlowMatchParameters(len(bytes([0xff] * 6)), bytes([0xff] * 6))
        matcher = DrMatcher(table, 0, u.MatchCriteriaEnable.OUTER, mask_param)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        self.rules.append(DrRule(matcher, value_param, actions))

    def send_client_raw_packets(self, iters, src_mac=None):
        """
        Send raw packets.
        :param iters: Number of packets to send.
        :param src_mac: If set, src mac to set in the packets.
        """
        c_send_wr, _, _ = u.get_send_elements_raw_qp(self.client, src_mac=src_mac)
        poll_cq = u.poll_cq_ex if isinstance(self.client.cq, CQEX) else u.poll_cq
        for _ in range(iters):
            u.send(self.client, c_send_wr, e.IBV_WR_SEND)
            poll_cq(self.client.cq)

    def send_server_fdb_to_nic_packets(self, iters):
        """
        Server sends and receives raw packets.
        :param iters: Number of packets to send.
        """
        s_recv_wr = u.get_recv_wr(self.server)
        u.post_recv(self.server, s_recv_wr, qp_idx=0)
        c_send_wr, _, msg = u.get_send_elements_raw_qp(self.server)
        for _ in range(iters):
            u.send(self.server, c_send_wr, e.IBV_WR_SEND)
            u.poll_cq_ex(self.server.cq)
            u.poll_cq_ex(self.server.cq)
            u.post_recv(self.server, s_recv_wr, qp_idx=0)
            msg_received = self.server.mr.read(self.server.msg_size, 0)
            u.validate_raw(msg_received, msg, [])

    def dest_port(self, is_vport=True):
        """
        Creates FDB domain, root table with matcher on source mac on the server
        side. Create a rule to forward all traffic to the non-root table.
        On this table apply VPort/IBPort action goto PF.
        On the server open another RX domain on PF with QP action and validate
        packets by sending traffic from client, catch all traffic with
        VPort/IBPort action goto PF, open another RX domain on PF with QP
        action and validate packets.
        :param is_vport: A flag to indicate if to use VPort or IBPort action.
        """
        self.client = Mlx5DrResources(**self.dev_info)
        self.server = Mlx5DrResources(**self.dev_info)
        self.domain_fdb = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_FDB)
        port_action = DrActionVPort(self.domain_fdb, PF_VPORT) if is_vport \
            else DrActionIBPort(self.domain_fdb, self.ib_port)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.fdb_table, self.fdb_dest_act = self.create_rx_recv_rules(smac_value, [port_action],
                                                                      domain=self.domain_fdb)
        self.domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        rx_table = DrTable(self.domain_rx, 0)
        qp_action = DrActionQp(self.server.qp)
        smac_mask = bytes([0xff] * 6)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        rx_matcher = DrMatcher(rx_table, 0, u.MatchCriteriaEnable.OUTER, mask_param)
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        self.rules.append(DrRule(rx_matcher, value_param, [qp_action]))
        # Validate traffic on RX
        u.raw_traffic(self.client, self.server, self.iters)

    @staticmethod
    def create_dest_mac_params():
        from tests.mlx5_prm_structs import FlowTableEntryMatchParam

        eth_match_mask = FlowTableEntryMatchParam()
        eth_match_mask.outer_headers.dmac = PacketConsts.MAC_MASK
        eth_match_value = FlowTableEntryMatchParam()
        eth_match_value.outer_headers.dmac = PacketConsts.DST_MAC
        mask_param = Mlx5FlowMatchParameters(len(eth_match_mask), eth_match_mask)
        value_param = Mlx5FlowMatchParameters(len(eth_match_value), eth_match_value)
        return mask_param, value_param

    @staticmethod
    def create_counter(ctx):
        """
        Create flow counter.
        :param ctx: The player context to create the counter on.
        :return: The counter object and the flow counter ID .
        """
        from tests.mlx5_prm_structs import AllocFlowCounterIn, AllocFlowCounterOut
        counter = Mlx5DevxObj(ctx, AllocFlowCounterIn(), len(AllocFlowCounterOut()))
        flow_counter_id = AllocFlowCounterOut(counter.out_view).flow_counter_id
        return counter, flow_counter_id

    @staticmethod
    def query_counter_packets(counter, flow_counter_id):
        """
        Query flow counter packets count.
        :param counter: The counter for the query.
        :param flow_counter_id: The flow counter ID for the query.
        :return: Number of packets on this counter.
        """
        from tests.mlx5_prm_structs import QueryFlowCounterIn, QueryFlowCounterOut
        query_in = QueryFlowCounterIn(flow_counter_id=flow_counter_id)
        counter_out = QueryFlowCounterOut(counter.query(query_in, len(QueryFlowCounterOut())))
        return counter_out.flow_statistics.packets

    @staticmethod
    def gen_gre_tunnel_encap_header(msg_size, is_l2_tunnel=True):
        gre_ether_type = PacketConsts.ETHER_TYPE_ETH if is_l2_tunnel else \
                PacketConsts.ETHER_TYPE_IPV4
        gre_header = u.gen_gre_header(ether_type=gre_ether_type)
        ip_header = u.gen_ipv4_header(packet_len=msg_size + len(gre_header),
                                      next_proto=socket.IPPROTO_GRE)
        mac_header = u.gen_ethernet_header()
        return mac_header + ip_header + gre_header

    @staticmethod
    def gen_geneve_tunnel_encap_header(msg_size, is_l2_tunnel=True):
        proto = PacketConsts.ETHER_TYPE_ETH if is_l2_tunnel else PacketConsts.ETHER_TYPE_IPV4
        geneve_header = u.gen_geneve_header(proto=proto)
        udp_header = u.gen_udp_header(packet_len=msg_size + len(geneve_header),
                                      dst_port=PacketConsts.GENEVE_PORT)
        ip_header = u.gen_ipv4_header(packet_len=msg_size + len(udp_header) + len(geneve_header))
        mac_header = u.gen_ethernet_header()
        return mac_header + ip_header + udp_header + geneve_header

    @staticmethod
    def create_geneve_params():
        from tests.mlx5_prm_structs import FlowTableEntryMatchParam
        geneve_mask = FlowTableEntryMatchParam()
        geneve_mask.misc_parameters.geneve_vni = 0xffffff
        geneve_mask.misc_parameters.geneve_oam = 1
        geneve_value = FlowTableEntryMatchParam()
        geneve_value.misc_parameters.geneve_vni = PacketConsts.GENEVE_VNI
        geneve_value.misc_parameters.geneve_oam = PacketConsts.GENEVE_OAM
        mask_param = Mlx5FlowMatchParameters(len(geneve_mask), geneve_mask)
        value_param = Mlx5FlowMatchParameters(len(geneve_value), geneve_value)
        return mask_param, value_param

    @staticmethod
    def gen_roce_bth_header(msg_size):
        mac_header = u.gen_ethernet_header()
        ip_header = u.gen_ipv4_header(packet_len=msg_size + PacketConsts.UDP_HEADER_SIZE +
                                      PacketConsts.BTH_HEADER_SIZE)
        udp_header = u.gen_udp_header(packet_len=msg_size + PacketConsts.BTH_HEADER_SIZE,
                                      dst_port=PacketConsts.ROCE_PORT)
        bth_header = u.gen_bth_header()
        return mac_header + ip_header + udp_header + bth_header

    @staticmethod
    def create_roce_bth_params():
        from tests.mlx5_prm_structs import FlowTableEntryMatchParam
        roce_mask = FlowTableEntryMatchParam()
        roce_mask.misc_parameters.bth_opcode = 0xff
        roce_mask.misc_parameters.bth_dst_qp = 0xffffff
        roce_mask.misc_parameters.bth_a = 0x1
        roce_value = FlowTableEntryMatchParam()
        roce_value.misc_parameters.bth_opcode = PacketConsts.BTH_OPCODE
        roce_value.misc_parameters.bth_dst_qp = PacketConsts.BTH_DST_QP
        roce_value.misc_parameters.bth_a = PacketConsts.BTH_A
        mask_param = Mlx5FlowMatchParameters(len(roce_mask), roce_mask)
        value_param = Mlx5FlowMatchParameters(len(roce_value), roce_value)
        return mask_param, value_param

    def create_empty_matcher_go_to_tbl(self, src_tbl, dst_tbl):
        """
        Create rule that forward all packets (by empty matcher) from src_tbl to
        dst_tbl.
        """
        from tests.mlx5_prm_structs import FlowTableEntryMatchParam

        empty_param = Mlx5FlowMatchParameters(len(FlowTableEntryMatchParam()),
                                              FlowTableEntryMatchParam())
        matcher = DrMatcher(src_tbl, 0, u.MatchCriteriaEnable.NONE, empty_param)
        go_to_tbl_action = DrActionDestTable(dst_tbl)
        self.rules.append(DrRule(matcher, empty_param, [go_to_tbl_action]))
        return go_to_tbl_action

    @requires_eswitch_on
    @skip_unsupported
    def test_dest_vport(self):
        self.dest_port()

    @requires_eswitch_on
    @skip_unsupported
    def test_dest_ib_port(self):
        self.dest_port(False)

    @skip_unsupported
    def test_tbl_qp_rule(self):
        """
        Creates RX domain, SW table with matcher on source mac. Creates QP action
        and a rule with this action on the matcher.
        """
        self.create_players(Mlx5DrResources)
        self.qp_action = DrActionQp(self.server.qp)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.create_rx_recv_rules(smac_value, [self.qp_action])
        u.raw_traffic(self.client, self.server, self.iters)

    @skip_unsupported
    def test_tbl_modify_header_rule(self):
        """
        Creates TX domain, SW table with matcher on source mac and modify the smac.
        Then creates RX domain and rule that forwards packets with the new smac
        to server QP. Perform traffic that do this flow.
        """
        self.create_players(Mlx5DrResources)
        self.create_tx_modify_rule()
        src_mac = struct.pack('!6s', bytes.fromhex("88:88:88:88:88:88".replace(':', '')))
        self.qp_action = DrActionQp(self.server.qp)
        self.create_rx_recv_rules(src_mac, [self.qp_action])
        exp_packet = u.gen_packet(self.client.msg_size, src_mac=src_mac)
        u.raw_traffic(self.client, self.server, self.iters, expected_packet=exp_packet)

    @skip_unsupported
    def test_metadata_modify_action_set_copy_match(self):
        """
        Verify modify header with set and copy actions.
        TX and RX:
        - Root table:
            Match empty (hit all):
                Rule: prio 0 - val empty. Action: Go TO Table 1
        - Table 1:
            Match empty (hit all):
                Rule: prio 0 - val empty. Action: Modify Header (set reg_c_0 to REG_C_DATA)
                                                     + Go TO Table 2
        - Table 2:
            Match empty (hit all):
                Rule: prio 0 - val empty. Action: Modify Header (copy reg_c_0 to reg_c_1)
                                                  + Go To Table 3
        TX:
        - Table 3:
            Match reg_c_0 and reg_c_1:
                Rule: prio 0 - val REG_C_DATA. Action: Counter
        RX:
        - Table 3:
            Match reg_c_0 and reg_c_1:
                Rule: prio 0 - val REG_C_DATA. Action: Go To QP
        """
        from tests.mlx5_prm_structs import FlowTableEntryMatchParam, FlowTableEntryMatchSetMisc2, \
            SetActionIn, CopyActionIn

        self.create_players(Mlx5DrResources)
        match_param = FlowTableEntryMatchParam()
        empty_param = Mlx5FlowMatchParameters(len(match_param), match_param)
        mask_metadata = FlowTableEntryMatchParam(misc_parameters_2=
                FlowTableEntryMatchSetMisc2(metadata_reg_c_0=0xffff, metadata_reg_c_1=0xffff))
        mask_param = Mlx5FlowMatchParameters(len(match_param), mask_metadata)
        value_metadata = FlowTableEntryMatchParam(misc_parameters_2=
                FlowTableEntryMatchSetMisc2(metadata_reg_c_0=REG_C_DATA,
                                            metadata_reg_c_1=REG_C_DATA))
        value_param = Mlx5FlowMatchParameters(len(match_param), value_metadata)
        self.client.domain = DrDomain(self.client.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_TX)
        self.server.domain = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        for player in [self.client, self.server]:
            player.tables = []
            player.matchers = []
            for i in range(4):
                player.tables.append(DrTable(player.domain, i))
            for i in range(2):
                player.matchers.append(DrMatcher(player.tables[i + 1], 0,
                                                 u.MatchCriteriaEnable.NONE, empty_param))
            player.matchers.append(DrMatcher(player.tables[3], 0,
                                             u.MatchCriteriaEnable.MISC_2, mask_param))
            player.go_to_tbl1_action = self.create_empty_matcher_go_to_tbl(player.tables[0],
                                                                           player.tables[1])
            set_reg = SetActionIn(field=ModifyFields.META_DATA_REG_C_0,
                                  length=ModifyFieldsLen.META_DATA_REG_C, data=REG_C_DATA)
            player.modify_action_set = DrActionModify(player.domain, 0, [set_reg])
            player.go_to_tbl2_action = DrActionDestTable(player.tables[2])
            self.rules.append(DrRule(player.matchers[0], empty_param, [player.modify_action_set,
                                                                       player.go_to_tbl2_action]))
            copy_reg = CopyActionIn(src_field=ModifyFields.META_DATA_REG_C_0,
                                    length=ModifyFields.META_DATA_REG_C_0,
                                    dst_field=ModifyFields.META_DATA_REG_C_1)
            player.modify_action_copy = DrActionModify(player.domain, 0, [copy_reg])
            player.go_to_tbl3_action = DrActionDestTable(player.tables[3])
            self.rules.append(DrRule(player.matchers[1], empty_param, [player.modify_action_copy,
                                                                       player.go_to_tbl3_action]))
        counter, flow_counter_id = self.create_counter(self.client.ctx)
        counter_action = DrActionFlowCounter(counter)
        self.rules.append(DrRule(self.client.matchers[2], value_param, [counter_action]))
        qp_action = DrActionQp(self.server.qp)
        self.rules.append(DrRule(self.server.matchers[2], value_param, [qp_action]))
        u.raw_traffic(self.client, self.server, self.iters)
        sent_packets = self.query_counter_packets(counter, flow_counter_id)
        self.assertEqual(sent_packets, self.iters, 'Counter of metadata missed some sent packets')

    @skip_unsupported
    def test_tbl_counter_action(self):
        """
        Create flow counter object, attach it to a rule using counter action
        and perform traffic that hit this rule. Verify that the counter packets
        increased.
        """
        self.create_players(Mlx5DrResources)
        counter, flow_counter_id = self.create_counter(self.server.ctx)
        self.server_counter_action = DrActionFlowCounter(counter)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.qp_action = DrActionQp(self.server.qp)
        self.create_rx_recv_rules(smac_value, [self.qp_action, self.server_counter_action])
        u.raw_traffic(self.client, self.server, self.iters)
        recv_packets = self.query_counter_packets(counter, flow_counter_id)
        self.assertEqual(recv_packets, self.iters, 'Counter missed some recv packets')

    @skip_unsupported
    def test_prevent_duplicate_rule(self):
        """
        Creates RX domain, sets duplicate rule to be not allowed on that domain,
        try creating duplicate rule. Fail if creation succeeded.
        """
        from tests.mlx5_prm_structs import FlowTableEntryMatchParam

        self.server = Mlx5DrResources(**self.dev_info)
        domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        domain_rx.allow_duplicate_rules(False)
        table = DrTable(domain_rx, 1)
        empty_param = Mlx5FlowMatchParameters(len(FlowTableEntryMatchParam()),
                                              FlowTableEntryMatchParam())
        matcher = DrMatcher(table, 0, u.MatchCriteriaEnable.NONE, empty_param)
        self.qp_action = DrActionQp(self.server.qp)
        self.drop_action = DrActionDrop()
        self.rules.append(DrRule(matcher, empty_param, [self.qp_action]))
        with self.assertRaises(PyverbsRDMAError) as ex:
            self.rules.append(DrRule(matcher, empty_param, [self.drop_action]))
            self.assertEqual(ex.exception.error_code, errno.EEXIST)

    @skip_unsupported
    def test_root_tbl_drop_action(self):
        """
        Create drop action on TX and verify using counter on the server RX that
        only packets that miss the drop rule arrived to the server RX.
        """
        self.create_players(Mlx5DrResources)
        # Create server counter.
        counter, flow_counter_id = self.create_counter(self.server.ctx)
        self.server_counter_action = DrActionFlowCounter(counter)

        # Create rule that attaches all the packets in the server RX, sends them
        # to the server RX domain and counts them.
        domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        table = DrTable(domain_rx, 0)
        mask_param, value_param = self.create_dest_mac_params()
        matcher = DrMatcher(table, 0, u.MatchCriteriaEnable.OUTER, mask_param)
        self.rx_drop_action = DrActionDrop()
        self.rules.append(DrRule(matcher, value_param, [self.server_counter_action,
                                                        self.rx_drop_action]))

        # Create drop action on the client TX on specific smac.
        self.tx_drop_action = DrActionDrop()
        self.create_client_send_rule([self.tx_drop_action])

        # Send packets with two differet smacs and expect half to be dropped.
        src_mac_drop = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        src_mac_non_drop = struct.pack('!6s', bytes.fromhex("88:88:88:88:88:88".replace(':', '')))
        self.send_client_raw_packets(int(self.iters/2), src_mac=src_mac_drop)
        recv_packets = self.query_counter_packets(counter, flow_counter_id)
        self.assertEqual(recv_packets, 0, 'Drop action did not drop the TX packets')
        self.send_client_raw_packets(int(self.iters/2), src_mac=src_mac_non_drop)
        recv_packets = self.query_counter_packets(counter, flow_counter_id)
        self.assertEqual(recv_packets, int(self.iters/2),
                         'Drop action dropped TX packets that not matched the rule')

    @skip_unsupported
    def test_tbl_qp_tag_rule(self):
        """
        Creates RX domain, table with matcher on source mac. Creates QP action
        and tag action. Creates a rule with those actions on the matcher.
        Verifies traffic and tag.
        """
        self.wc_flags = e.IBV_WC_EX_WITH_FLOW_TAG
        self.create_players(Mlx5DrResources,  wc_flags=e.IBV_WC_EX_WITH_FLOW_TAG)
        qp_action = DrActionQp(self.server.qp)
        tag = 0x123
        tag_action = DrActionTag(tag)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.create_rx_recv_rules(smac_value, [tag_action, qp_action])
        self.domain_rx.sync()
        u.raw_traffic(self.client, self.server, self.iters)
        # Verify tag
        self.assertEqual(self.server.cq.read_flow_tag(), tag, 'Wrong tag value')

    @skip_unsupported
    def test_set_matcher_layout(self):
        """
        Creates a non root matcher and sets its size. Creates a rule on that
        matcher and increases the matcher size. Verifies the rule.
        """
        log_matcher_size = 5
        self.create_players(Mlx5DrResources)
        self.qp_action = DrActionQp(self.server.qp)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.create_rx_recv_rules(smac_value, [self.qp_action], log_matcher_size)
        self.matcher.set_layout(log_matcher_size + 1)
        u.raw_traffic(self.client, self.server, self.iters)
        self.matcher.set_layout(flags=dve.MLX5DV_DR_MATCHER_LAYOUT_RESIZABLE)
        u.raw_traffic(self.client, self.server, self.iters)

    @skip_unsupported
    def test_push_vlan(self):
        """
        Creates RX domain, root table with matcher on source mac. Create a rule to forward
        all traffic to the non-root table. Creates QP action and push VLAN action.
        Creates a rule with those actions on the matcher.
        Verifies traffic and packet with specified VLAN.
        """
        self.client = Mlx5DrResources(**self.dev_info)
        vlan_hdr = struct.pack('!HH', PacketConsts.VLAN_TPID, (PacketConsts.VLAN_PRIO << 13) +
                               (PacketConsts.VLAN_CFI << 12) + PacketConsts.VLAN_ID)
        self.server = Mlx5DrResources(msg_size=self.client.msg_size + PacketConsts.VLAN_HEADER_SIZE,
                                      **self.dev_info)
        self.domain_tx = DrDomain(self.client.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_TX)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        push_action = DrActionPushVLan(self.domain_tx, struct.unpack('I', vlan_hdr)[0])
        self.tx_table, self.tx_dest_act = self.create_rx_recv_rules(smac_value, [push_action],
                                                                    domain=self.domain_tx)
        self.domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        qp_action = DrActionQp(self.server.qp)
        self.create_rx_recv_rules(smac_value, [qp_action], domain=self.domain_rx)
        exp_packet = u.gen_packet(self.client.msg_size + PacketConsts.VLAN_HEADER_SIZE,
                                  with_vlan=True)
        u.raw_traffic(self.client, self.server, self.iters, expected_packet=exp_packet)

    @skip_unsupported
    def test_pop_vlan(self):
        """
        Creates RX domain, root table with matcher on source mac. Create a rule to forward
        all traffic to the non-root table. Creates QP action and pop VLAN action.
        Creates a rule with those actions on the matcher.
        Verifies packets received without VLAN header.
        """
        self.server = Mlx5DrResources(**self.dev_info)
        self.client = Mlx5DrResources(**self.dev_info)
        exp_packet = u.gen_packet(self.server.msg_size - PacketConsts.VLAN_HEADER_SIZE)
        qp_action = DrActionQp(self.server.qp)
        pop_action = DrActionPopVLan()
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.create_rx_recv_rules(smac_value, [pop_action, qp_action])
        u.raw_traffic(self.client, self.server, self.iters, with_vlan=True, expected_packet=exp_packet)

    @skip_unsupported
    def test_dest_array(self):
        """
        Creates RX domain, root table with matcher on source mac. Create a rule
        to forward all traffic to the non-root table. On this table add a rule
        with multi dest array action which include destination QP actions and
        next FT (also with QP action).
        Validate on all QPs the received packets.
        """
        max_actions = 8
        self.client = Mlx5DrResources(qp_count=max_actions, **self.dev_info)
        self.server = Mlx5DrResources(qp_count=max_actions, **self.dev_info)
        self.domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        actions = []
        dest_attrs = []
        for qp in self.server.qps[:-1]:
            qp_action = DrActionQp(qp)
            actions.append(qp_action)
            dest_attrs.append(DrActionDestAttr(dve.MLX5DV_DR_ACTION_DEST, qp_action))
        ft_action = DrTable(self.domain_rx, 0xff)
        last_table_action = DrActionDestTable(ft_action)
        smac_mask = bytes([0xff] * 6) + bytes(2)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        last_matcher = DrMatcher(ft_action, 1, u.MatchCriteriaEnable.OUTER, mask_param)
        dest_attrs.append(DrActionDestAttr(dve.MLX5DV_DR_ACTION_DEST, last_table_action))
        last_qp_action = DrActionQp(self.server.qps[max_actions - 1])
        smac_value = struct.pack('!6s2s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')),
                                 bytes(2))
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        self.rules.append(DrRule(last_matcher, value_param, [last_qp_action]))
        multi_dest_a = DrActionDestArray(self.domain_rx, len(dest_attrs), dest_attrs)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.create_rx_recv_rules(smac_value, [multi_dest_a], domain=self.domain_rx)
        u.raw_traffic(self.client, self.server, self.iters)

    @skip_unsupported
    def test_tx_def_miss_action(self):
        """
        Create TX root table and forward all traffic to next SW steering table,
        create two matchers with different priorities, one with default miss
        action (on TX it's go to wire action) and one with drop action, default
        miss action should occur before the drop action hence packets
        should reach server side which has RX rule with QP action.
        """
        self.create_players(Mlx5DrResources)
        self.domain_tx = DrDomain(self.client.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_TX)
        tx_def_miss = DrActionDefMiss()
        tx_drop_action = DrActionDrop()
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.tx_table, self.tx_dest_act = self.create_rx_recv_rules(smac_value, [tx_def_miss],
                                                                    domain=self.domain_tx)
        qp_action = DrActionQp(self.server.qp)
        self.create_rx_recv_rules(smac_value, [qp_action])
        smac_mask = bytes([0xff] * 6) + bytes(2)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        matcher_tx2 = DrMatcher(self.tx_table, 2, u.MatchCriteriaEnable.OUTER, mask_param)
        smac_value += bytes(2)
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        self.rules.append(DrRule(matcher_tx2, value_param, [tx_drop_action]))
        u.raw_traffic(self.client, self.server, self.iters)

    @skip_unsupported
    def test_dest_tir(self):
        self.client = Mlx5DrTirResources(**self.dev_info)
        self.server = Mlx5DrTirResources(**self.dev_info, server=True)
        tir_action = DrActionDestTir(self.server.tir)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.create_rx_recv_rules(smac_value, [tir_action])
        u.raw_traffic(self.client, self.server, self.iters)

    def packet_reformat_actions(self, outer, root_only=False, l2_ref_type=True):
        """
        Creates packet reformat actions on TX (encap) and on RX (decap).
        :param outer: The outer header to encap.
        :param root_only: If True create actions only on root tables
        :param l2_ref_type: If False use L2 to L3 tunneling reformat
        """
        smac_mask = bytes([0xff] * 6) + bytes(2)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        reformat_flag = dve.MLX5DV_DR_ACTION_FLAGS_ROOT_LEVEL if root_only else 0
        # TX
        domain_tx = DrDomain(self.client.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_TX)
        tx_root_table = DrTable(domain_tx, 0)
        tx_root_matcher = DrMatcher(tx_root_table, 0, u.MatchCriteriaEnable.OUTER, mask_param)
        if not root_only:
            tx_table = DrTable(domain_tx, 1)
            tx_matcher = DrMatcher(tx_table, 1, u.MatchCriteriaEnable.OUTER, mask_param)
            dest_table_action_tx = DrActionDestTable(tx_table)
            self.rules.append(DrRule(tx_root_matcher, value_param, [dest_table_action_tx]))
        reformat_matcher = tx_root_matcher if root_only else tx_matcher
        # Create encap action
        tx_reformat_type = dve.MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL_ if \
            l2_ref_type else dve.MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL_
        reformat_action_tx = DrActionPacketReformat(domain=domain_tx, flags=reformat_flag,
                                                    reformat_type=tx_reformat_type, data=outer)
        smac_value_tx = smac_value + bytes(2)
        value_param = Mlx5FlowMatchParameters(len(smac_value_tx), smac_value_tx)
        self.rules.append(DrRule(reformat_matcher, value_param, [reformat_action_tx]))
        # RX
        domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        # Create decap action
        data = struct.pack('!6s6s',
                           bytes.fromhex(PacketConsts.DST_MAC.replace(':', '')),
                           bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        data += PacketConsts.ETHER_TYPE_IPV4.to_bytes(2, 'big')
        rx_reformat_type = dve.MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2_ if \
            l2_ref_type else dve.MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2_
        reformat_action_rx = DrActionPacketReformat(domain=domain_rx, flags=reformat_flag,
                                                    reformat_type=rx_reformat_type,
                                                    data=None if l2_ref_type else data)
        qp_action = DrActionQp(self.server.qp)
        if root_only:
            rx_root_table = DrTable(domain_rx, 0)
            rx_root_matcher = DrMatcher(rx_root_table, 0, u.MatchCriteriaEnable.OUTER, mask_param)
            self.rules.append(DrRule(rx_root_matcher, value_param, [reformat_action_rx, qp_action]))
        else:
            self.create_rx_recv_rules(smac_value, [reformat_action_rx, qp_action], domain=domain_rx)

        # Send traffic and validate packet
        u.raw_traffic(self.client, self.server, self.iters)

    @skip_unsupported
    def test_flow_sampler(self):
        """
        Flow sampler has a default table (all the packets are forwarded to it)
        and a sampler actions (for sampled packets)
        The default table has counter action.
        For NIC RX table sampler actions are counter and TIR.
        Verify that default counter counts all the packets.
        Verify that sampled packets counter and receiving them on QP(from TIR)
        """
        self.client = Mlx5DrTirResources(**self.dev_info)
        self.server = Mlx5DrTirResources(**self.dev_info, server=True)
        self.iters = 1000
        # Create tir & counter actions for sampler attr
        tir_action = DrActionDestTir(self.server.tir)
        counter_1, flow_counter_id_1 = self.create_counter(self.server.ctx)
        self.server_counter_action = DrActionFlowCounter(counter_1)
        # Create resources
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        rx_domain = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        default_tbl = DrTable(rx_domain, 2)
        # Create sampler action on NIC RX table
        sample_actions = [self.server_counter_action, tir_action]
        sampler_attr = DrFlowSamplerAttr(sample_ratio=SAMPLE_RATIO, default_next_table=default_tbl,
                                         sample_actions=sample_actions)
        sampler_action = DrActionFlowSample(sampler_attr)
        tbl, _ = self.create_rx_recv_rules(smac_value, [sampler_action], domain=rx_domain)
        smac_mask = bytes([0xff] * 6) + bytes(2)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        self.default_matcher = DrMatcher(default_tbl, 1, u.MatchCriteriaEnable.OUTER, mask_param)
        # Size of the matcher value should be modulo 4
        smac_value += bytes(2)
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        # Create Counter action on default table
        counter_2, flow_counter_id_2 = self.create_counter(self.server.ctx)
        self.server_counter_action_2 = DrActionFlowCounter(counter_2)
        self.rules.append(DrRule(self.default_matcher, value_param, [self.server_counter_action_2]))
        # Send traffic and validate packet
        u.sampler_traffic(self.client, self.server, self.iters)
        recv_packets = self.query_counter_packets(counter=counter_1,
                                                  flow_counter_id=flow_counter_id_1)
        exp_packets = math.ceil((self.iters / SAMPLE_RATIO))
        max_exp_packets = int(exp_packets * (1 + SAMPLER_ERROR_MARGIN))
        min_exp_packets = int(exp_packets * (1 - SAMPLER_ERROR_MARGIN))
        is_sampled_packets_in_error_margin = min_exp_packets <= recv_packets <= max_exp_packets
        self.assertTrue(is_sampled_packets_in_error_margin,
                        f'Expected sampled packets {exp_packets} is more than '
                        f'{SAMPLER_ERROR_MARGIN * 100}% \ndiffernt from actual {recv_packets}')
        recv_packets_from_default_tbl = \
            self.query_counter_packets(counter=counter_2, flow_counter_id=flow_counter_id_2)
        self.assertEqual(recv_packets_from_default_tbl, self.iters,
                         'Counter on default table missed some recv packets')

    @skip_unsupported
    def test_geneve_match_rx(self):
        """
        Creates matcher on RX to match on Geneve related fields with counter and qp action,
        sends packets and verifies the matcher.
        """
        self.create_players(Mlx5DrResources)
        geneve_mask, geneve_val = self.create_geneve_params()
        domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        counter, flow_counter_id = self.create_counter(self.server.ctx)
        self.server_counter_action = DrActionFlowCounter(counter)
        self.qp_action = DrActionQp(self.server.qp)
        self.create_rx_recv_rules_based_on_match_params(geneve_mask, geneve_val,
                                                        [self.qp_action, self.server_counter_action],
                                                        match_criteria=u.MatchCriteriaEnable.MISC, domain=domain_rx)
        inner_msg_size = self.client.msg_size - GENEVE_PACKET_OUTER_LENGTH
        outer = self.gen_geneve_tunnel_encap_header(inner_msg_size)
        packet_to_send = outer + u.gen_packet(msg_size=inner_msg_size)
        # Send traffic and validate packet
        u.raw_traffic(self.client, self.server, self.iters, packet_to_send=packet_to_send)
        recv_packets_rx = self.query_counter_packets(counter, flow_counter_id)
        self.assertEqual(recv_packets_rx, self.iters, 'Counter rx missed some recv packets')
        src_mac = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.send_client_raw_packets(self.iters, src_mac=src_mac)
        recv_packets_rx = self.query_counter_packets(counter, flow_counter_id)
        self.assertEqual(recv_packets_rx, self.iters,
                         'Counter rx counts more than expected recv packets')

    @skip_unsupported
    def test_geneve_match_tx(self):
        """
        Creates matcher on TX to match on Geneve related fields with counter action,
        sends packets and verifies the matcher.
        """
        from tests.mlx5_prm_structs import FlowTableEntryMatchParam
        self.create_players(Mlx5DrResources)
        skip_if_has_geneve_tx_bug(self.client.ctx)
        geneve_mask, geneve_val = self.create_geneve_params()
        # TX
        self.domain_tx = DrDomain(self.client.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_TX)
        tx_root_table = DrTable(self.domain_tx, 0)
        tx_root_matcher = DrMatcher(tx_root_table, 0, u.MatchCriteriaEnable.MISC, geneve_mask)
        tx_table = DrTable(self.domain_tx, 1)
        self.tx_matcher = DrMatcher(tx_table, 1, u.MatchCriteriaEnable.MISC, geneve_mask)
        counter, flow_counter_id = self.create_counter(self.client.ctx)
        self.client_counter_action = DrActionFlowCounter(counter)
        self.dest_table_action_tx = DrActionDestTable(tx_table)
        self.rules.append(DrRule(tx_root_matcher, geneve_val, [self.dest_table_action_tx]))
        self.rules.append(DrRule(self.tx_matcher, geneve_val, [self.client_counter_action]))
        # RX
        domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        self.qp_action = DrActionQp(self.server.qp)
        empty_param = Mlx5FlowMatchParameters(len(FlowTableEntryMatchParam()),
                                              FlowTableEntryMatchParam())
        self.create_rx_recv_rules_based_on_match_params\
            (empty_param, empty_param, [self.qp_action],
             match_criteria=u.MatchCriteriaEnable.NONE, domain=domain_rx)
        inner_msg_size = self.client.msg_size - GENEVE_PACKET_OUTER_LENGTH
        outer = self.gen_geneve_tunnel_encap_header(inner_msg_size)
        packet_to_send = outer + u.gen_packet(msg_size=inner_msg_size)
        # Send traffic and validate packet
        u.raw_traffic(self.client, self.server, self.iters, packet_to_send=packet_to_send)
        recv_packets_tx = self.query_counter_packets(counter, flow_counter_id)
        self.assertEqual(recv_packets_tx, self.iters, 'Counter tx missed some recv packets')
        src_mac = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.send_client_raw_packets(self.iters, src_mac=src_mac)
        recv_packets_tx = self.query_counter_packets(counter, flow_counter_id)
        self.assertEqual(recv_packets_tx, self.iters,
                         'Counter tx counts more than expected recv packets')

    def roce_bth_match(self, domain_flag=dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX):
        """
        Creates RoCE BTH rule on RX/TX domain. For RX domain, will match on BTH related
        fields with counter and qp action. For TX domain, will match on BTH relate fields
        with counter action. And then generate and send RoCE BTH hit and miss traffic according
        to the matcher and validate the result.
        :param domain_flag: RX/TX Domain for the test.
        """
        from tests.mlx5_prm_structs import FlowTableEntryMatchParam
        self.create_players(Mlx5DrResources)
        roce_bth_mask, roce_bth_val = self.create_roce_bth_params()
        empty_param = Mlx5FlowMatchParameters(len(FlowTableEntryMatchParam()),
                                              FlowTableEntryMatchParam())
        self.domain = DrDomain(self.server.ctx, domain_flag)
        root_table = DrTable(self.domain, 0)
        root_matcher = DrMatcher(root_table, 0, u.MatchCriteriaEnable.NONE, empty_param)
        table = DrTable(self.domain, 1)
        self.matcher = DrMatcher(table, 1, u.MatchCriteriaEnable.MISC, roce_bth_mask)
        if domain_flag == dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
            counter, flow_counter_id = self.create_counter(self.server.ctx)
        else:
            counter, flow_counter_id = self.create_counter(self.client.ctx)
        self.dest_tbl_action = DrActionDestTable(table)
        self.qp_action = DrActionQp(self.server.qp)
        self.counter_action = DrActionFlowCounter(counter)
        self.rules.append(DrRule(root_matcher, empty_param, [self.dest_tbl_action]))
        if domain_flag == dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
            self.rules.append(DrRule(self.matcher, roce_bth_val, [self.qp_action, self.counter_action]))
        else:
            self.rules.append(DrRule(self.matcher, roce_bth_val, [self.counter_action]))
        if domain_flag == dve.MLX5DV_DR_DOMAIN_TYPE_NIC_TX:
            domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
            self.create_rx_recv_rules_based_on_match_params\
                (empty_param, empty_param, [self.qp_action],
                match_criteria=u.MatchCriteriaEnable.NONE, domain=domain_rx)
        inner_msg_size = self.client.msg_size - ROCE_PACKET_OUTER_LENGTH
        outer = self.gen_roce_bth_header(inner_msg_size)
        packet_to_send = outer + u.gen_packet(msg_size=inner_msg_size)
        # Send traffic hit the rule and validate by the counter action
        u.raw_traffic(self.client, self.server, self.iters, packet_to_send=packet_to_send)
        recv_packets = self.query_counter_packets(counter, flow_counter_id)
        self.assertEqual(recv_packets, self.iters, 'Counter missed some recv packets')
        # Send traffic miss the rule and validate by the counter action
        src_mac = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.send_client_raw_packets(self.iters, src_mac=src_mac)
        recv_packets = self.query_counter_packets(counter, flow_counter_id)
        self.assertEqual(recv_packets, self.iters,
                         'Counter counts more than expected recv packets')

    @u.requires_roce_disabled
    @skip_unsupported
    def test_roce_bth_match_rx(self):
        """
        Verify RX matching on RoCE BTH.
        """
        self.roce_bth_match()

    @u.requires_roce_disabled
    @skip_unsupported
    def test_roce_bth_match_tx(self):
        """
        Verify TX matching on RoCE BTH.
        """
        self.roce_bth_match(domain_flag=dve.MLX5DV_DR_DOMAIN_TYPE_NIC_TX)

    @requires_reformat_support
    @skip_unsupported
    def test_packet_reformat_l2_gre(self):
        """
        Creates GRE packet with non-root l2 to l2 reformat actions on TX (encap)
        and on RX (decap).
        """
        self.create_players(Mlx5DrResources)
        encap_header = self.gen_gre_tunnel_encap_header(self.client.msg_size, is_l2_tunnel=True)
        self.packet_reformat_actions(outer=encap_header)

    @requires_reformat_support
    @u.requires_encap_disabled_if_eswitch_on
    @skip_unsupported
    def test_packet_reformat_root_l2_gre(self):
        """
        Creates GRE packet with root l2 to l2 reformat actions on TX (encap) and
        on RX (decap).
        """
        self.create_players(Mlx5DrResources)
        encap_header = self.gen_gre_tunnel_encap_header(self.client.msg_size, is_l2_tunnel=True)
        self.packet_reformat_actions(outer=encap_header, root_only=True)

    @requires_reformat_support
    @skip_unsupported
    def test_packet_reformat_l3_gre(self):
        """
        Creates GRE packet with non-root l2 to l3 reformat actions on TX (encap)
        and on RX (decap).
        """
        self.create_players(Mlx5DrResources)
        encap_header = self.gen_gre_tunnel_encap_header(self.client.msg_size, is_l2_tunnel=False)
        self.packet_reformat_actions(outer=encap_header, l2_ref_type=False)

    @requires_reformat_support
    @u.requires_encap_disabled_if_eswitch_on
    @skip_unsupported
    def test_packet_reformat_root_l3_gre(self):
        """
        Creates GRE packet with root l2 to l3 reformat actions on TX (encap) and
        on RX (decap).
        """
        self.create_players(Mlx5DrResources)
        encap_header = self.gen_gre_tunnel_encap_header(self.client.msg_size, is_l2_tunnel=False)
        self.packet_reformat_actions(outer=encap_header, root_only=True, l2_ref_type=False)

    @requires_reformat_support
    @skip_unsupported
    def test_packet_reformat_l2_geneve(self):
        """
        Creates Geneve packet with non-root l2 to l2 reformat actions on TX
        (encap) and on RX (decap).
        """
        self.create_players(Mlx5DrResources)
        encap_header = self.gen_geneve_tunnel_encap_header(self.client.msg_size, is_l2_tunnel=True)
        self.packet_reformat_actions(outer=encap_header)

    @requires_reformat_support
    @u.requires_encap_disabled_if_eswitch_on
    @skip_unsupported
    def test_packet_reformat_root_l2_geneve(self):
        """
        Creates Geneve packet with root l2 to l2 reformat actions on TX (encap)
        and on RX (decap).
        """
        self.create_players(Mlx5DrResources)
        encap_header = self.gen_geneve_tunnel_encap_header(self.client.msg_size, is_l2_tunnel=True)
        self.packet_reformat_actions(outer=encap_header, root_only=True)

    @requires_reformat_support
    @skip_unsupported
    def test_packet_reformat_l3_geneve(self):
        """
        Creates Geneve packet with non-root l2 to l3 tunnel reformat actions on
        TX (encap) and on RX (decap).
        """
        self.create_players(Mlx5DrResources)
        encap_header = self.gen_geneve_tunnel_encap_header(self.client.msg_size, is_l2_tunnel=False)
        self.packet_reformat_actions(outer=encap_header, l2_ref_type=False)

    @requires_reformat_support
    @u.requires_encap_disabled_if_eswitch_on
    @skip_unsupported
    def test_packet_reformat_root_l3_geneve(self):
        """
        Creates Geneve packet with root l2 to l3 reformat actions on TX (encap)
        and on RX (decap).
        """
        self.create_players(Mlx5DrResources)
        encap_header = self.gen_geneve_tunnel_encap_header(self.client.msg_size, is_l2_tunnel=False)
        self.packet_reformat_actions(outer=encap_header, root_only=True, l2_ref_type=False)


class Mlx5DrDumpTest(PyverbsAPITestCase):
    def setUp(self):
        super().setUp()
        self.res = None

    def tearDown(self):
        super().tearDown()
        if self.res:
            self.res.ctx.close()

    @skip_unsupported
    def test_domain_dump(self):
        dump_file = '/tmp/dump.txt'
        self.res = Mlx5DrResources(self.dev_name, self.ib_port)
        self.domain_rx = DrDomain(self.res.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        self.domain_rx.dump(dump_file)
        self.assertTrue(os.path.isfile(dump_file), 'Dump file does not exist.')
        self.assertGreater(os.path.getsize(dump_file), 0, 'Dump file is empty')
