# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved. See COPYING file
"""
Test module for pyverbs' mlx5 dr module.
"""

import unittest
import os.path
import struct
import errno

from pyverbs.providers.mlx5.dr_action import DrActionQp, DrActionModify, \
    DrActionFlowCounter, DrActionDrop, DrActionTag, DrActionDestTable, \
    DrActionPopVLan, DrActionPushVLan, DrActionDestAttr, DrActionDestArray, \
    DrActionDefMiss, DrActionVPort, DrActionIBPort
from pyverbs.providers.mlx5.mlx5dv import Mlx5DevxObj, Mlx5Context, Mlx5DVContextAttr
from tests.utils import skip_unsupported, requires_root_on_eth, requires_eswitch_on, \
    PacketConsts
from pyverbs.providers.mlx5.mlx5dv_flow import Mlx5FlowMatchParameters
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
from tests.mlx5_base import Mlx5RDMATestCase, PyverbsAPITestCase
from pyverbs.providers.mlx5.dr_matcher import DrMatcher
from pyverbs.providers.mlx5.dr_domain import DrDomain
from pyverbs.providers.mlx5.dr_table import DrTable
from pyverbs.providers.mlx5.dr_rule import DrRule
import pyverbs.providers.mlx5.mlx5_enums as dve

from pyverbs.cq import CqInitAttrEx, CQEX
from tests.base import RawResources
import pyverbs.enums as e
import tests.utils as u

OUT_SMAC_47_16_FIELD_ID = 0x1
OUT_SMAC_47_16_FIELD_LENGTH = 32
OUT_SMAC_15_0_FIELD_ID = 0x2
OUT_SMAC_15_0_FIELD_LENGTH = 16
SET_ACTION = 0x1
MAX_MATCH_PARAM_SIZE = 0x180
PF_VPORT = 0x0


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

    def create_counter(self):
        """
        Create flow counter.
        :param player: The player to create the counter on.
        """
        from tests.mlx5_prm_structs import AllocFlowCounterIn, AllocFlowCounterOut
        self.counter = Mlx5DevxObj(self.ctx, AllocFlowCounterIn(), len(AllocFlowCounterOut()))
        self.flow_counter_id = AllocFlowCounterOut(self.counter.out_view).flow_counter_id

    def query_counter_packets(self):
        """
        Query flow counter packets count.
        :return: Number of packets on this counter.
        """
        from tests.mlx5_prm_structs import QueryFlowCounterIn, QueryFlowCounterOut
        query_in = QueryFlowCounterIn(flow_counter_id=self.flow_counter_id)
        counter_out = QueryFlowCounterOut(self.counter.query(query_in,
                                                             len(QueryFlowCounterOut())))
        return counter_out.flow_statistics.packets

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

    def create_players(self, resource, **resource_arg):
        """
        Init Dr test resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)

    @skip_unsupported
    def create_rx_recv_qp_rule(self, smac_value, actions, log_matcher_size=None, domain=None):
        """
        Creates a rule on RX domain that forwards packets that match the smac in the matcher
        to the SW steering flow table and another rule on that table with provided actions.
        :param smac_value: The smac matcher value.
        :param actions: List of actions to attach to the recv rule.
        :param log_matcher_size: Size of the matcher table
        :param domain: RX DR domain to use if provided, otherwise create default RX domain.
        :return: Non root table and dest table action to it
        """
        self.domain_rx = domain if domain else DrDomain(self.server.ctx,
                                                        dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        root_table = DrTable(self.domain_rx, 0)
        table = DrTable(self.domain_rx, 1)
        smac_mask = bytes([0xff] * 6) + bytes(2)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        root_matcher = DrMatcher(root_table, 0, u.MatchCriteriaEnable.OUTER, mask_param)
        self.matcher = DrMatcher(table, 1, u.MatchCriteriaEnable.OUTER, mask_param)
        if log_matcher_size:
            self.matcher.set_layout(log_matcher_size)
        # Size of the matcher value should be modulo 4
        smac_value += bytes(2)
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        self.dest_table_action = DrActionDestTable(table)
        self.rules.append(DrRule(root_matcher, value_param, [self.dest_table_action]))
        self.rules.append(DrRule(self.matcher, value_param, actions))
        return table, self.dest_table_action

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
        action1 = SetActionIn(action_type=SET_ACTION, field=OUT_SMAC_47_16_FIELD_ID,
                              data=0x88888888, length=OUT_SMAC_47_16_FIELD_LENGTH)
        action2 = SetActionIn(action_type=SET_ACTION, field=OUT_SMAC_15_0_FIELD_ID,
                              data=0x8888, length=OUT_SMAC_15_0_FIELD_LENGTH)
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
        for _ in range(iters):
            u.send(self.client, c_send_wr, e.IBV_WR_SEND)
            u.poll_cq_ex(self.client.cq)

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
            u.post_recv(self.server, s_recv_wr, qp_idx=0)
            msg_received = self.server.mr.read(self.server.msg_size, 0)
            u.validate_raw(msg_received, msg, [])

    def dest_port(self, is_vport=True):
        """
        Creates FDB domain, root table with matcher on source mac on the server
        side. Create a rule to forward all traffic to the non-root table.
        On this table apply VPort/IBPort action goto PF.
        Validate RX side of FDB:
        On the server open another RX domain on PF with QP action and validate
        packets by sending traffic from client, catch all traffic with
        VPort/IBPort action goto PF, open another RX domain on PF with QP
        action and validate packets.
        Validate TX side of FDB:
        Send traffic from server and validate packets on servers' QP
        with the same rules.
        :param is_vport: A flag to indicate if to use VPort or IBPort action.
        """
        self.client = Mlx5DrResources(**self.dev_info)
        self.server = Mlx5DrResources(**self.dev_info)
        self.domain_fdb = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_FDB)
        port_action = DrActionVPort(self.domain_fdb, PF_VPORT) if is_vport \
            else DrActionIBPort(self.domain_fdb, self.ib_port)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.fdb_table, self.fdb_dest_act = self.create_rx_recv_qp_rule(smac_value, [port_action],
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
        # Validate traffic on TX
        self.send_server_fdb_to_nic_packets(self.iters)

    @requires_eswitch_on
    def test_dest_vport(self):
        self.dest_port()

    @requires_eswitch_on
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
        self.create_rx_recv_qp_rule(smac_value, [self.qp_action])
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
        self.create_rx_recv_qp_rule(src_mac, [self.qp_action])
        exp_packet = u.gen_packet(self.client.msg_size, src_mac=src_mac)
        u.raw_traffic(self.client, self.server, self.iters, expected_packet=exp_packet)

    @skip_unsupported
    def test_tbl_counter_action(self):
        """
        Create flow counter object, attach it to a rule using counter action
        and perform traffic that hit this rule. Verify that the counter packets
        increased.
        """
        self.create_players(Mlx5DrResources)
        self.server.create_counter()
        self.server_counter_action = DrActionFlowCounter(self.server.counter)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.qp_action = DrActionQp(self.server.qp)
        self.create_rx_recv_qp_rule(smac_value, [self.qp_action, self.server_counter_action])
        u.raw_traffic(self.client, self.server, self.iters)
        recv_packets = self.server.query_counter_packets()
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
        self.server.create_counter()
        self.server_counter_action = DrActionFlowCounter(self.server.counter)

        # Create rule that attaches all the packets in the server RX, sends them
        # to the server RX domain and counts them.
        domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        table = DrTable(domain_rx, 0)
        mask_param = Mlx5FlowMatchParameters(MAX_MATCH_PARAM_SIZE, bytes(MAX_MATCH_PARAM_SIZE))
        matcher = DrMatcher(table, 0, u.MatchCriteriaEnable.NONE, mask_param)
        self.rx_drop_action = DrActionDrop()
        self.rules.append(DrRule(matcher, mask_param, [self.server_counter_action, self.rx_drop_action]))

        # Create drop action on the client TX on specific smac.
        self.tx_drop_action = DrActionDrop()
        self.create_client_send_rule([self.tx_drop_action])

        # Send packets with two differet smacs and expect half to be dropped.
        src_mac_drop = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        src_mac_non_drop = struct.pack('!6s', bytes.fromhex("88:88:88:88:88:88".replace(':', '')))
        self.send_client_raw_packets(int(self.iters/2), src_mac=src_mac_drop)
        recv_packets = self.server.query_counter_packets()
        self.assertEqual(recv_packets, 0, 'Drop action did not drop the TX packets')
        self.send_client_raw_packets(int(self.iters/2), src_mac=src_mac_non_drop)
        recv_packets = self.server.query_counter_packets()
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
        self.create_rx_recv_qp_rule(smac_value, [tag_action, qp_action])
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
        self.create_rx_recv_qp_rule(smac_value, [self.qp_action], log_matcher_size)
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
        self.tx_table, self.tx_dest_act = self.create_rx_recv_qp_rule(smac_value, [push_action],
                                                                      domain=self.domain_tx)
        self.domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        qp_action = DrActionQp(self.server.qp)
        self.create_rx_recv_qp_rule(smac_value, [qp_action], domain=self.domain_rx)
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
        self.create_rx_recv_qp_rule(smac_value, [pop_action, qp_action])
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
        self.create_rx_recv_qp_rule(smac_value, [multi_dest_a], domain=self.domain_rx)
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
        self.tx_table, self.tx_dest_act = self.create_rx_recv_qp_rule(smac_value, [tx_def_miss],
                                                                      domain=self.domain_tx)
        qp_action = DrActionQp(self.server.qp)
        self.create_rx_recv_qp_rule(smac_value, [qp_action])
        smac_mask = bytes([0xff] * 6) + bytes(2)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        matcher_tx2 = DrMatcher(self.tx_table, 2, u.MatchCriteriaEnable.OUTER, mask_param)
        smac_value += bytes(2)
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        self.rules.append(DrRule(matcher_tx2, value_param, [tx_drop_action]))
        u.raw_traffic(self.client, self.server, self.iters)


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
