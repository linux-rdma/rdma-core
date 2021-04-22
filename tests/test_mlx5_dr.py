# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved. See COPYING file
"""
Test module for pyverbs' mlx5 dr module.
"""

from tests.utils import skip_unsupported, requires_root_on_eth, PacketConsts
from pyverbs.providers.mlx5.dr_action import DrActionQp, DrActionModify
from pyverbs.providers.mlx5.mlx5dv_flow import Mlx5FlowMatchParameters
from pyverbs.providers.mlx5.dr_matcher import DrMatcher
from pyverbs.providers.mlx5.dr_domain import DrDomain
from pyverbs.providers.mlx5.dr_table import DrTable
from pyverbs.providers.mlx5.dr_rule import DrRule
import pyverbs.providers.mlx5.mlx5_enums as dve
from tests.mlx5_base import Mlx5RDMATestCase
from tests.base import RawResources
import tests.utils as u
import struct

OUT_SMAC_47_16_FIELD_ID = 0x1
OUT_SMAC_47_16_FIELD_LENGTH = 32
OUT_SMAC_15_0_FIELD_ID = 0x2
OUT_SMAC_15_0_FIELD_LENGTH = 16
SET_ACTION = 0x1


class Mlx5DrResources(RawResources):
    """
    Test various functionalities of the mlx5 direct rules class.
    """
    @requires_root_on_eth()
    def create_qps(self):
        super().create_qps()


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
    def create_rx_recv_qp_rule(self, smac_value):
        """
        Creates a rule on RX domain that forwards packets that match the smac
        in the matcher to the server QP.
        :param smac_value: The smac matcher value.
        """
        domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        table = DrTable(domain_rx, 0)
        smac_mask = bytes([0xff] * 6)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        matcher = DrMatcher(table, 0, u.MatchCriteriaEnable.OUTER, mask_param)
        self.qp_action = DrActionQp(self.server.qp)
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        self.rules.append(DrRule(matcher, value_param, [self.qp_action]))

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
    def test_root_tbl_qp_rule(self):
        """
        Creates RX domain, root table with matcher on source mac. Creates QP
        action and a rule with this action on the matcher.
        """
        self.create_players(Mlx5DrResources)
        smac_value = struct.pack('!6s', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        self.create_rx_recv_qp_rule(smac_value)
        u.raw_traffic(self.client, self.server, self.iters)

    @skip_unsupported
    def test_root_tbl_modify_header_rule(self):
        """
        Creates TX domain, root table with matcher on source mac and modify
        the smac. Then creates RX domain and rule that forwards packets with
        the new smac to server QP. Perform traffic that do this flow.
        """
        self.create_players(Mlx5DrResources)
        self.create_tx_modify_rule()
        src_mac = struct.pack('!6s', bytes.fromhex("88:88:88:88:88:88".replace(':', '')))
        self.create_rx_recv_qp_rule(src_mac)
        exp_packet = u.gen_packet(self.client.msg_size, src_mac=src_mac)
        u.raw_traffic(self.client, self.server, self.iters, expected_packet=exp_packet)
