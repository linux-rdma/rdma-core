# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved. See COPYING file
"""
Test module for pyverbs' mlx5 dr module.
"""

from tests.utils import skip_unsupported, requires_root_on_eth, PacketConsts
from pyverbs.providers.mlx5.mlx5dv_flow import Mlx5FlowMatchParameters
from pyverbs.providers.mlx5.dr_matcher import DrMatcher
from pyverbs.providers.mlx5.dr_action import DrActionQp
from pyverbs.providers.mlx5.dr_domain import DrDomain
from pyverbs.providers.mlx5.dr_table import DrTable
from pyverbs.providers.mlx5.dr_rule import DrRule
import pyverbs.providers.mlx5.mlx5_enums as dve
from tests.mlx5_base import Mlx5RDMATestCase
from tests.base import RawResources
import tests.utils as u
import struct


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
    def test_root_tbl_qp_rule(self):
        """
        Creates RX domain, root table with matcher on source mac. Creates QP
        action and a rule with this action on the matcher.
        """
        self.create_players(Mlx5DrResources)
        domain_rx = DrDomain(self.server.ctx, dve.MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
        table = DrTable(domain_rx, 0)
        smac_mask = bytes([0xff] * 6)
        mask_param = Mlx5FlowMatchParameters(len(smac_mask), smac_mask)
        matcher = DrMatcher(table, 0, u.MatchCriteriaEnable.OUTER, mask_param)
        qp_action = DrActionQp(self.server.qp)
        smac_value = struct.pack('!6s',
                                 bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        self.rule = DrRule(matcher, value_param, [qp_action])
        u.raw_traffic(self.client, self.server, self.iters)
