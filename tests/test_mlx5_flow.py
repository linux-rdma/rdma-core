# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved. See COPYING file
"""
Test module for pyverbs' mlx5 flow module.
"""

import unittest
import errno

from pyverbs.providers.mlx5.mlx5dv_flow import Mlx5FlowMatcher, \
    Mlx5FlowMatcherAttr, Mlx5FlowMatchParameters, Mlx5FlowActionAttr, Mlx5Flow
from tests.utils import requires_root_on_eth, PacketConsts
from pyverbs.pyverbs_error import PyverbsRDMAError
from tests.base import RDMATestCase, RawResources
import pyverbs.providers.mlx5.mlx5_enums as dve
import tests.utils as u
import struct


MAX_MATCH_PARAM_SIZE = 0x180


class Mlx5FlowResources(RawResources):

    def create_matcher(self, mask, match_criteria_enable):
        """
        Creates a matcher from a provided mask.
        :param mask: The mask to match on (in bytes)
        :param match_criteria_enable: Bitmask representing which of the
                                      headers and parameters in match_criteria
                                      are used
        :return: Resulting matcher
        """
        try:
            flow_match_param = Mlx5FlowMatchParameters(len(mask), mask)
            attr = Mlx5FlowMatcherAttr(match_mask=flow_match_param,
                                       match_criteria_enable=match_criteria_enable)
            matcher = Mlx5FlowMatcher(self.ctx, attr)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Matcher creation is not supported')
            raise ex
        return matcher

    @requires_root_on_eth()
    def create_qps(self):
        super().create_qps()


class Mlx5MatcherTest(RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

    def create_players(self, resource, **resource_arg):
        """
        Init Flow tests resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)

    @u.skip_unsupported
    def test_create_empty_matcher(self):
        """
        Creates an empty matcher
        """
        self.res = Mlx5FlowResources(**self.dev_info)
        empty_mask = bytes(MAX_MATCH_PARAM_SIZE)
        self.res.create_matcher(empty_mask, u.MatchCriteriaEnable.NONE)

    @u.skip_unsupported
    def test_create_smac_matcher(self):
        """
        Creates a matcher to match on outer source mac
        """
        self.res = Mlx5FlowResources(**self.dev_info)
        smac_mask = bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        self.res.create_matcher(smac_mask, u.MatchCriteriaEnable.OUTER)

    @u.skip_unsupported
    def test_smac_matcher_to_qp_flow(self):
        """
        Creates a matcher to match on outer source mac and a flow that forwards
        packets to QP when matching on source mac.
        """
        self.create_players(Mlx5FlowResources)
        smac_mask = bytes([0xff] * 6)
        matcher = self.server.create_matcher(smac_mask,
                                             u.MatchCriteriaEnable.OUTER)
        smac_value = struct.pack('!6s',
                                 bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        action_qp = Mlx5FlowActionAttr(action_type=dve.MLX5DV_FLOW_ACTION_DEST_IBV_QP,
                                       qp=self.server.qp)
        self.server.flow = Mlx5Flow(matcher, value_param, [action_qp], 1)
        u.raw_traffic(self.client, self.server, self.iters)
