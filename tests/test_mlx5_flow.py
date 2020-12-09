# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved. See COPYING file
"""
Test module for pyverbs' mlx5 flow module.
"""

import unittest
import errno

from pyverbs.providers.mlx5.mlx5dv_flow import Mlx5FlowMatcher, \
    Mlx5FlowMatcherAttr, Mlx5FlowMatchParameters
from pyverbs.pyverbs_error import PyverbsRDMAError
from tests.base import RDMATestCase, RawResources
import tests.utils as u


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


class Mlx5MatcherTest(RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

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
