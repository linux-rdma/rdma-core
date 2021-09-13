# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

"""
Test module for mlx5 packet pacing entry allocation.
"""

from pyverbs.providers.mlx5.mlx5dv import Mlx5PP, Mlx5Context, Mlx5DVContextAttr
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
import pyverbs.providers.mlx5.mlx5_enums as e
from tests.mlx5_base import Mlx5RDMATestCase
import unittest
import struct
import errno


class Mlx5PPRes:
    def __init__(self, dev_name):
        try:
            mlx5dv_attr = Mlx5DVContextAttr(e.MLX5DV_CONTEXT_FLAGS_DEVX)
            self.ctx = Mlx5Context(mlx5dv_attr, dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest('Could not open mlx5 context ({})'
                                    .format(str(ex)))
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 DevX context is not supported')
        self.pps = []


class Mlx5PPTestCase(Mlx5RDMATestCase):
    def setUp(self):
        super().setUp()
        self.pp_res = Mlx5PPRes(self.dev_name)

    def test_pp_alloc(self):
        """
        Allocate two packet pacing entries with the same configuration. One of
        the entries is allocated with a dedicated index.
        Then verify that the indexes are different and free the entries.
        """
        # An arbitrary valid rate limit value (in kbps)
        rate_limit = struct.pack('>I', 100)
        try:
            self.pp_res.pps.append(Mlx5PP(self.pp_res.ctx, rate_limit))
            # Create a dedicated entry of the same previous configuration
            # and verify that it has a different index
            self.pp_res.pps.append(Mlx5PP(self.pp_res.ctx, rate_limit,
                                          flags=e._MLX5DV_PP_ALLOC_FLAGS_DEDICATED_INDEX))
            self.assertNotEqual(self.pp_res.pps[0].index, self.pp_res.pps[1].index,
                                'Dedicated PP index is not unique')
            for pp in self.pp_res.pps:
                pp.close()
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP or ex.error_code == errno.EPROTONOSUPPORT:
                raise unittest.SkipTest('Packet pacing entry allocation is not supported')
            raise ex
