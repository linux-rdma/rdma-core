# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

"""
Test module for Mlx5 UAR allocation.
"""
import unittest
import errno

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.providers.mlx5.mlx5dv import Mlx5UAR
import pyverbs.providers.mlx5.mlx5_enums as e
from tests.mlx5_base import Mlx5RDMATestCase
from tests.base import BaseResources


class Mlx5UarRes(BaseResources):
    def __init__(self, dev_name, ib_port=None, gid_index=None):
        super().__init__(dev_name, ib_port, gid_index)
        self.uars = []


class Mlx5UarTestCase(Mlx5RDMATestCase):
    def setUp(self):
        super().setUp()
        self.uar_res = Mlx5UarRes(self.dev_name)

    def test_alloc_uar(self):
        try:
            for f in [e._MLX5DV_UAR_ALLOC_TYPE_BF, e._MLX5DV_UAR_ALLOC_TYPE_NC]:
                self.uar_res.uars.append(Mlx5UAR(self.uar_res.ctx, f))
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP or ex.error_code == errno.EPROTONOSUPPORT:
                raise unittest.SkipTest(f'UAR allocation (with flag={f}) is not supported')
            raise ex
        finally:
            for uar in self.uar_res.uars:
                uar.close()
