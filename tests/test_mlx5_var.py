# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

"""
Test module for Mlx5 VAR allocation.
"""

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.providers.mlx5.mlx5dv import Mlx5VAR
from tests.base import BaseResources
from tests.base import RDMATestCase
import unittest
import mmap


class Mlx5VarRes(BaseResources):
    def __init__(self, dev_name, ib_port=None, gid_index=None):
        super().__init__(dev_name, ib_port, gid_index)
        try:
            self.var = Mlx5VAR(self.ctx)
        except PyverbsRDMAError as ex:
            if 'not supported' in str(ex):
                raise unittest.SkipTest('VAR allocation is not supported')


class Mlx5VarTestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        self.var_res = Mlx5VarRes(self.dev_name)

    def test_var_map_unmap(self):
        var_map = mmap.mmap(fileno=self.var_res.ctx.cmd_fd,
                            length=self.var_res.var.length,
                            offset=self.var_res.var.mmap_off)
        # There is no munmap method in mmap Python module, but by closing the
        # mmap instance the memory is unmapped.
        var_map.close()
        self.var_res.var.close()
