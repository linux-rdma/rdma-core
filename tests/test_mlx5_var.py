# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

"""
Test module for Mlx5 VAR allocation and export/import.
"""

import mmap
from pyverbs.providers.mlx5.mlx5dv import Mlx5VAR
from pyverbs.providers.mlx5.mlx5_enums import MLX5DV_VAR_ALLOC_FLAG_TLP_
from tests.utils import skip_unsupported
from tests.mlx5_base import Mlx5PyverbsAPITestCase


@skip_unsupported
def alloc_var(ctx, flags=0):
    """
    Allocate VAR with given flags.
    :param ctx: Device context
    :param flags: VAR allocation flags (default: 0)
    :return: Mlx5VAR object
    """
    return Mlx5VAR(ctx, flags=flags)


class Mlx5VarTestCase(Mlx5PyverbsAPITestCase):
    def setUp(self):
        super().setUp()
        self.var = alloc_var(self.ctx)

    def tearDown(self):
        """Ensure VAR is always freed, even if test fails."""
        if hasattr(self, 'var') and self.var:
            self.var.close()
        super().tearDown()

    def test_var_map_unmap(self):
        var_map = mmap.mmap(fileno=self.ctx.cmd_fd,
                            length=self.var.length,
                            offset=self.var.mmap_off)
        # There is no munmap method in mmap Python module, but by closing the
        # mmap instance the memory is unmapped.
        var_map.close()


class Mlx5TlpVarTestCase(Mlx5PyverbsAPITestCase):
    """
    Test cases for TLP VAR allocation and import functionality.
    """
    def setUp(self):
        super().setUp()
        self.var = alloc_var(self.ctx, flags=MLX5DV_VAR_ALLOC_FLAG_TLP_)

    def tearDown(self):
        """Ensure TLP VAR is always freed, even if test fails."""
        if hasattr(self, 'var') and self.var:
            self.var.close()
        super().tearDown()

    @skip_unsupported
    def test_tlp_var_alloc_and_mmap(self):
        """
        Create TLP VAR and mmap it.
        """
        var_map = mmap.mmap(fileno=self.ctx.cmd_fd,
                            length=self.var.length,
                            offset=self.var.mmap_off)
        var_map.close()

    @skip_unsupported
    def test_tlp_var_import(self):
        """
        Export and import TLP VAR in the same process and mmap the imported VAR.
        """
        data = self.var.export()
        imported_var = Mlx5VAR.import_var(self.ctx, data)
        var_map = mmap.mmap(fileno=self.ctx.cmd_fd,
                            length=imported_var.length,
                            offset=imported_var.mmap_off)
        var_map.close()
        imported_var.close()
