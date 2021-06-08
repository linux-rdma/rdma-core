# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 NVIDIA Corporation . All rights reserved. See COPYING file

"""
Test module for Mlx5 DV query port.
"""

import unittest
import errno

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context
from tests.mlx5_base import Mlx5PyverbsAPITestCase
import pyverbs.providers.mlx5.mlx5_enums as e


class Mlx5DVQueryPortTestCase(Mlx5PyverbsAPITestCase):
    def test_dv_query_port(self):
        """
        Test the DV query port and that no error is returned.
        """
        for port in range (1, self.attr_ex.phys_port_cnt_ex + 1):
            try:
                port_attr = Mlx5Context.query_mlx5_port(self.ctx, port)
            except PyverbsRDMAError as ex:
                if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                    raise unittest.SkipTest(f'mlx5dv_query_port() isn\'t supported')
                raise ex

            if (port_attr.flags & e.MLX5DV_QUERY_PORT_VPORT_STEERING_ICM_RX_):
                self.assertNotEqual(port_attr.vport_steering_icm_rx, 0,
                                    f'Vport steering icm rx address is zero')

            if (port_attr.flags & e.MLX5DV_QUERY_PORT_VPORT_STEERING_ICM_TX_):
                self.assertNotEqual(port_attr.vport_steering_icm_tx, 0,
                                    f'Vport steering icm tx address is zero')

            if (port_attr.flags & e.MLX5DV_QUERY_PORT_VPORT_REG_C0_):
                self.assertNotEqual(port_attr.reg_c0_mask, 0,
                                    f'Vport reg c0 mask is zero')
