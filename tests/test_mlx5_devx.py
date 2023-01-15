# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia Inc. All rights reserved. See COPYING file

"""
Test module for mlx5 DevX.
"""

from tests.mlx5_base import Mlx5DevxRcResources, Mlx5DevxTrafficBase


class Mlx5DevxRcTrafficTest(Mlx5DevxTrafficBase):
    """
    Test various functionality of mlx5 DevX objects
    """

    def test_devx_rc_qp_send_imm_traffic(self):
        """
        Creates two DevX RC QPs and modifies them to RTS state.
        Then does SEND_IMM traffic.
        """
        self.create_players(Mlx5DevxRcResources)
        # Send traffic
        self.send_imm_traffic()

    def test_devx_rc_qp_send_imm_doorbell_less_traffic(self):
        """
        Creates two DevX RC QPs with dbr less ext and modifies them to RTS state.
        Then does SEND_IMM traffic.
        """
        from tests.mlx5_prm_structs import SendDbrMode

        self.create_players(Mlx5DevxRcResources, send_dbr_mode=SendDbrMode.NO_DBR_EXT)
        # Send traffic
        self.send_imm_traffic()
