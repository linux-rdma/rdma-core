# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia Inc. All rights reserved. See COPYING file

"""
Test module for mlx5 DevX.
"""

from tests.mlx5_base import Mlx5DevxRcResources, Mlx5DevxTrafficBase
import pyverbs.mem_alloc as mem
from pyverbs.mr import MR
from pyverbs.libibverbs_enums import ibv_access_flags, ibv_odp_transport_cap_bits
import tests.utils as u


class Mlx5DevxRcOdpRes(Mlx5DevxRcResources):
    @u.requires_odpv2
    def create_mr(self):
        self.with_odp = True
        self.user_addr = mem.mmap(length=self.msg_size,
                                  flags=mem.MAP_ANONYMOUS_ | mem.MAP_PRIVATE_)
        access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE | ibv_access_flags.IBV_ACCESS_REMOTE_READ | \
                 ibv_access_flags.IBV_ACCESS_ON_DEMAND
        self.mr = MR(self.pd, self.msg_size, access, self.user_addr)


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

    @u.requires_odp('rc', ibv_odp_transport_cap_bits.IBV_ODP_SUPPORT_SEND | ibv_odp_transport_cap_bits.IBV_ODP_SUPPORT_RECV)
    def test_devx_rc_qp_odp_traffic(self):
        """
        Creates two DevX RC QPs using ODP enabled MKeys.
        Then does SEND_IMM traffic.
        """
        self.create_players(Mlx5DevxRcOdpRes)
        # Send traffic
        self.send_imm_traffic()
