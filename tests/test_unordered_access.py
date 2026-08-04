# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2026 NVIDIA Corporation. All rights reserved. See COPYING file
"""
Test module for the IBV_ACCESS_UNORDERED access flag.
"""
from pyverbs.libibverbs_enums import ibv_access_flags, ibv_wr_opcode

from tests.test_mr import MRRes, MRExRes
from tests.base import RDMATestCase
import tests.utils as u


class UnorderedAccessTestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 100

    def test_unordered_rc_traffic(self):
        """
        Run RC SEND traffic with a memory region registered for unordered
        access.
        """
        access = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                  ibv_access_flags.IBV_ACCESS_UNORDERED)
        self.create_players(MRRes, mr_access=access)
        u.traffic(**self.traffic_args)

    def test_unordered_mr_ex_rdma_write(self):
        """
        Run RDMA Write traffic to an extended memory region registered for
        unordered access.
        """
        access = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                  ibv_access_flags.IBV_ACCESS_REMOTE_WRITE |
                  ibv_access_flags.IBV_ACCESS_UNORDERED)
        self.create_players(MRExRes, mr_access=access)
        u.rdma_traffic(**self.traffic_args, send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE)
