# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2025 NVIDIA Corporation . All rights reserved. See COPYING file

from pyverbs.libibverbs_enums import ibv_access_flags, ibv_wr_opcode, ibv_odp_transport_cap_bits, \
    ibv_tph_mem_type
from tests.base import PyverbsAPITestCase, RCResources, RDMATestCase
from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
import pyverbs.device as d
from pyverbs.pd import PD
from pyverbs.mr import MREx, DMAHandle
from pyverbs.qp import QPAttr
import tests.utils as u


class DMAHandleTest(PyverbsAPITestCase):
    @u.skip_unsupported
    def test_dmah_with_mrex(self):
        """Verify DMAHandle can be used during MREx registration."""
        with d.Context(name=self.dev_name) as ctx:
            with PD(ctx) as pd:
                attr = u.create_dmah_init_attr()
                with DMAHandle(ctx, attr) as dmah:
                    length = u.get_mr_length()
                    access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE
                    with MREx(pd, length, access, dmah=dmah) as mr:
                        pass

    @u.skip_unsupported
    def test_dmah_invalid_ph(self):
        """Verify DMAHandle with invalid PH value, max ph value is 3."""
        with d.Context(name=self.dev_name) as ctx:
            with PD(ctx) as pd:
                attr = u.create_dmah_init_attr(ph=4)
                with self.assertRaises(PyverbsError):
                    DMAHandle(ctx, attr)

    @u.skip_unsupported
    def test_dmah_persistent_memory(self):
        """Attempt to create DMAHandle targeting persistent memory."""
        with d.Context(name=self.dev_name) as ctx:
            attr = u.create_dmah_init_attr(tph_mem_type=ibv_tph_mem_type.IBV_TPH_MEM_TYPE_PM)
            with DMAHandle(ctx, attr):
                pass

    @u.skip_unsupported
    def test_dmah_invalid_mem_type(self):
        """Pass an unsupported TPH memory-type and verify provider rejects it."""
        with d.Context(name=self.dev_name) as ctx:
            attr = u.create_dmah_init_attr(tph_mem_type=0xFE)
            with self.assertRaises(PyverbsError):
                DMAHandle(ctx, attr)

    @u.skip_unsupported
    def test_dmah_inval_cpu_id(self):
        """Attempt to create DMAHandle with invalid CPU ID (0xffff). Expect failure."""
        with d.Context(name=self.dev_name) as ctx:
            attr = u.create_dmah_init_attr(cpu_id=0xffff, ph=3)
            with self.assertRaises(PyverbsError):
                DMAHandle(ctx, attr)

    @u.skip_unsupported
    def test_dmah_mrex_odp_bad_flow(self):
        """Attempt to register ODP-capable MREx with DMAHandle.
        Expect failure since ODP isn't supported with DMAHandle."""
        with d.Context(name=self.dev_name) as ctx:
            # Check ODP support; skip if not available
            odp_cap = (ibv_odp_transport_cap_bits.IBV_ODP_SUPPORT_SEND |
                       ibv_odp_transport_cap_bits.IBV_ODP_SUPPORT_RECV)
            u.odp_supported(ctx, 'rc', odp_cap)
            with PD(ctx) as pd:
                attr = u.create_dmah_init_attr()
                dmah = DMAHandle(ctx, attr)
                with self.assertRaises(PyverbsError):
                    length = u.get_mr_length()
                    access = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                              ibv_access_flags.IBV_ACCESS_ON_DEMAND)
                    MREx(pd, length, access, dmah=dmah)


class DmaHandleMRExRC(RCResources):
    """RC resource class that registers an MREx with a DMAHandle."""

    def __init__(self, dev_name, ib_port, gid_index,
                 mr_access=ibv_access_flags.IBV_ACCESS_LOCAL_WRITE, msg_size=1024):
        self.dmah = None
        self.mr_access = mr_access
        super().__init__(dev_name=dev_name, ib_port=ib_port, gid_index=gid_index,
                         msg_size=msg_size)

    def create_dmah(self):
        """Allocate a DMAHandle using the existing device Context."""
        attr = u.create_dmah_init_attr()
        self.dmah = DMAHandle(self.ctx, attr)

    @u.skip_unsupported
    def create_mr(self):
        self.create_dmah()
        self.mr = MREx(self.pd, self.msg_size, self.mr_access, dmah=self.dmah)

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_access = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                     ibv_access_flags.IBV_ACCESS_REMOTE_WRITE |
                     ibv_access_flags.IBV_ACCESS_REMOTE_ATOMIC)
        qp_attr.qp_access_flags = qp_access
        return qp_attr


class DmaHandleTrafficTest(RDMATestCase):
    """Traffic tests for MREx + DMAHandle combinations."""

    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None
        self.traffic_args = None

    def test_dmah_mrex_rc_send(self):
        """Checks basic RC send/recv traffic with DMAHandle-registered MREx."""
        access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE
        self.create_players(DmaHandleMRExRC, mr_access=access, msg_size=1024)
        u.traffic(**self.traffic_args)

    def test_dmah_mrex_rc_rdma_write(self):
        """Validates RC RDMA Write traffic with DMAHandle & MREx."""
        access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE | ibv_access_flags.IBV_ACCESS_REMOTE_WRITE
        self.create_players(DmaHandleMRExRC, mr_access=access, msg_size=1024)
        u.rdma_traffic(**self.traffic_args, send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE)

    def test_dmah_mrex_rc_atomic(self):
        """Tests RC atomic fetch&add using a DMAHandle-backed MREx."""
        access = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                  ibv_access_flags.IBV_ACCESS_REMOTE_ATOMIC |
                  ibv_access_flags.IBV_ACCESS_REMOTE_WRITE)
        self.create_players(DmaHandleMRExRC, mr_access=access, msg_size=8)
        u.atomic_traffic(**self.traffic_args, send_op=ibv_wr_opcode.IBV_WR_ATOMIC_FETCH_AND_ADD)
