# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia Inc. All rights reserved. See COPYING file

"""
Test module for mlx5 DevX.
"""

import resource
import unittest
import errno
import os

from tests.mlx5_base import Mlx5DevxRcResources, Mlx5DevxTrafficBase
from tests.test_buf import alloc_buf, device_has_cc_dma_bounce, \
    make_cc_pd, register_buf_mr
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, \
    Mlx5DevxCmdComp, Mlx5DevxObj, Mlx5UMEM
from pyverbs.providers.mlx5.mlx5_enums import mlx5dv_context_attr_flags
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
import pyverbs.mem_alloc as mem
from pyverbs.mr import MR
from pyverbs.libibverbs_enums import ibv_access_flags, ibv_odp_transport_cap_bits
import tests.utils as u


class BufDevxRcResources(Mlx5DevxRcResources):
    """
    DevX RC resources for a Confidential Computing (CoCo) guest: every DevX
    UMEM and the data MR live in shared/unprotected memory allocated with
    Buf on a CC parent domain. Each UMEM is registered through the
    DevX dmabuf path using an FD exported from its Buf, so all NIC-DMA'd memory
    is shared as a DMA-bounce device requires.
    """
    def __init__(self, dev_name, ib_port, gid_index, msg_size=1024,
                 activate_port_state=False, send_dbr_mode=0):
        self.bufs = []
        self.dmabuf_fds = []
        self.base_pd = None
        super().__init__(dev_name, ib_port, gid_index, msg_size,
                         activate_port_state, send_dbr_mode)

    def create_pd(self):
        """Build a CC parent domain and derive the DevX pdn from it."""
        from pyverbs.providers.mlx5.mlx5dv_objects import Mlx5DvObj
        from pyverbs.providers.mlx5.mlx5_enums import mlx5dv_obj_type
        if not device_has_cc_dma_bounce(self.ctx):
            raise unittest.SkipTest('Device is not a CC DMA-bounce device')
        self.base_pd, self.pd = make_cc_pd(self.ctx)
        self.dv_pd = Mlx5DvObj(mlx5dv_obj_type.MLX5DV_OBJ_PD, pd=self.pd).dvpd

    def create_mr(self):
        """Register the data buffer as a shared Buf MR on the CC PD."""
        access = ibv_access_flags.IBV_ACCESS_REMOTE_WRITE | \
                 ibv_access_flags.IBV_ACCESS_LOCAL_WRITE | \
                 ibv_access_flags.IBV_ACCESS_REMOTE_READ
        buf = alloc_buf(self.pd, self.msg_size)
        self.mr = register_buf_mr(self.pd, buf, self.msg_size, access)

    def create_umem(self, size, access=ibv_access_flags.IBV_ACCESS_LOCAL_WRITE,
                    alignment=resource.getpagesize()):
        """Return a DevX UMEM backed by a Buf exported as a dmabuf FD."""
        from pyverbs.providers.mlx5.mlx5_enums import MLX5DV_UMEM_MASK_DMABUF
        page_size = resource.getpagesize()
        alloc_size = max(size, page_size)
        buf = alloc_buf(self.pd, alloc_size)
        mem.write(buf.addr, bytes(alloc_size), alloc_size)  # Zero-fill the buffer
        fd = self.export_buf_dmabuf_fd(buf)
        umem = Mlx5UMEM(self.ctx, alloc_size, addr=0, alignment=alignment, access=access,
                        pgsz_bitmap=page_size, comp_mask=MLX5DV_UMEM_MASK_DMABUF, dmabuf_fd=fd)
        umem.umem_addr = buf.addr
        self.bufs.append(buf)
        self.dmabuf_fds.append(fd)
        return umem

    def export_buf_dmabuf_fd(self, buf):
        """Export the Buf's dmabuf FD, skipping when it is not dmabuf-backed."""
        try:
            return buf.export_dmabuf_fd()
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.ENODATA:
                raise unittest.SkipTest('Buf is not dmabuf-backed')
            raise

    def close_resources(self):
        """Close the exported dmabuf FDs"""
        super().close_resources()
        for fd in self.dmabuf_fds:
            os.close(fd)
        self.dmabuf_fds = []


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

    def test_devx_rc_qp_send_imm_buf_umem_traffic(self):
        """
        Run DevX RC SEND_IMM traffic where all NIC memory (QP, CQ, doorbell
        UMEMs and the data MR) is shared CoCo memory: buffers on a CC parent
        domain, registered as UMEMs via their dmabuf FD.
        """
        self.create_players(BufDevxRcResources)
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


class Mlx5DevxApiTest(Mlx5DevxTrafficBase):
    def setUp(self):
        super().setUp()
        self.devx_res = None

    def tearDown(self):
        super().tearDown()
        if self.devx_res:
            self.devx_res.close_resources()

    def _create_devx_ctx(self):
        try:
            attr = Mlx5DVContextAttr(mlx5dv_context_attr_flags.MLX5DV_CONTEXT_FLAGS_DEVX)
            return Mlx5Context(attr, self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 DevX context is not supported')

    def test_devx_async_query(self):
        """
        Test DevX Async Query API.
        Creating a DevX QP and query it using DevX async query.
        """
        self.devx_res = Mlx5DevxRcResources(**self.dev_info)
        self.cmd_comp = Mlx5DevxCmdComp(self.devx_res.ctx)
        from tests.mlx5_prm_structs import QueryQpIn, QueryQpOut
        query_qp_in = QueryQpIn(qpn=self.devx_res.qpn)
        qp_wr_id = 100
        try:
            self.devx_res.qp.query_async(query_qp_in, len(QueryQpOut()), wr_id=qp_wr_id,
                                    cmd_comp=self.cmd_comp)
            wr_id, out_data = self.cmd_comp.get_async_cmd_comp()
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Async command completion is not supported')
            raise ex

        query_qp_out = QueryQpOut(out_data)
        self.assertTrue(query_qp_out.status == 0,
                        'Query Devx QP by Async Query API failed with non-zero status: '
                        f'{query_qp_out.status}')
        self.assertTrue(wr_id == qp_wr_id,
                        f'Mismatched work request ID. Expected: {qp_wr_id}, Actual: {wr_id}')
        self.assertTrue(query_qp_out.sw_qpc.log_rq_size == self.devx_res.log_rq_size,
                        f'Mismatched RQ size. Expected: {self.devx_res.log_rq_size}, '
                        f'Actual: {query_qp_out.sw_qpc.log_rq_size}')

    @u.skip_unsupported
    def test_umem_export_import(self):
        """
        Create UMEM, export, import, then close both.
        """
        with self._create_devx_ctx() as ctx:
            with Mlx5UMEM(ctx, size=resource.getpagesize()) as umem:
                original_id = umem.umem_id
                data = umem.export()
                with Mlx5UMEM.import_umem(ctx, data) as imported_umem:
                    self.assertEqual(imported_umem.umem_id, original_id,
                                     f'Imported UMEM ID {imported_umem.umem_id}'
                                     f' does not match original {original_id}')

    @u.skip_unsupported
    def test_devx_obj_export_import(self):
        """
        Create a DevX flow counter object, export to opaque buffer,
        import from buffer, then close both.
        """
        from tests.mlx5_prm_structs import AllocFlowCounterIn, AllocFlowCounterOut

        with self._create_devx_ctx() as ctx:
            with Mlx5DevxObj(ctx, AllocFlowCounterIn(),
                             len(AllocFlowCounterOut())) as counter:
                data = counter.export()
                with Mlx5DevxObj.import_obj(ctx, data) as imported_counter:
                    self.assertIsNotNone(imported_counter,
                                         'Failed to import DevX object '
                                         'from exported data')
