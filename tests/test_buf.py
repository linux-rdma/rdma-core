# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2026 NVIDIA Corporation . All rights reserved. See COPYING file
"""
Test module for the provider-aware buffer API (ibv_alloc_buf, ibv_free_buf and
ibv_reg_buf_mr), including the parent-domain ALLOW_CC_UNPROTECTED_ALLOC opt-in
used by DMA-bounce devices (on a Confidential Computing (CoCo) guest).

The tests form a {buffer source} x {kind} matrix:

                  | API (single node)   | Traffic (two endpoints)
    --------------+---------------------+------------------------
    plain PD      | BufAPITest          | BufTrafficTest
    CC parent dom | CocoBufAPITest      | CocoBufTrafficTest

The plain-PD classes cover the generic ibv_buf infrastructure: ibv_alloc_buf()/
ibv_reg_buf_mr() fall back to plain memory + ibv_reg_mr() (the libibverbs
default allocator), so they run on any provider, including ones without
parent-domain support, and are skipped on a DMA-bounce device where registering
plain (private) memory is rejected.

The CC classes use a parent domain created with ALLOW_CC_UNPROTECTED_ALLOC. On a
DMA-bounce device the buffers are dma-buf backed from the shared heap; on an
ordinary device they fall back to plain memory. On a DMA-bounce device every
buffer the device DMAs to/from must come from the shared heap, so the traffic
resources allocate the data buffer, the CQ and the QP from the same parent
domain.
"""
import unittest
import errno

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.pd import PD, ParentDomain, ParentDomainInitAttr
from pyverbs.mr import MR, Buf, BufMR
from pyverbs.qp import QPAttr
from pyverbs.cq import CqInitAttrEx, CQEX
import pyverbs.device as d
from pyverbs.libibverbs_enums import ibv_access_flags, ibv_atomic_cap, \
    ibv_cq_init_attr_mask, ibv_wr_opcode, IBV_WC_STANDARD_FLAGS, \
    _IBV_PARENT_DOMAIN_INIT_ATTR_ALLOW_CC_UNPROTECTED_ALLOC, \
    _IBV_DEVICE_CC_DMA_BOUNCE
from tests.base import PyverbsAPITestCase, RCResources, UDResources, \
    RDMATestCase
import tests.utils as u


# errnos that mean this environment can't provide CC shared buffers / parent
# domains, and the corresponding test should be skipped rather than fail.
SKIP_ERRNOS = (errno.EOPNOTSUPP, errno.ENOENT, errno.ENODEV)

PAGE_SIZE = 4096

RC_REMOTE_ACCESS = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                    ibv_access_flags.IBV_ACCESS_REMOTE_WRITE)
RC_ATOMIC_ACCESS = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                    ibv_access_flags.IBV_ACCESS_REMOTE_WRITE |
                    ibv_access_flags.IBV_ACCESS_REMOTE_ATOMIC)
RC_READ_ACCESS = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                  ibv_access_flags.IBV_ACCESS_REMOTE_READ)


def device_has_cc_dma_bounce(ctx):
    """Whether the device reports IBV_DEVICE_CC_DMA_BOUNCE."""
    return bool(ctx.query_device_ex().device_cap_flags_ex &
                _IBV_DEVICE_CC_DMA_BOUNCE)


def make_cc_parent_domain(ctx):
    """
    Allocate a base PD and a parent domain that opts in to unprotected/shared
    memory allocation for CoCo guests.
    :param ctx: The Context to allocate on
    :return: A (base_pd, parent_domain) tuple. The base PD must outlive the
             parent domain, so close the parent domain first.
    :raises unittest.SkipTest: if the provider does not support a CC parent
        domain
    """
    base_pd = PD(ctx)
    pd_attr = ParentDomainInitAttr(
        pd=base_pd,
        comp_mask=_IBV_PARENT_DOMAIN_INIT_ATTR_ALLOW_CC_UNPROTECTED_ALLOC)
    try:
        pd = ParentDomain(ctx, attr=pd_attr)
    except PyverbsRDMAError as ex:
        if ex.error_code in SKIP_ERRNOS:
            raise unittest.SkipTest('CC parent domain is not supported by '
                                    'provider')
        raise ex
    return base_pd, pd


def buf_res_cls(base_class, cc):
    """
    Factory turning a TrafficResources subclass into one whose data buffer is
    allocated with ibv_alloc_buf()/ibv_reg_buf_mr().

    cc=False: the buffer is registered through a plain PD with a regular CQ.
        This is the generic ibv_buf path; it runs on any provider but is skipped
        on a DMA-bounce device, where registering plain (private) memory is
        rejected.
    cc=True:  the buffer, CQ and QP come from a parent domain created with
        ALLOW_CC_UNPROTECTED_ALLOC. On a DMA-bounce device the buffers are
        dma-buf backed from the shared heap; on an ordinary device they fall
        back to plain memory. Skipped where parent domains are unsupported.

    Both modes use an extended CQ (the CC mode binds it to the parent domain),
    so the traffic helpers always poll it with is_cq_ex=True. Extra keyword
    arguments:
      * mr_access: access flags for the data MR (and the QP).
      * buf_size:  size of the underlying ibv_buf (defaults to just covering the
                   registered range), allowing a buffer larger than the MR.
      * mr_offset: page-aligned offset of the MR inside the buffer, to register
                   a subrange.
    """
    class BufRes(base_class):
        def __init__(self, *args,
                     mr_access=ibv_access_flags.IBV_ACCESS_LOCAL_WRITE,
                     buf_size=None, mr_offset=0, **kwargs):
            self.base_pd = None
            self.cocobuf = None
            self.mr_access = mr_access
            self.buf_size = buf_size
            self.mr_offset = mr_offset
            super().__init__(*args, **kwargs)

        def create_pd(self):
            if cc:
                self.base_pd, self.pd = make_cc_parent_domain(self.ctx)
            else:
                # A plain PD registers private memory, which a DMA-bounce device
                # rejects - that case is covered by the cc=True resources.
                if device_has_cc_dma_bounce(self.ctx):
                    raise unittest.SkipTest('plain-memory registration is '
                                            'rejected on a DMA-bounce device')
                self.pd = PD(self.ctx)

        def create_cq(self):
            comp_mask = ibv_cq_init_attr_mask.IBV_CQ_INIT_ATTR_MASK_FLAGS
            if cc:
                comp_mask |= ibv_cq_init_attr_mask.IBV_CQ_INIT_ATTR_MASK_PD
            cqia = CqInitAttrEx(
                cqe=self.num_msgs, wc_flags=IBV_WC_STANDARD_FLAGS,
                parent_domain=self.pd if cc else None,
                comp_mask=comp_mask)
            try:
                self.cq = CQEX(self.ctx, cqia)
            except PyverbsRDMAError as ex:
                if ex.error_code in SKIP_ERRNOS:
                    raise unittest.SkipTest('Extended CQ is not supported')
                raise ex

        def create_mr(self):
            # UD prepends a GRH on receive, so the buffer needs room for it.
            extra = self.GRH_SIZE if isinstance(self, UDResources) else 0
            mr_len = self.msg_size + extra
            buf_size = self.buf_size if self.buf_size is not None \
                else mr_len + self.mr_offset
            try:
                self.cocobuf = Buf(self.pd, buf_size)
                self.mr = BufMR(self.pd, self.cocobuf, mr_len, self.mr_access,
                                offset=self.mr_offset)
            except PyverbsRDMAError as ex:
                if ex.error_code in SKIP_ERRNOS:
                    raise unittest.SkipTest('ibv_alloc_buf is not supported')
                raise ex

        def create_qp_attr(self):
            qp_attr = super().create_qp_attr()
            # UD QPs ignore access flags (and reject unknown ones); only set
            # them for connected transports that honor remote operations.
            if not isinstance(self, UDResources):
                qp_attr.qp_access_flags = self.mr_access
            return qp_attr

    return BufRes


BufRC = buf_res_cls(RCResources, cc=False)
BufUD = buf_res_cls(UDResources, cc=False)
CocoBufRC = buf_res_cls(RCResources, cc=True)
CocoBufUD = buf_res_cls(UDResources, cc=True)


class _BufApiHelpers:
    """
    Helpers shared by the buffer API test cases. Mixed into a
    PyverbsAPITestCase, so self.ctx/self.addCleanup are available.
    """
    def _create_cc_pd(self):
        """Create a CC parent domain and register its teardown."""
        base_pd, pd = make_cc_parent_domain(self.ctx)
        # Cleanups run LIFO, so register the base PD first: the parent domain
        # is then closed before the base PD it depends on.
        self.addCleanup(base_pd.close)
        self.addCleanup(pd.close)
        return pd

    def _create_pd(self):
        """Create a PD and register its teardown."""
        pd = PD(self.ctx)
        self.addCleanup(pd.close)
        return pd

    def _alloc_buf(self, pd, size):
        try:
            buf = Buf(pd, size)
        except PyverbsRDMAError as ex:
            if ex.error_code in SKIP_ERRNOS:
                raise unittest.SkipTest('ibv_alloc_buf is not supported')
            raise ex
        self.addCleanup(buf.close)
        return buf

    def _is_cc(self):
        return device_has_cc_dma_bounce(self.ctx)

    def _check_reg_and_access(self, pd, size=PAGE_SIZE, offset=0, buf_size=None):
        """Allocate a buffer, register (a subrange of) it and access the MR."""
        access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE
        buf = self._alloc_buf(pd, buf_size if buf_size is not None
                              else size + offset)
        mr = BufMR(pd, buf, size, access, offset=offset)
        self.addCleanup(mr.close)
        self.assertEqual(mr.buf, buf.buf + offset)
        mr.write('a' * size, size)
        self.assertEqual(mr.read(size, 0), b'a' * size)


class _BufApiTests:
    """
    Generic ibv_buf API test bodies, parametrized over the buffer's PD via the
    _buf_pd() hook (an ordinary PD or a CC parent domain). Concrete subclasses
    provide _buf_pd() and mix in _BufApiHelpers + PyverbsAPITestCase.
    """
    def test_alloc_reg_free_buf(self):
        """Allocate a buffer, register the full range and access it."""
        self._check_reg_and_access(self._buf_pd())

    def test_reg_buf_subrange(self):
        """Register a page-aligned subrange of a larger buffer."""
        self._check_reg_and_access(self._buf_pd(), size=PAGE_SIZE,
                                   offset=PAGE_SIZE)

    def test_multiple_mrs_one_buf(self):
        """Register several MRs over disjoint subranges of one buffer."""
        access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE
        pd = self._buf_pd()
        buf = self._alloc_buf(pd, 2 * PAGE_SIZE)
        mr1 = BufMR(pd, buf, PAGE_SIZE, access, offset=0)
        self.addCleanup(mr1.close)
        mr2 = BufMR(pd, buf, PAGE_SIZE, access, offset=PAGE_SIZE)
        self.addCleanup(mr2.close)
        self.assertNotEqual(mr1.lkey, mr2.lkey)
        mr1.write('a' * PAGE_SIZE, PAGE_SIZE)
        mr2.write('b' * PAGE_SIZE, PAGE_SIZE)
        self.assertEqual(mr1.read(PAGE_SIZE, 0), b'a' * PAGE_SIZE)
        self.assertEqual(mr2.read(PAGE_SIZE, 0), b'b' * PAGE_SIZE)

    def test_buf_reuse_after_free(self):
        """Free a buffer and allocate/register another."""
        size = PAGE_SIZE
        access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE
        pd = self._buf_pd()
        buf = Buf(pd, size)
        buf.close()
        buf = self._alloc_buf(pd, size)
        mr = BufMR(pd, buf, size, access)
        self.addCleanup(mr.close)
        mr.write('a' * size, size)
        self.assertEqual(mr.read(size, 0), b'a' * size)

    def test_buf_double_close(self):
        """Closing a Buf/BufMR twice must be a safe no-op."""
        size = PAGE_SIZE
        access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE
        pd = self._buf_pd()
        buf = self._alloc_buf(pd, size)
        mr = BufMR(pd, buf, size, access)
        mr.close()
        mr.close()
        buf.close()
        buf.close()


class BufAPITest(_BufApiTests, _BufApiHelpers, PyverbsAPITestCase):
    """
    Generic ibv_buf API on an ordinary PD (skipped on a DMA-bounce device) plus the
    environment-agnostic bad-flow checks (rejected inside libibverbs before the
    provider, so they run anywhere).
    """
    def _buf_pd(self):
        if self._is_cc():
            raise unittest.SkipTest('plain-memory registration is rejected on '
                                    'a DMA-bounce device')
        return self._create_pd()

    def test_reg_buf_wrong_pd(self):
        """ibv_reg_buf_mr() must reject a PD other than the allocating one."""
        size = PAGE_SIZE
        access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE
        alloc_pd = self._create_pd()
        other_pd = self._create_pd()
        buf = self._alloc_buf(alloc_pd, size)
        with self.assertRaises(PyverbsRDMAError) as cm:
            BufMR(other_pd, buf, size, access)
        self.assertEqual(cm.exception.error_code, errno.EINVAL)

    def test_reg_buf_out_of_range(self):
        """ibv_reg_buf_mr() must reject a range outside the buffer."""
        size = PAGE_SIZE
        access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE
        pd = self._create_pd()
        buf = self._alloc_buf(pd, size)
        with self.assertRaises(PyverbsRDMAError) as cm:
            BufMR(pd, buf, 2 * size, access)
        self.assertEqual(cm.exception.error_code, errno.EINVAL)
        with self.assertRaises(PyverbsRDMAError) as cm:
            BufMR(pd, buf, size, access, offset=size)
        self.assertEqual(cm.exception.error_code, errno.EINVAL)


class CocoBufAPITest(_BufApiTests, _BufApiHelpers, PyverbsAPITestCase):
    """
    CoCo-specific API tests: the same buffer-API bodies run through a parent
    domain created with ALLOW_CC_UNPROTECTED_ALLOC (dma-buf backed on a
    DMA-bounce device, plain memory otherwise), plus a check that plain memory
    registration is rejected on a DMA-bounce device.
    """
    def _buf_pd(self):
        return self._create_cc_pd()

    def test_plain_mr_rejected(self):
        """On a DMA-bounce device, registering plain memory must fail.

        This documents why the feature exists: the device cannot DMA to private
        guest memory, so a regular ibv_reg_mr() is rejected and applications
        must use the parent-domain buffers instead. Skipped otherwise.
        """
        if not self._is_cc():
            raise unittest.SkipTest('Device does not report CC_DMA_BOUNCE')
        access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE
        with PD(self.ctx) as pd:
            with self.assertRaises(PyverbsRDMAError):
                MR(pd, PAGE_SIZE, access)


class _BufTrafficTests:
    """
    RC/UD traffic over ibv_alloc_buf()/ibv_reg_buf_mr() data buffers. Concrete
    subclasses set RC and UD to the resource classes (plain or CC) and mix in
    RDMATestCase. Both resource flavors use an extended CQ, so traffic always
    polls with is_cq_ex=True.
    """
    RC = None
    UD = None

    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

    def test_rc_traffic(self):
        """RC send/recv over a buffer MR."""
        self.create_players(self.RC)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_rc_send_imm(self):
        """RC send-with-immediate over a buffer MR."""
        self.create_players(self.RC)
        u.traffic(**self.traffic_args, is_cq_ex=True,
                  send_op=ibv_wr_opcode.IBV_WR_SEND_WITH_IMM)

    def test_rc_multi_qp(self):
        """RC send/recv across several QPs."""
        self.create_players(self.RC, qp_count=3)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_rc_large_msg(self):
        """RC send/recv with a multi-page buffer MR."""
        self.create_players(self.RC, msg_size=16384)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_rc_subrange_mr(self):
        """RC send/recv where the MR is a page-aligned subrange of the buffer."""
        self.create_players(self.RC, mr_offset=PAGE_SIZE,
                            buf_size=PAGE_SIZE + 16384, msg_size=8192)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_rc_rdma_write(self):
        """RC RDMA write (with immediate) into a buffer MR."""
        self.create_players(self.RC, mr_access=RC_REMOTE_ACCESS)
        u.traffic(**self.traffic_args, is_cq_ex=True,
                  send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE_WITH_IMM)

    def test_rc_rdma_read(self):
        """RC RDMA read from a buffer MR."""
        self.create_players(self.RC, mr_access=RC_READ_ACCESS)
        u.rdma_traffic(**self.traffic_args, is_cq_ex=True,
                       send_op=ibv_wr_opcode.IBV_WR_RDMA_READ)

    def test_rc_atomic_fetch_add(self):
        """RC atomic fetch&add on a buffer MR."""
        ctx = d.Context(name=self.dev_name)
        if ctx.query_device().atomic_caps == ibv_atomic_cap.IBV_ATOMIC_NONE:
            raise unittest.SkipTest('Atomic operations are not supported')
        self.create_players(self.RC, mr_access=RC_ATOMIC_ACCESS, msg_size=8)
        u.atomic_traffic(**self.traffic_args, is_cq_ex=True,
                         send_op=ibv_wr_opcode.IBV_WR_ATOMIC_FETCH_AND_ADD)

    def test_ud_traffic(self):
        """UD send/recv over a buffer MR."""
        self.create_players(self.UD)
        u.traffic(**self.traffic_args, is_cq_ex=True)


class BufTrafficTest(_BufTrafficTests, RDMATestCase):
    """Generic buffer-MR traffic on an ordinary PD + regular CQ (skipped on CoCo)."""
    RC = BufRC
    UD = BufUD


class CocoBufTrafficTest(_BufTrafficTests, RDMATestCase):
    """Buffer-MR traffic with the buffer, CQ and QP from a CC parent domain."""
    RC = CocoBufRC
    UD = CocoBufUD
