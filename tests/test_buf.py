# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2026 NVIDIA Corporation . All rights reserved. See COPYING file
"""
Tests for the provider-aware buffer API: ibv_alloc_buf(), ibv_free_buf(),
ibv_reg_buf_mr() and the ibv_reg_mr_ex() IBV_REG_MR_MASK_BUF path.
"""
import unittest
import errno
import resource

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.pd import PD, ParentDomain, ParentDomainInitAttr
from pyverbs.mr import MR, Buf, BufMR, MREx
from pyverbs.cq import CqInitAttrEx, CQEX
import pyverbs.device as d
from pyverbs.libibverbs_enums import ibv_access_flags, ibv_atomic_cap, \
    ibv_cq_init_attr_mask, ibv_wr_opcode, ibv_parent_domain_init_attr_mask, \
    IBV_WC_STANDARD_FLAGS, _IBV_DEVICE_CC_DMA_BOUNCE
from tests.base import PyverbsAPITestCase, RCResources, UDResources, \
    RDMATestCase
import tests.utils as u


# errnos that mean the environment cannot provide CC shared buffers / parent
# domains; the affected test is skipped rather than failed.
SKIP_ERRNOS = (errno.EOPNOTSUPP, errno.ENOENT, errno.ENODEV)

PAGE_SIZE = resource.getpagesize()


def device_has_cc_dma_bounce(ctx):
    """Whether the device reports IBV_DEVICE_CC_DMA_BOUNCE."""
    return bool(ctx.query_device_ex().device_cap_flags_ex &
                _IBV_DEVICE_CC_DMA_BOUNCE)


def make_cc_pd(ctx):
    """
    Allocate a base PD and a CC PD opting in to unprotected/shared memory for
    CoCo guests. Returns a (base_pd, cc_pd) tuple; the base PD must outlive the
    CC PD. Skips if CC PDs are unsupported.
    """
    base_pd = PD(ctx)
    attr = ParentDomainInitAttr(
        pd=base_pd,
        comp_mask=ibv_parent_domain_init_attr_mask.
        IBV_PARENT_DOMAIN_INIT_ATTR_ALLOW_CC_UNPROTECTED_ALLOC)
    try:
        pd = ParentDomain(ctx, attr=attr)
    except PyverbsRDMAError as ex:
        base_pd.close()
        if ex.error_code in SKIP_ERRNOS:
            raise unittest.SkipTest('CC PD is not supported')
        raise
    return base_pd, pd


def alloc_buf(pd, size):
    """
    Allocate a buffer of ibv_buf type, skipping if the provider
    does not support it
    """
    try:
        return Buf(pd, size)
    except PyverbsRDMAError as ex:
        if ex.error_code in SKIP_ERRNOS:
            raise unittest.SkipTest('ibv_alloc_buf() is not supported')
        raise


def register_buf_mr(pd, buf, length, access, offset=0, via_reg_mr_ex=False):
    """
    Register (a subrange of) buf, either through ibv_reg_buf_mr() or, when
    via_reg_mr_ex is set, through the ibv_reg_mr_ex() IBV_REG_MR_MASK_BUF path.
    """
    try:
        if via_reg_mr_ex:
            return MREx(pd, length=length, access=access, buf=buf,
                        address=buf.addr + offset)
        return BufMR(pd, buf, length, access, offset=offset)
    except PyverbsRDMAError as ex:
        if ex.error_code in SKIP_ERRNOS:
            raise unittest.SkipTest('Buffer MR registration is not supported')
        raise


def init_buf_resource(res, cc, via_reg_mr_ex, mr_access, buf_size, mr_offset):
    """Store the buffer parameters before the base resource init runs."""
    res.cc = cc
    res.via_reg_mr_ex = via_reg_mr_ex
    res.mr_access = mr_access
    res.buf_size = buf_size
    res.mr_offset = mr_offset
    res.base_pd = None
    res.data_buf = None


def create_pd(res):
    """Create the resource's PD: a plain PD or a CC PD."""
    if res.cc:
        res.base_pd, res.pd = make_cc_pd(res.ctx)
    else:
        # A plain PD registers private memory, which a DMA-bounce device
        # rejects; that device is exercised by the cc=True resources.
        if device_has_cc_dma_bounce(res.ctx):
            raise unittest.SkipTest('Plain-memory registration is rejected on '
                                    'a DMA-bounce device')
        res.pd = PD(res.ctx)


def create_cq(res):
    """Create the resource's extended CQ, bound to the CC PD for cc."""
    comp_mask = ibv_cq_init_attr_mask.IBV_CQ_INIT_ATTR_MASK_FLAGS
    if res.cc:
        comp_mask |= ibv_cq_init_attr_mask.IBV_CQ_INIT_ATTR_MASK_PD
    cqia = CqInitAttrEx(cqe=res.num_msgs, wc_flags=IBV_WC_STANDARD_FLAGS,
                        parent_domain=res.pd if res.cc else None,
                        comp_mask=comp_mask)
    try:
        res.cq = CQEX(res.ctx, cqia)
    except PyverbsRDMAError as ex:
        if ex.error_code in SKIP_ERRNOS:
            raise unittest.SkipTest('Extended CQ is not supported')
        raise


def create_buf_mr(res, mr_len, buf_size, offset):
    """Allocate an ibv_buf and register (a subrange of) it as the MR."""
    if buf_size is None:
        buf_size = mr_len + offset
    res.data_buf = alloc_buf(res.pd, buf_size)
    res.mr = register_buf_mr(res.pd, res.data_buf, mr_len, res.mr_access,
                             offset=offset, via_reg_mr_ex=res.via_reg_mr_ex)


class BufRC(RCResources):
    """RC resources whose data buffer is allocated with ibv_alloc_buf()."""
    def __init__(self, *args, cc=False, via_reg_mr_ex=False,
                 mr_access=ibv_access_flags.IBV_ACCESS_LOCAL_WRITE,
                 buf_size=None, mr_offset=0, **kwargs):
        init_buf_resource(self, cc, via_reg_mr_ex, mr_access, buf_size,
                          mr_offset)
        super().__init__(*args, **kwargs)

    def create_pd(self):
        create_pd(self)

    def create_cq(self):
        create_cq(self)

    def create_mr(self):
        create_buf_mr(self, self.msg_size, self.buf_size, self.mr_offset)

    def create_qp_attr(self):
        attr = super().create_qp_attr()
        attr.qp_access_flags = self.mr_access
        return attr


class BufUD(UDResources):
    """UD resources whose data buffer is allocated with ibv_alloc_buf()."""
    def __init__(self, *args, cc=False, via_reg_mr_ex=False,
                 mr_access=ibv_access_flags.IBV_ACCESS_LOCAL_WRITE,
                 buf_size=None, mr_offset=0, **kwargs):
        init_buf_resource(self, cc, via_reg_mr_ex, mr_access, buf_size,
                          mr_offset)
        super().__init__(*args, **kwargs)

    def create_pd(self):
        create_pd(self)

    def create_cq(self):
        create_cq(self)

    def create_mr(self):
        # UD prepends a GRH on receive, so the buffer needs room for it.
        mr_len = self.msg_size + self.GRH_SIZE
        create_buf_mr(self, mr_len, self.buf_size, self.mr_offset)


class BufAPITest(PyverbsAPITestCase):
    """Single-node API tests for ibv_alloc_buf()/ibv_reg_buf_mr()."""

    def get_pd(self, cc=False):
        """Create a PD, or a CC PD when cc is set."""
        if cc:
            _, pd = make_cc_pd(self.ctx)
            return pd
        if device_has_cc_dma_bounce(self.ctx):
            raise unittest.SkipTest('Plain-memory registration is rejected on '
                                    'a DMA-bounce device')
        return PD(self.ctx)

    def get_buf(self, pd, size):
        return alloc_buf(pd, size)

    def get_mr(self, pd, buf, length, offset=0, via_reg_mr_ex=False):
        return register_buf_mr(pd, buf, length,
                               ibv_access_flags.IBV_ACCESS_LOCAL_WRITE,
                               offset=offset, via_reg_mr_ex=via_reg_mr_ex)

    def check_multiple_mrs_one_buf(self, pd, via_reg_mr_ex=False):
        """Register two disjoint subranges of one buffer and access them."""
        buf = self.get_buf(pd, 2 * PAGE_SIZE)
        mr1 = self.get_mr(pd, buf, PAGE_SIZE, offset=0,
                          via_reg_mr_ex=via_reg_mr_ex)
        mr2 = self.get_mr(pd, buf, PAGE_SIZE, offset=PAGE_SIZE,
                          via_reg_mr_ex=via_reg_mr_ex)
        self.assertNotEqual(mr1.lkey, mr2.lkey,
                            'MR lkeys for disjoint subranges must differ')
        self.assertEqual(mr1.buf, buf.addr,
                         'MR1 address does not match buffer start')
        self.assertEqual(mr2.buf, buf.addr + PAGE_SIZE,
                         'MR2 address does not match its subrange start')
        mr1.write('a' * PAGE_SIZE, PAGE_SIZE)
        mr2.write('b' * PAGE_SIZE, PAGE_SIZE)
        self.assertEqual(mr1.read(PAGE_SIZE, 0), b'a' * PAGE_SIZE,
                         'MR1 readback does not match written data')
        self.assertEqual(mr2.read(PAGE_SIZE, 0), b'b' * PAGE_SIZE,
                         'MR2 readback does not match written data')

    def test_multiple_mrs_one_buf_plain_pd_reg_buf_mr(self):
        """Plain PD: registered with ibv_reg_buf_mr()."""
        self.check_multiple_mrs_one_buf(self.get_pd())

    def test_multiple_mrs_one_buf_plain_pd_reg_mr_ex(self):
        """Plain PD: registered with the ibv_reg_mr_ex() MASK_BUF path."""
        self.check_multiple_mrs_one_buf(self.get_pd(), via_reg_mr_ex=True)

    def test_multiple_mrs_one_buf_cc_pd_reg_buf_mr(self):
        """CC PD: registered with ibv_reg_buf_mr()."""
        self.check_multiple_mrs_one_buf(self.get_pd(cc=True))

    def check_reg_wrong_allocating_pd_fails(self, pd, other_pd):
        """Registering a buffer with a non-allocating PD must fail."""
        buf = self.get_buf(pd, PAGE_SIZE)
        with self.assertRaises(PyverbsRDMAError) as cm:
            register_buf_mr(other_pd, buf, PAGE_SIZE,
                            ibv_access_flags.IBV_ACCESS_LOCAL_WRITE)
        self.assertEqual(cm.exception.error_code, errno.EINVAL,
                         'Registering a buffer with a non-allocating PD '
                         'must fail with EINVAL')

    def test_buf_reg_wrong_allocating_pd_fails_plain_pd(self):
        """Plain PDs: a non-allocating PD is rejected."""
        self.check_reg_wrong_allocating_pd_fails(self.get_pd(), self.get_pd())

    def test_buf_reg_wrong_allocating_pd_fails_cc_pd(self):
        """CC PDs: a non-allocating PD is rejected."""
        self.check_reg_wrong_allocating_pd_fails(self.get_pd(cc=True),
                                                 self.get_pd(cc=True))

    def check_reg_length_exceeds_buffer_fails(self, pd):
        """Registering a length larger than the buffer must fail."""
        buf = self.get_buf(pd, PAGE_SIZE)
        with self.assertRaises(PyverbsRDMAError) as cm:
            register_buf_mr(pd, buf, 2 * PAGE_SIZE,
                            ibv_access_flags.IBV_ACCESS_LOCAL_WRITE)
        self.assertEqual(cm.exception.error_code, errno.EINVAL,
                         'Registering a length larger than the buffer '
                         'must fail with EINVAL')

    def test_buf_reg_length_exceeds_buffer_fails_plain_pd(self):
        """Plain PD: a too-large length is rejected."""
        self.check_reg_length_exceeds_buffer_fails(self.get_pd())

    def test_buf_reg_length_exceeds_buffer_fails_cc_pd(self):
        """CC PD: a too-large length is rejected."""
        self.check_reg_length_exceeds_buffer_fails(self.get_pd(cc=True))

    def check_reg_offset_length_exceeds_buffer_fails(self, pd):
        """Registering offset + length past the buffer must fail."""
        buf = self.get_buf(pd, PAGE_SIZE)
        with self.assertRaises(PyverbsRDMAError) as cm:
            register_buf_mr(pd, buf, PAGE_SIZE,
                            ibv_access_flags.IBV_ACCESS_LOCAL_WRITE,
                            offset=PAGE_SIZE)
        self.assertEqual(cm.exception.error_code, errno.EINVAL,
                         'Registering past the buffer end via offset '
                         'must fail with EINVAL')

    def test_buf_reg_offset_length_exceeds_buffer_fails_plain_pd(self):
        """Plain PD: an out-of-range offset+length is rejected."""
        self.check_reg_offset_length_exceeds_buffer_fails(self.get_pd())

    def test_buf_reg_offset_length_exceeds_buffer_fails_cc_pd(self):
        """CC PD: an out-of-range offset+length is rejected."""
        self.check_reg_offset_length_exceeds_buffer_fails(self.get_pd(cc=True))

    def test_plain_mr_rejected_on_bounce_device(self):
        """DMA-bounce device: a plain ibv_reg_mr() is rejected."""
        if not device_has_cc_dma_bounce(self.ctx):
            raise unittest.SkipTest('Device does not report CC_DMA_BOUNCE')
        with PD(self.ctx) as pd:
            with self.assertRaises(
                    PyverbsRDMAError,
                    msg='Plain ibv_reg_mr() must be rejected on a '
                        'DMA-bounce device'):
                MR(pd, PAGE_SIZE, ibv_access_flags.IBV_ACCESS_LOCAL_WRITE)


class BufTrafficTest(RDMATestCase):
    """RC/UD traffic over ibv_alloc_buf() data buffers."""
    def test_buf_rc_send_cc_pd_reg_buf_mr(self):
        """CC PD: RC send/recv over a buffer MR."""
        self.create_players(BufRC, cc=True)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_buf_rc_send_large_msg_cc_pd_reg_buf_mr(self):
        """CC PD: RC send/recv with a multi-page buffer MR."""
        self.create_players(BufRC, cc=True, msg_size=16384)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_buf_rc_send_mr_subrange_cc_pd_reg_buf_mr(self):
        """CC PD: RC send/recv over a buffer-subrange MR."""
        self.create_players(BufRC, cc=True, mr_offset=PAGE_SIZE,
                            buf_size=PAGE_SIZE + 16384, msg_size=8192)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_buf_rc_rdma_write_imm_cc_pd_reg_buf_mr(self):
        """CC PD: RC RDMA write-with-immediate into a buffer MR."""
        access = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                  ibv_access_flags.IBV_ACCESS_REMOTE_WRITE)
        self.create_players(BufRC, cc=True, mr_access=access)
        u.traffic(**self.traffic_args, is_cq_ex=True,
                  send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE_WITH_IMM)

    def test_buf_rc_rdma_read_cc_pd_reg_buf_mr(self):
        """CC PD: RC RDMA read from a buffer MR."""
        access = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                  ibv_access_flags.IBV_ACCESS_REMOTE_READ)
        self.create_players(BufRC, cc=True, mr_access=access)
        u.rdma_traffic(**self.traffic_args, is_cq_ex=True,
                       send_op=ibv_wr_opcode.IBV_WR_RDMA_READ)

    def test_buf_rc_atomic_fetch_add_cc_pd_reg_buf_mr(self):
        """CC PD: RC atomic fetch&add on a buffer MR."""
        with d.Context(name=self.dev_name) as ctx:
            atomic_caps = ctx.query_device().atomic_caps
            if atomic_caps == ibv_atomic_cap.IBV_ATOMIC_NONE:
                raise unittest.SkipTest('Atomic operations are not supported')
        access = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                  ibv_access_flags.IBV_ACCESS_REMOTE_WRITE |
                  ibv_access_flags.IBV_ACCESS_REMOTE_ATOMIC)
        self.create_players(BufRC, cc=True, mr_access=access, msg_size=8)
        u.atomic_traffic(**self.traffic_args, is_cq_ex=True,
                         send_op=ibv_wr_opcode.IBV_WR_ATOMIC_FETCH_AND_ADD)

    def test_buf_ud_send_cc_pd_reg_buf_mr(self):
        """CC PD: UD send/recv over a buffer MR."""
        self.create_players(BufUD, cc=True)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_buf_rc_send_plain_pd_reg_buf_mr(self):
        """Plain PD: RC send/recv over a buffer MR."""
        self.create_players(BufRC, cc=False)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_buf_rc_send_cc_pd_reg_mr_ex(self):
        """CC PD: RC send/recv via ibv_reg_mr_ex()."""
        self.create_players(BufRC, cc=True, via_reg_mr_ex=True)
        u.traffic(**self.traffic_args, is_cq_ex=True)
