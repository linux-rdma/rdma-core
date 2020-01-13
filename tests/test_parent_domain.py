# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for Pyverbs' ParentDomain.
"""
from pyverbs.pd import ParentDomainInitAttr, ParentDomain, ParentDomainContext
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.srq import SrqAttr, SrqInitAttr, SRQ
from pyverbs.qp import QPInitAttr, QP
from tests.base import BaseResources
from tests.base import RDMATestCase
import pyverbs.mem_alloc as mem
import pyverbs.enums as e
from pyverbs.cq import CQ
import tests.utils as u
import unittest


class ParentDomainRes(BaseResources):
    def __init__(self, dev_name, ib_port=None, gid_index=None):
        super().__init__(dev_name=dev_name, ib_port=ib_port,
                         gid_index=gid_index)
        # Parent Domain will be created according to the test
        self.pd_ctx = None
        self.parent_domain = None


class ParentDomainTestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        self.pd_res = ParentDomainRes(self.dev_name)

    def _create_parent_domain_with_allocators(self, alloc_func, free_func):
        if alloc_func and free_func:
            self.pd_res.pd_ctx = ParentDomainContext(self.pd_res.pd, alloc_func,
                                                     free_func)
        pd_attr = ParentDomainInitAttr(pd=self.pd_res.pd,
                                       pd_context=self.pd_res.pd_ctx)
        try:
            self.pd_res.parent_domain = ParentDomain(self.pd_res.ctx,
                                                     attr=pd_attr)
        except PyverbsRDMAError as ex:
            if 'not supported' in str(ex) or 'not implemented' in str(ex):
                raise unittest.SkipTest('Parent Domain is not supported on this device')
            raise ex

    def _create_rdma_objects(self):
        cq = CQ(self.pd_res.ctx, 100, None, None, 0)
        dev_attr = self.pd_res.ctx.query_device()
        qp_cap = u.random_qp_cap(dev_attr)
        qia = QPInitAttr(scq=cq, rcq=cq, cap=qp_cap)
        qia.qp_type = e.IBV_QPT_RC
        QP(self.pd_res.parent_domain, qia)
        srq_init_attr = SrqInitAttr(SrqAttr())
        SRQ(self.pd_res.parent_domain, srq_init_attr)

    def test_without_allocators(self):
        self._create_parent_domain_with_allocators(None, None)
        self._create_rdma_objects()
        self.pd_res.parent_domain.close()

    def test_default_allocators(self):
        def alloc_p_func(pd, context, size, alignment, resource_type):
            return e._IBV_ALLOCATOR_USE_DEFAULT

        def free_p_func(pd, context, ptr, resource_type):
            return e._IBV_ALLOCATOR_USE_DEFAULT

        self._create_parent_domain_with_allocators(alloc_p_func, free_p_func)
        self._create_rdma_objects()
        self.pd_res.parent_domain.close()

    def test_mem_align_allocators(self):
        def alloc_p_func(pd, context, size, alignment, resource_type):
            p = mem.posix_memalign(size, alignment)
            return p

        def free_p_func(pd, context, ptr, resource_type):
            mem.free(ptr)

        self._create_parent_domain_with_allocators(alloc_p_func, free_p_func)
        self._create_rdma_objects()
        self.pd_res.parent_domain.close()
