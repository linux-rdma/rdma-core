# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for Pyverbs' ParentDomain.
"""
from pyverbs.pd import ParentDomainInitAttr, ParentDomain, ParentDomainContext
from tests.base import RCResources, UDResources, RDMATestCase
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.cq import CqInitAttrEx, CQEX
import pyverbs.mem_alloc as mem
import pyverbs.enums as e
import tests.utils as u

import unittest
import errno


HUGE_PAGE_SIZE = 0x200000


def default_allocator(pd, context, size, alignment, resource_type):
    return e._IBV_ALLOCATOR_USE_DEFAULT


def default_free(pd, context, ptr, resource_type):
    return e._IBV_ALLOCATOR_USE_DEFAULT


def mem_align_allocator(pd, context, size, alignment, resource_type):
    p = mem.posix_memalign(size, alignment)
    return p


def free_func(pd, context, ptr, resource_type):
    mem.free(ptr)


def huge_page_alloc(pd, context, size, alignment, resource_type):
    ptr = context.user_data
    remainder = ptr % alignment
    ptr += 0 if remainder == 0 else (alignment - remainder)
    context.user_data += size
    return ptr


def huge_page_free(pd, context, ptr, resource_type):
    """
    No need to free memory, since this allocator assumes the huge page was
    externally mapped (and will be externally un-mapped).
    """
    pass


def create_parent_domain_with_allocators(res):
    """
    Creates parent domain for res instance. The allocators themselves are taken
    from res.allocator_func and res.free_func.
    :param res: The resources instance to work on (an instance of BaseResources)
    """
    if res.allocator_func and res.free_func:
        res.pd_ctx = ParentDomainContext(res.pd, res.allocator_func,
                                         res.free_func, res.user_data)
    pd_attr = ParentDomainInitAttr(pd=res.pd, pd_context=res.pd_ctx)
    try:
        res.pd = ParentDomain(res.ctx, attr=pd_attr)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EOPNOTSUPP:
            raise unittest.SkipTest('Parent Domain is not supported on this device')
        raise ex


def parent_domain_res_cls(base_class):
    """
    This is a factory function which creates a class that inherits base_class of
    any BaseResources type. Its purpose is to behave exactly as base_class does,
    except for creating a parent domain with custom allocators.
    Hence the returned class must be initialized with (alloc_func, free_func,
    user_data, **kwargs), while kwargs are the arguments needed (if any) for
    base_class.
    :param base_class: The base resources class to inherit from
    :return: ParentDomainRes(alloc_func=None, free_func=None, **kwargs) class
    """
    class ParentDomainRes(base_class):
        def __init__(self, alloc_func=None, free_func=None, user_data=None, **kwargs):
            self.pd_ctx = None
            self.protection_domain = None
            self.allocator_func = alloc_func
            self.free_func = free_func
            self.user_data = user_data
            super().__init__(**kwargs)

        def create_pd(self):
            super().create_pd()
            self.protection_domain = self.pd
            create_parent_domain_with_allocators(self)

    return ParentDomainRes


class ParentDomainHugePageRcRes(parent_domain_res_cls(RCResources)):
    def __init__(self, alloc_func=None, free_func=None, **kwargs):
        user_data = mem.mmap(length=HUGE_PAGE_SIZE,
                             flags=mem.MAP_ANONYMOUS_ | mem.MAP_PRIVATE_ | mem.MAP_HUGETLB_)
        super().__init__(alloc_func=alloc_func, free_func=free_func,
                         user_data=user_data, **kwargs)

    def __del__(self):
        mem.munmap(self.user_data, HUGE_PAGE_SIZE)


class ParentDomainCqExSrqRes(parent_domain_res_cls(RCResources)):
    """
    Parent domain resources. Based on RCResources.
    This includes a parent domain created with the given allocators, in addition
    it creates an extended CQ and a SRQ for RC traffic.
    :param dev_name: Device name to be used
    :param ib_port: IB port of the device to use
    :param gid_index: Which GID index to use
    :param alloc_func: Custom allocator function
    :param free_func: Custom free function
    """
    def __init__(self, dev_name, ib_port=None, gid_index=None, alloc_func=None,
                 free_func=None):
        super().__init__(dev_name=dev_name, ib_port=ib_port,
                         gid_index=gid_index, alloc_func=alloc_func,
                         free_func=free_func, with_srq=True)

    def create_cq(self):
        wc_flags = e.IBV_WC_STANDARD_FLAGS
        cia = CqInitAttrEx(cqe=2000, wc_flags=wc_flags, parent_domain=self.pd,
                           comp_mask=e.IBV_CQ_INIT_ATTR_MASK_FLAGS |
                                     e.IBV_CQ_INIT_ATTR_MASK_PD)
        try:
            self.cq = CQEX(self.ctx, cia)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Extended CQ with Parent Domain is not supported')
            raise ex


class ParentDomainTrafficTest(RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

    def create_players(self, resource, **resource_arg):
        """
        Init Parent Domain tests resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
        attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)
        self.traffic_args = {'client': self.client, 'server': self.server,
                             'iters': self.iters, 'gid_idx': self.gid_index,
                             'port': self.ib_port}

    def test_without_allocators_rc_traffic(self):
        parent_domain_rc_res = parent_domain_res_cls(RCResources)
        self.create_players(parent_domain_rc_res)
        u.traffic(**self.traffic_args)

    def test_default_allocators_rc_traffic(self):
        parent_domain_rc_res = parent_domain_res_cls(RCResources)
        self.create_players(parent_domain_rc_res, alloc_func=default_allocator,
                            free_func=default_free)
        u.traffic(**self.traffic_args)

    def test_mem_align_rc_traffic(self):
        parent_domain_rc_res = parent_domain_res_cls(RCResources)
        self.create_players(parent_domain_rc_res,
                            alloc_func=mem_align_allocator, free_func=free_func)
        u.traffic(**self.traffic_args)

    def test_mem_align_ud_traffic(self):
        parent_domain_ud_res = parent_domain_res_cls(UDResources)
        self.create_players(parent_domain_ud_res,
                            alloc_func=mem_align_allocator, free_func=free_func)
        u.traffic(**self.traffic_args)

    def test_mem_align_srq_excq_rc_traffic(self):
        self.create_players(ParentDomainCqExSrqRes,
                            alloc_func=mem_align_allocator, free_func=free_func)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    @u.requires_huge_pages()
    def test_huge_page_traffic(self):
        self.create_players(ParentDomainHugePageRcRes,
                            alloc_func=huge_page_alloc, free_func=huge_page_free)
        u.traffic(**self.traffic_args)
