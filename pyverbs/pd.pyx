# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.
import weakref
import logging

from pyverbs.pyverbs_error import PyverbsUserError, PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
from pyverbs.device cimport Context
from libc.stdint cimport uintptr_t
from pyverbs.cmid cimport CMID
from .mr cimport MR, MW, DMMR
from pyverbs.srq cimport SRQ
from pyverbs.addr cimport AH
from pyverbs.qp cimport QP


cdef class PD(PyverbsCM):
    def __init__(self, object creator not None):
        """
        Initializes a PD object. A reference for the creating Context is kept
        so that Python's GC will destroy the objects in the right order.
        :param creator: The Context/CMID object creating the PD
        """
        super().__init__()
        if issubclass(type(creator), Context):
            # Check if the ibv_pd* was initialized by an inheriting class
            if self.pd == NULL:
                self.pd = v.ibv_alloc_pd((<Context>creator).context)
                if self.pd == NULL:
                    raise PyverbsRDMAErrno('Failed to allocate PD')
            self.ctx = creator
        elif issubclass(type(creator), CMID):
            cmid = <CMID>creator
            self.pd = cmid.id.pd
            self.ctx = cmid.ctx
            cmid.pd = self
        else:
            raise PyverbsUserError('Cannot create PD from {type}'
                                   .format(type=type(creator)))
        self.ctx.add_ref(self)
        self.logger.debug('PD: Allocated ibv_pd')
        self.srqs = weakref.WeakSet()
        self.mrs = weakref.WeakSet()
        self.mws = weakref.WeakSet()
        self.ahs = weakref.WeakSet()
        self.qps = weakref.WeakSet()
        self.parent_domains = weakref.WeakSet()

    def __dealloc__(self):
        """
        Closes the inner PD.
        :return: None
        """
        self.close()

    cpdef close(self):
        """
        Closes the underlying C object of the PD.
        PD may be deleted directly or indirectly by closing its context, which
        leaves the Python PD object without the underlying C object, so during
        destruction, need to check whether or not the C object exists.
        :return: None
        """
        self.logger.debug('Closing PD')
        close_weakrefs([self.parent_domains, self.qps, self.ahs, self.mws,
                        self.mrs, self.srqs])
        if self.pd != NULL:
            rc = v.ibv_dealloc_pd(self.pd)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to dealloc PD')
            self.pd = NULL
            self.ctx = None

    cdef add_ref(self, obj):
        if isinstance(obj, MR) or isinstance(obj, DMMR):
            self.mrs.add(obj)
        elif isinstance(obj, MW):
            self.mws.add(obj)
        elif isinstance(obj, AH):
            self.ahs.add(obj)
        elif isinstance(obj, QP):
            self.qps.add(obj)
        elif isinstance(obj, SRQ):
            self.srqs.add(obj)
        elif isinstance(obj, ParentDomain):
            self.parent_domains.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')


cdef void *pd_alloc(v.ibv_pd *pd, void *pd_context, size_t size,
                  size_t alignment, v.uint64_t resource_type):
    """
    Parent Domain allocator wrapper. This function is used to wrap a
    user-defined Python alloc function which should be a part of pd_context.
    :param pd: Parent domain
    :param pd_context: User-specific context of type ParentDomainContext
    :param size: Size of the requested buffer
    :param alignment: Alignment of the requested buffer
    :param resource_type: Vendor-specific resource type
    :return: Pointer to the allocated buffer, or NULL to designate an error.
             It may also return IBV_ALLOCATOR_USE_DEFAULT asking the callee to
             allocate the buffer using the default allocator.

    """
    cdef ParentDomainContext pd_ctx
    pd_ctx = <object>pd_context
    ptr = <uintptr_t>pd_ctx.p_alloc(pd_ctx.pd, pd_ctx, size, alignment,
                                    resource_type)
    return <void*>ptr


cdef void pd_free(v.ibv_pd *pd, void *pd_context, void *ptr,
                     v.uint64_t resource_type):
    """
    Parent Domain deallocator wrapper. This function is used to wrap a
    user-defined Python free function which should be part of pd_context.
    :param pd: Parent domain
    :param pd_context: User-specific context of type ParentDomainContext
    :param ptr: Pointer to the buffer to be freed
    :param resource_type: Vendor-specific resource type
    """
    cdef ParentDomainContext pd_ctx
    pd_ctx = <object>pd_context
    pd_ctx.p_free(pd_ctx.pd, pd_ctx, <uintptr_t>ptr, resource_type)


cdef class ParentDomainContext(PyverbsObject):
    def __init__(self, PD pd, alloc_func, free_func):
        """
        Initializes ParentDomainContext object which is used as a pd_context.
        It contains the relevant fields in order to allow the user to write
        alloc and free functions in Python
        :param pd: PD object that represents the ibv_pd which is passed to the
                  creation of the Parent Domain
        :param alloc_func: Python alloc function
        :param free_func: Python free function
        """
        super().__init__()
        self.pd = pd
        self.p_alloc = alloc_func
        self.p_free = free_func


cdef class ParentDomainInitAttr(PyverbsObject):
    def __init__(self, PD pd not None, ParentDomainContext pd_context=None):
        """
        Represents ibv_parent_domain_init_attr C struct
        :param pd: PD to initialize the ParentDomain with
        :param pd_context: ParentDomainContext object including the alloc and
                          free Python callbacks
        """
        super().__init__()
        self.pd = pd
        self.init_attr.pd = <v.ibv_pd*>pd.pd
        if pd_context:
            self.init_attr.alloc = pd_alloc
            self.init_attr.free = pd_free
            self.init_attr.pd_context = <void*>pd_context
            # The only way to use Python callbacks is to pass the (Python)
            # functions through pd_context. Hence, we must set PD_CONTEXT
            # in the comp mask.
            self.init_attr.comp_mask = v.IBV_PARENT_DOMAIN_INIT_ATTR_PD_CONTEXT | \
                                       v.IBV_PARENT_DOMAIN_INIT_ATTR_ALLOCATORS

    @property
    def comp_mask(self):
        return self.init_attr.comp_mask


cdef class ParentDomain(PD):
    def __init__(self, Context context not None, ParentDomainInitAttr attr not None):
        """
        Initializes ParentDomain object which represents a parent domain of
        ibv_pd C struct type
        :param context: Device context
        :param attr: Attribute of type ParentDomainInitAttr to initialize the
                     ParentDomain with
        """
        # Initialize the logger here as the parent's __init__ is called after
        # the PD is allocated. Allocation can fail, which will lead to exceptions
        # thrown during object's teardown.
        self.logger = logging.getLogger(self.__class__.__name__)
        (<PD>attr.pd).add_ref(self)
        self.protection_domain = attr.pd
        self.pd = v.ibv_alloc_parent_domain(context.context, &attr.init_attr)
        if self.pd == NULL:
            raise PyverbsRDMAErrno('Failed to allocate Parent Domain')
        super().__init__(context)
        self.logger.debug('Allocated ParentDomain')

    def __dealloc__(self):
        self.__close(True)

    cpdef close(self):
        self.__close()

    def __close(self, from_dealloc=False):
        """
        The close function can be called either explicitly by the user, or
        implicitly (from __dealloc__). In the case it was called by dealloc,
        the close function of the PD would have been already called, thus
        freeing the PD of this parent domain and no need to dealloc it again
        :param from_dealloc: Indicates whether the close was called via dealloc
        """
        self.logger.debug('Closing ParentDomain')
        if not from_dealloc:
            super(ParentDomain, self).close()
