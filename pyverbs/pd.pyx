# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.
import weakref

from pyverbs.pyverbs_error import PyverbsUserError, PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.device cimport Context, DM
from pyverbs.cmid cimport CMID
from .mr cimport MR, MW, DMMR
from pyverbs.srq cimport SRQ
from pyverbs.addr cimport AH
from pyverbs.qp cimport QP
from libc.errno cimport errno


cdef class PD(PyverbsCM):
    def __cinit__(self, object creator not None):
        """
        Initializes a PD object. A reference for the creating Context is kept
        so that Python's GC will destroy the objects in the right order.
        :param context: The Context object creating the PD
        :return: The newly created PD on success
        """
        if issubclass(type(creator), Context):
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
        self.close_weakrefs([self.qps, self.ahs, self.mws, self.mrs, self.srqs])
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
        else:
            raise PyverbsError('Unrecognized object type')
