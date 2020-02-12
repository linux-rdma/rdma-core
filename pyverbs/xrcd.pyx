# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.
import weakref

from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
from pyverbs.device cimport Context
from pyverbs.srq cimport SRQ
from pyverbs.qp cimport QP
from libc.errno cimport errno


cdef class XRCDInitAttr(PyverbsObject):
    def __init__(self, comp_mask, oflags, fd):
        super().__init__()
        self.attr.fd = fd
        self.attr.comp_mask = comp_mask
        self.attr.oflags = oflags

    @property
    def fd(self):
        return self.attr.fd
    @fd.setter
    def fd(self, val):
        self.attr.fd = val

    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val

    @property
    def oflags(self):
        return self.attr.oflags
    @oflags.setter
    def oflags(self, val):
        self.attr.oflags = val


cdef class XRCD(PyverbsCM):
    def __init__(self, Context context not None, XRCDInitAttr init_attr not None):
        """
        Initializes a XRCD object.
        :param context: The Context object creating the XRCD
        :return: The newly created XRCD on success
        """
        super().__init__()
        self.xrcd = v.ibv_open_xrcd(<v.ibv_context*> context.context,
                                    &init_attr.attr)
        if self.xrcd == NULL:
            raise PyverbsRDMAErrno('Failed to allocate XRCD')
        self.ctx = context
        context.add_ref(self)
        self.logger.debug('XRCD: Allocated ibv_xrcd')
        self.srqs = weakref.WeakSet()
        self.qps = weakref.WeakSet()

    def __dealloc__(self):
        """
        Closes the inner XRCD.
        :return: None
        """
        self.close()

    cpdef close(self):
        """
        Closes the underlying C object of the XRCD.
        :return: None
        """
        self.logger.debug('Closing XRCD')
        close_weakrefs([self.qps, self.srqs])
        # XRCD may be deleted directly or indirectly by closing its context,
        # which leaves the Python XRCD object without the underlying C object,
        # so during destruction, need to check whether or not the C object
        # exists.
        if self.xrcd != NULL:
            rc = v.ibv_close_xrcd(self.xrcd)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to dealloc XRCD')
            self.xrcd = NULL
            self.ctx = None

    cdef add_ref(self, obj):
        if isinstance(obj, QP):
            self.qps.add(obj)
        elif isinstance(obj, SRQ):
            self.srqs.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')
