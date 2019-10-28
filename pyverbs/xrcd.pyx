# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.
import weakref

from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.device cimport Context
from pyverbs.qp cimport QP

cdef extern from 'errno.h':
    int errno


cdef class XRCDInitAttr(PyverbsObject):
    def __cinit__(self, comp_mask, oflags, fd):
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
    def __cinit__(self, Context context not None, XRCDInitAttr init_attr not None):
        """
        Initializes a XRCD object.
        :param context: The Context object creating the XRCD
        :return: The newly created XRCD on success
        """
        self.xrcd = v.ibv_open_xrcd(<v.ibv_context*> context.context,
                                    &init_attr.attr)
        if self.xrcd == NULL:
            raise PyverbsRDMAErrno('Failed to allocate XRCD', errno)
        self.ctx = context
        context.add_ref(self)
        self.logger.debug('XRCD: Allocated ibv_xrcd')
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
        self.close_weakrefs([self.qps])
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
        else:
            raise PyverbsError('Unrecognized object type')
