# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

from .base cimport PyverbsObject, PyverbsCM
cimport pyverbs.libibverbs as v


cdef class Context(PyverbsCM):
    cdef v.ibv_context *context
    cdef object name
    cdef add_ref(self, obj)
    cdef object pds

cdef class DeviceAttr(PyverbsObject):
    cdef v.ibv_device_attr dev_attr
