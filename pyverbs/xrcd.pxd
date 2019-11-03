# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsCM, PyverbsObject
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v


cdef class XRCDInitAttr(PyverbsObject):
    cdef v.ibv_xrcd_init_attr attr


cdef class XRCD(PyverbsCM):
    cdef v.ibv_xrcd *xrcd
    cdef Context ctx
    cdef add_ref(self, obj)
    cdef object srqs
    cdef object qps
