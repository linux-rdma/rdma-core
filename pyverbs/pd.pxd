# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v
from .base cimport PyverbsCM


cdef class PD(PyverbsCM):
    cdef v.ibv_pd *pd
    cdef Context ctx
    cdef add_ref(self, obj)
    cdef object mrs
    cdef object mws
