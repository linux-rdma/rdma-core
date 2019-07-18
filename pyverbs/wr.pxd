# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

#cython: language_level=3

from .base cimport PyverbsCM
from pyverbs cimport libibverbs as v


cdef class SGE(PyverbsCM):
    cdef v.ibv_sge *sge
    cpdef read(self, length, offset)

cdef class RecvWR(PyverbsCM):
    cdef v.ibv_recv_wr recv_wr

cdef class SendWR(PyverbsCM):
    cdef v.ibv_send_wr send_wr
