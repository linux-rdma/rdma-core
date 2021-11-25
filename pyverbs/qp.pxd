# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
cimport pyverbs.libibverbs as v

cdef class QPCap(PyverbsObject):
    cdef v.ibv_qp_cap cap

cdef class QPInitAttr(PyverbsObject):
    cdef v.ibv_qp_init_attr attr
    cdef object scq
    cdef object rcq
    cdef object srq

cdef class QPInitAttrEx(PyverbsObject):
    cdef v.ibv_qp_init_attr_ex attr
    cdef object scq
    cdef object rcq
    cdef object _pd
    cdef object xrcd
    cdef object srq

cdef class QPAttr(PyverbsObject):
    cdef v.ibv_qp_attr attr

cdef class QP(PyverbsCM):
    cdef v.ibv_qp *qp
    cdef int type
    cdef int state
    cdef object pd
    cdef object context
    cdef object xrcd
    cpdef close(self)
    cdef update_cqs(self, init_attr)
    cdef object scq
    cdef object rcq
    cdef object mws
    cdef object srq
    cdef object flows
    cdef object dr_actions
    cdef add_ref(self, obj)

cdef class DataBuffer(PyverbsCM):
    cdef v.ibv_data_buf data

cdef class QPEx(QP):
    cdef v.ibv_qp_ex *qp_ex

cdef class ECE(PyverbsCM):
    cdef v.ibv_ece ece
