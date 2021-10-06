# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia Inc. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v
from pyverbs.cq cimport CQ
from pyverbs.pd cimport PD


cdef class WQInitAttr(PyverbsObject):
    cdef v.ibv_wq_init_attr attr
    cdef PD pd
    cdef CQ cq

cdef class WQAttr(PyverbsObject):
    cdef v.ibv_wq_attr attr

cdef class WQ(PyverbsCM):
    cdef v.ibv_wq *wq
    cdef Context context
    cdef PD pd
    cdef CQ cq
    cdef object rwq_ind_tables
    cpdef add_ref(self, obj)

cdef class RwqIndTableInitAttr(PyverbsObject):
    cdef v.ibv_rwq_ind_table_init_attr attr
    cdef object wqs_list

cdef class RwqIndTable(PyverbsCM):
    cdef v.ibv_rwq_ind_table *rwq_ind_table
    cdef Context context
    cdef object wqs
    cdef object qps
    cpdef add_ref(self, obj)

cdef class RxHashConf(PyverbsObject):
    cdef v.ibv_rx_hash_conf rx_hash_conf
