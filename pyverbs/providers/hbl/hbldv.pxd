# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2022-2024 HabanaLabs, Ltd.
# Copyright (C) 2023-2024, Intel Corporation.
# All Rights Reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsObject
cimport pyverbs.providers.hbl.libhbl as dv
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v


cdef class HblContext(Context):
    cpdef close(self)

cdef class HblDVContextAttr(PyverbsObject):
    cdef dv.hbldv_ucontext_attr attr

cdef class HblDVPortExAttr(PyverbsObject):
    cdef dv.hbldv_port_ex_attr attr

cdef class HblDVUserFIFOAttr(PyverbsObject):
    cdef dv.hbldv_usr_fifo_attr attr

cdef class HblDVUserFIFO(PyverbsObject):
    cdef dv.hbldv_usr_fifo *usr_fifo

cdef class HblDVCQattr(PyverbsObject):
    cdef dv.hbldv_cq_attr cq_attr

cdef class HblDVQueryCQ(PyverbsObject):
    cdef dv.hbldv_query_cq_attr query_cq_attr

cdef class HblDVCQ(PyverbsObject):
    cdef v.ibv_cq *ibvcq

cdef class HblDVPortAttr(PyverbsObject):
    cdef dv.hbldv_query_port_attr hbl_attr

cdef class HblDVQP(PyverbsObject):
    cdef v.ibv_qp *ibvqp

cdef class HblDVModifyQP(PyverbsObject):
    cdef dv.hbldv_qp_attr attr

cdef class HblDVQueryQP(PyverbsObject):
    cdef dv.hbldv_query_qp_attr query_qp_attr

cdef class HblDVEncapAttr(PyverbsObject):
    cdef dv.hbldv_encap_attr encap_attr

cdef class HblDVEncapOut(PyverbsObject):
    cdef dv.hbldv_encap encap_out

cdef class HblDVEncap(PyverbsObject):
    cdef dv.hbldv_encap *hbldv_encap

cdef class HblDVDeviceAttr(PyverbsObject):
    cdef dv.hbldv_device_attr attr
