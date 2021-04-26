# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.device cimport Context
from pyverbs.qp cimport QP, QPEx
from pyverbs.cq cimport CQEX


cdef class Mlx5Context(Context):
    cdef object devx_umems
    cdef object devx_objs
    cdef add_ref(self, obj)
    cpdef close(self)

cdef class Mlx5DVContextAttr(PyverbsObject):
    cdef dv.mlx5dv_context_attr attr

cdef class Mlx5DVContext(PyverbsObject):
    cdef dv.mlx5dv_context dv

cdef class Mlx5DVPortAttr(PyverbsObject):
    cdef dv.mlx5dv_port attr

cdef class Mlx5DCIStreamInitAttr(PyverbsObject):
    cdef dv.mlx5dv_dci_streams dci_streams

cdef class Mlx5DVDCInitAttr(PyverbsObject):
    cdef dv.mlx5dv_dc_init_attr attr

cdef class Mlx5DVQPInitAttr(PyverbsObject):
    cdef dv.mlx5dv_qp_init_attr attr

cdef class Mlx5QP(QPEx):
    cdef object dc_type

cdef class Mlx5DVCQInitAttr(PyverbsObject):
    cdef dv.mlx5dv_cq_init_attr attr

cdef class Mlx5CQ(CQEX):
    pass

cdef class Mlx5VAR(PyverbsObject):
    cdef dv.mlx5dv_var *var
    cdef object context
    cpdef close(self)

cdef class Mlx5PP(PyverbsObject):
    cdef dv.mlx5dv_pp *pp
    cdef object context
    cpdef close(self)

cdef class Mlx5UAR(PyverbsObject):
    cdef dv.mlx5dv_devx_uar *uar
    cdef object context
    cpdef close(self)

cdef class Mlx5DmOpAddr(PyverbsCM):
    cdef void *addr

cdef class WqeSeg(PyverbsCM):
    cdef void *segment
    cpdef _copy_to_buffer(self, addr)

cdef class WqeCtrlSeg(WqeSeg):
    pass

cdef class WqeDataSeg(WqeSeg):
    pass

cdef class Wqe(PyverbsCM):
    cdef void *addr
    cdef int is_user_addr
    cdef object segments

cdef class Mlx5UMEM(PyverbsCM):
    cdef dv.mlx5dv_devx_umem *umem
    cdef Context context
    cdef void *addr
    cdef object is_user_addr

cdef class Mlx5DevxObj(PyverbsCM):
    cdef dv.mlx5dv_devx_obj *obj
    cdef Context context
    cdef object out_view
    cdef object flow_counter_actions
    cdef add_ref(self, obj)

cdef class Mlx5Cqe64(PyverbsObject):
    cdef dv.mlx5_cqe64 *cqe

cdef class Mlx5VfioAttr(PyverbsObject):
    cdef dv.mlx5dv_vfio_context_attr attr
