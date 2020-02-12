# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

#cython: language_level=3

cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.device cimport Context, VAR
from pyverbs.base cimport PyverbsObject
from pyverbs.cq cimport CQEX
from pyverbs.qp cimport QP


cdef class Mlx5Context(Context):
    pass

cdef class Mlx5DVContextAttr(PyverbsObject):
    cdef dv.mlx5dv_context_attr attr

cdef class Mlx5DVContext(PyverbsObject):
    cdef dv.mlx5dv_context dv

cdef class Mlx5DVDCInitAttr(PyverbsObject):
    cdef dv.mlx5dv_dc_init_attr attr

cdef class Mlx5DVQPInitAttr(PyverbsObject):
    cdef dv.mlx5dv_qp_init_attr attr

cdef class Mlx5QP(QP):
    cdef object dc_type

cdef class Mlx5DVCQInitAttr(PyverbsObject):
    cdef dv.mlx5dv_cq_init_attr attr

cdef class Mlx5CQ(CQEX):
    pass

cdef class Mlx5VAR(VAR):
    cdef dv.mlx5dv_var *var
    cpdef close(self)
