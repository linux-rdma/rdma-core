# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base cimport PyverbsObject


cdef class Mlx5DvPD(PyverbsObject):
    cdef dv.mlx5dv_pd dv_pd

cdef class Mlx5DvCQ(PyverbsObject):
    cdef dv.mlx5dv_cq dv_cq

cdef class Mlx5DvQP(PyverbsObject):
    cdef dv.mlx5dv_qp dv_qp

cdef class Mlx5DvSRQ(PyverbsObject):
    cdef dv.mlx5dv_srq dv_srq

cdef class Mlx5DvObj(PyverbsObject):
    cdef dv.mlx5dv_obj obj
    cdef Mlx5DvCQ dv_cq
    cdef Mlx5DvQP dv_qp
    cdef Mlx5DvPD dv_pd
    cdef Mlx5DvSRQ dv_srq

