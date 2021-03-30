# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base cimport PyverbsObject


cdef class Mlx5dvSchedAttr(PyverbsObject):
    cdef dv.mlx5dv_sched_attr sched_attr
    cdef object parent_sched_node

cdef class Mlx5dvSchedNode(PyverbsObject):
    cdef dv.mlx5dv_sched_node *sched_node
    cdef object context
    cdef object sched_attr
    cpdef close(self)

cdef class Mlx5dvSchedLeaf(PyverbsObject):
    cdef dv.mlx5dv_sched_leaf *sched_leaf
    cdef object context
    cdef object sched_attr
    cpdef close(self)
