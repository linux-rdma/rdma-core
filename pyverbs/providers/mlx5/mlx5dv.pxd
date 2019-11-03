# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

#cython: language_level=3

cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base cimport PyverbsObject
from pyverbs.device cimport Context

cdef class Mlx5Context(Context):
    pass

cdef class Mlx5DVContextAttr(PyverbsObject):
    cdef dv.mlx5dv_context_attr attr

cdef class Mlx5DVContext(PyverbsObject):
    cdef dv.mlx5dv_context dv
