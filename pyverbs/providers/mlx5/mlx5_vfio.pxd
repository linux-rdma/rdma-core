# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.providers.mlx5.mlx5dv cimport Mlx5Context
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base cimport PyverbsObject


cdef class Mlx5VfioContext(Mlx5Context):
    pass

cdef class Mlx5VfioAttr(PyverbsObject):
    cdef dv.mlx5dv_vfio_context_attr attr
