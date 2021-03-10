# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.pd cimport PD


cdef class Mlx5MrInterleaved(PyverbsObject):
    cdef dv.mlx5dv_mr_interleaved mlx5dv_mr_interleaved

cdef class Mlx5Mkey(PyverbsCM):
    cdef dv.mlx5dv_mkey *mlx5dv_mkey
    cdef PD pd
    cdef object max_entries
