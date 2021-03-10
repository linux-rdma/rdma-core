# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base cimport PyverbsCM
from pyverbs.pd cimport PD


cdef class Mlx5Mkey(PyverbsCM):
    cdef dv.mlx5dv_mkey *mlx5dv_mkey
    cdef PD pd
    cdef object max_entries
