# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base cimport PyverbsCM

cdef class DrTable(PyverbsCM):
    cdef dv.mlx5dv_dr_table *table
    cdef object dr_domain
    cdef object dr_matchers
    cdef object dr_actions
    cdef add_ref(self, obj)
