# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base cimport PyverbsCM
from pyverbs.qp cimport QP

cdef class DrAction(PyverbsCM):
    cdef dv.mlx5dv_dr_action *action
    cdef object dr_rules
    cdef add_ref(self, obj)

cdef class DrActionQp(DrAction):
    cdef QP qp

