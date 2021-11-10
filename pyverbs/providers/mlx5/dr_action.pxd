# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.providers.mlx5.dr_domain cimport DrDomain
from pyverbs.providers.mlx5.mlx5dv cimport Mlx5DevxObj
from pyverbs.providers.mlx5.dr_table cimport DrTable
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base cimport PyverbsCM
from pyverbs.qp cimport QP


cdef class DrAction(PyverbsCM):
    cdef dv.mlx5dv_dr_action *action
    cdef object dr_rules
    cdef add_ref(self, obj)

cdef class DrActionQp(DrAction):
    cdef QP qp

cdef class DrActionModify(DrAction):
    cdef DrDomain domain

cdef class DrActionFlowCounter(DrAction):
    cdef Mlx5DevxObj devx_obj

cdef class DrActionDrop(DrAction):
    pass

cdef class DrActionTag(DrAction):
    pass

cdef class DrActionDestTable(DrAction):
    cdef DrTable table

cdef class DrActionPushVLan(DrAction):
    cdef DrDomain domain

cdef class DrActionPopVLan(DrAction):
    pass

cdef class DrActionDestAttr(PyverbsCM):
    cdef DrAction dest
    cdef dv.mlx5dv_dr_action_dest_attr *action_dest_attr
    cdef dv.mlx5dv_dr_action_dest_reformat *dest_reformat

cdef class DrActionDestArray(DrAction):
    cdef DrDomain domain
    cdef object dest_actions

cdef class DrActionDefMiss(DrAction):
    pass

cdef class DrActionVPort(DrAction):
    cdef DrDomain domain
    cdef int vport

cdef class DrActionIBPort(DrAction):
    cdef DrDomain domain
    cdef int ib_port
