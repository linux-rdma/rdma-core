# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

from .base cimport PyverbsObject
from pyverbs cimport libibverbs as v


cdef class GID(PyverbsObject):
    cdef v.ibv_gid gid
