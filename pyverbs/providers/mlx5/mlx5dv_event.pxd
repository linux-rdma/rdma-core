# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2025 Nvidia Inc. All rights reserved. See COPYING file

#cython: language_level=3

cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base cimport PyverbsCM, PyverbsObject


cdef class EventChannel(PyverbsCM):
    cdef dv.mlx5dv_devx_event_channel *ec

cdef class EventHeader(PyverbsObject):
    cdef object cookie
    cdef object data

cdef class EventFD(PyverbsObject):
    cdef int fd
