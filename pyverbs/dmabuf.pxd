# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020, Intel Corporation. All rights reserved. See COPYING file

#cython: language_level=3

cdef class DmaBuf:
    cdef int drm_fd
    cdef int handle
    cdef int fd
    cdef unsigned long size
    cdef unsigned long map_offset
    cdef void *dmabuf
    cdef object dmabuf_mrs
    cdef add_ref(self, obj)
    cpdef close(self)
