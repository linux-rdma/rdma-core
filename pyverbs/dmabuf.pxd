# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020, Intel Corporation. All rights reserved. See COPYING file
# Copyright 2023 Amazon.com, Inc. or its affiliates. All rights reserved.

#cython: language_level=3

cdef class DmaBuf:
    cdef void *dmabuf
    cdef object dmabuf_mrs
    cdef unsigned long size
    cdef int dmabuf_fd
    cdef int device_fd
    cdef unsigned long map_offset
    cdef add_ref(self, obj)
    cpdef read(self, length, offset)
    cpdef write(self, data, length, offset)
    cpdef close(self)
    cdef _get_dmabuf_fd(self)
    cdef _get_device_fd(self)
    cdef _get_dmabuf_offset(self)
    cdef _free_dmabuf(self)


cdef class DrmDmaBuf(DmaBuf):
    cdef int handle
