# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020, Intel Corporation. All rights reserved. See COPYING file
# Copyright 2023 Amazon.com, Inc. or its affiliates. All rights reserved.

#cython: language_level=3

import errno
import weakref

from posix.mman cimport mmap, munmap, MAP_PRIVATE, PROT_READ, PROT_WRITE, MAP_SHARED
from enum import Enum
from pyverbs.base cimport close_weakrefs
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.mr cimport DmaBufMR
from libc.string cimport memcpy, memset
from libc.stdlib cimport free, malloc
from .pyverbs_error import PyverbsRDMAError


class GpuType(Enum):
    drm = 0,


cdef extern from "drm_dmabuf_alloc.h":
    cdef struct drm_dmabuf:
        pass
    drm_dmabuf *drm_dmabuf_alloc(unsigned long size, int gpu, int gtt)
    void drm_dmabuf_free(drm_dmabuf *dmabuf)
    int drm_dmabuf_get_buf_fd(drm_dmabuf *dmabuf)
    int drm_dmabuf_get_device_fd(drm_dmabuf *dmabuf)
    unsigned long drm_dmabuf_get_offset(drm_dmabuf *dmabuf)


cdef extern from 'sys/mman.h':
    cdef void* MAP_FAILED


cdef class DmaBuf:
    def __init__(self, size):
        self.size = size
        self.dmabuf_mrs = weakref.WeakSet()
        self.dmabuf_fd = self._get_dmabuf_fd()
        self.map_offset = self._get_dmabuf_offset()
        self.device_fd = self._get_device_fd()

    cpdef read(self, length, offset):
        raise PyverbsRDMAError("Read from user space isn't supported", errno.EOPNOTSUPP)

    cpdef write(self, data, length, offset):
        raise PyverbsRDMAError("Write from user space isn't supported", errno.EOPNOTSUPP)

    cdef _get_dmabuf_fd(self):
        raise NotImplementedError

    cdef _get_dmabuf_offset(self):
        raise NotImplementedError

    cdef _get_device_fd(self):
        raise NotImplementedError

    cdef _free_dmabuf(self):
        raise NotImplementedError

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.dmabuf == NULL:
            return None
        close_weakrefs([self.dmabuf_mrs])
        self._free_dmabuf()
        self.dmabuf = NULL

    cdef add_ref(self, obj):
        if isinstance(obj, DmaBufMR):
            self.dmabuf_mrs.add(obj)

    @property
    def dmabuf_fd(self):
        return self.dmabuf_fd

    @property
    def device_fd(self):
        return self.device_fd

    @property
    def map_offset(self):
        return self.map_offset

    @property
    def size(self):
        return self.size


cdef class DrmDmaBuf(DmaBuf):
    def __init__(self, size, gpu=0, gtt=0):
        """
        Allocate DrmDmaBuf object from a GPU device. This is done through the
        DRI device interface. Usually this requires the effective user id
        being a member of the 'render' group.
        :param size: The size (in number of bytes) of the buffer.
        :param gpu: The GPU unit to allocate the buffer from.
        :param gtt: Allocate from GTT (Graphics Translation Table) instead of VRAM.
        :return: The newly created DrmDmaBuf object on success.
        """
        self.dmabuf = drm_dmabuf_alloc(size, gpu, gtt)
        if self.dmabuf == NULL:
            raise PyverbsRDMAErrno(f'Failed to allocate dmabuf of size {size} on gpu {gpu}')
        super().__init__(size)

    cpdef read(self, length, offset):
        cdef void *buf = mmap(NULL, length + offset, PROT_READ | PROT_WRITE,
                              MAP_SHARED, self.dmabuf_fd, self.map_offset)
        if buf == MAP_FAILED:
            raise PyverbsRDMAErrno(f'Failed to map dma-buf of size {length}')
        cdef char *data =<char*>malloc(length)
        memset(data, 0, length)
        memcpy(data, <char*>(buf + <int>offset), length)
        munmap(buf, length + offset)
        res = data[:length]
        free(data)
        return res

    cpdef write(self, data, length, offset):
        cdef void *buf = mmap(NULL, length + offset, PROT_READ | PROT_WRITE,
                              MAP_SHARED, self.dmabuf_fd, self.map_offset)
        if buf == MAP_FAILED:
            raise PyverbsRDMAErrno(f'Failed to map dma-buf of size {length}')
        memcpy(<char*>(buf + <int>offset), <char *>data, length)
        munmap(buf, length + offset)

    cdef _get_dmabuf_fd(self):
        return drm_dmabuf_get_buf_fd(<drm_dmabuf *>self.dmabuf)

    cdef _get_dmabuf_offset(self):
        return drm_dmabuf_get_offset(<drm_dmabuf *>self.dmabuf)

    cdef _get_device_fd(self):
        return drm_dmabuf_get_device_fd(<drm_dmabuf *>self.dmabuf)

    cdef _free_dmabuf(self):
        drm_dmabuf_free(<drm_dmabuf *>self.dmabuf)

    @property
    def handle(self):
        return self.handle
