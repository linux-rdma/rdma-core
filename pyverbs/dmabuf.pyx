# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020, Intel Corporation. All rights reserved. See COPYING file

#cython: language_level=3

import weakref

from pyverbs.base cimport close_weakrefs
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.mr cimport DmaBufMR

cdef extern from "dmabuf_alloc.h":
    cdef struct dmabuf:
        pass
    dmabuf *dmabuf_alloc(unsigned long size, int gpu, int gtt)
    void dmabuf_free(dmabuf *dmabuf)
    int dmabuf_get_drm_fd(dmabuf *dmabuf)
    int dmabuf_get_fd(dmabuf *dmabuf)
    unsigned long dmabuf_get_offset(dmabuf *dmabuf)


cdef class DmaBuf:
    def __init__(self, size, gpu=0, gtt=0):
        """
        Allocate DmaBuf object from a GPU device. This is done through the
        DRI device interface. Usually this requires the effective user id
        being a member of the 'render' group.
        :param size: The size (in number of bytes) of the buffer.
        :param gpu: The GPU unit to allocate the buffer from.
        :param gtt: Allocate from GTT (Graphics Translation Table) instead of VRAM.
        :return: The newly created DmaBuf object on success.
        """
        self.dmabuf_mrs = weakref.WeakSet()
        self.dmabuf = dmabuf_alloc(size, gpu, gtt)
        if self.dmabuf == NULL:
            raise PyverbsRDMAErrno(f'Failed to allocate dmabuf of size {size} on gpu {gpu}')
        self.drm_fd = dmabuf_get_drm_fd(<dmabuf *>self.dmabuf)
        self.fd = dmabuf_get_fd(<dmabuf *>self.dmabuf)
        self.map_offset = dmabuf_get_offset(<dmabuf *>self.dmabuf)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.dmabuf == NULL:
            return None
        close_weakrefs([self.dmabuf_mrs])
        dmabuf_free(<dmabuf *>self.dmabuf)
        self.dmabuf = NULL

    cdef add_ref(self, obj):
        if isinstance(obj, DmaBufMR):
            self.dmabuf_mrs.add(obj)

    @property
    def drm_fd(self):
        return self.drm_fd

    @property
    def handle(self):
        return self.handle

    @property
    def fd(self):
        return self.fd

    @property
    def size(self):
        return self.size

    @property
    def map_offset(self):
        return self.map_offset
