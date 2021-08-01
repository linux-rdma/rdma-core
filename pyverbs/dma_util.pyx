# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

from libc.stdint cimport uintptr_t, uint64_t

cdef extern from 'util/udma_barrier.h':
    cdef void udma_to_device_barrier()
    cdef void udma_from_device_barrier()

cdef extern from 'util/mmio.h':
   cdef void mmio_write64_be(void *addr, uint64_t val)


def udma_to_dev_barrier():
    udma_to_device_barrier()


def udma_from_dev_barrier():
    udma_from_device_barrier()


def mmio_write64_as_be(addr, val):
    mmio_write64_be(<void*><uintptr_t> addr, val)
