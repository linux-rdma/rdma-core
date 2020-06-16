# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

#cython: language_level=3

from posix.stdlib cimport posix_memalign as c_posix_memalign
from libc.stdlib cimport malloc as c_malloc, free as c_free
from libc.stdint cimport uintptr_t
from libc.string cimport memset

def malloc(size):
    """
    Python wrapper for stdlib malloc function
    :param size: The size of the memory block in bytes
    :return: The address of the allocated memory, or 0 if the request fails
    """
    ptr = c_malloc(size)
    if not ptr:
        raise MemoryError('Failed to allocate memory')
    return <uintptr_t>ptr


def posix_memalign(size, alignment=8):
    """
    Python wrapper for the stdlib posix_memalign function.
    The function calls posix_memalign and memsets the memory to 0.
    :param size: The size of the memory block in bytes
    :param alignment: Alignment of the allocated memory, must be a power of two
    :return: The address of the allocated memory, which is a multiple of
             alignment.
    """
    cdef void* ptr
    ret = c_posix_memalign(&ptr, alignment, size)
    if ret:
        raise MemoryError('Failed to allocate memory ({err}'.format(ret))
    memset(ptr, 0, size)
    return <uintptr_t>ptr


def free(ptr):
    """
    Python wrapper for stdlib free function
    :param ptr: The address of a previously allocated memory block
    """
    c_free(<void*><uintptr_t>ptr)
