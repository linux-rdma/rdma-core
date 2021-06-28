# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

#cython: language_level=3

from posix.stdlib cimport posix_memalign as c_posix_memalign
from libc.stdlib cimport malloc as c_malloc, free as c_free
from posix.mman cimport mmap as c_mmap, munmap as c_munmap
from libc.stdint cimport uintptr_t, uint32_t, uint64_t
from libc.string cimport memset
cimport posix.mman as mm

cdef extern from 'sys/mman.h':
    cdef void* MAP_FAILED

cdef extern from 'endian.h':
    unsigned long htobe32(unsigned long host_32bits)
    unsigned long htobe64(unsigned long host_64bits)


def mmap(addr=0, length=100, prot=mm.PROT_READ | mm.PROT_WRITE,
         flags=mm.MAP_PRIVATE | mm.MAP_ANONYMOUS, fd=0, offset=0):
    """
    Python wrapper for sys mmap function
    :param addr: Address to mmap the memory
    :param length: The length of the requested memory in bytes
    :param prot: Indicate the protection of this memory
    :param flags: Specify speicific flags to this memory
    :param fd: File descriptor to mmap specific file
    :param offset: Offset to use when mmap
    :return: The address to the mapped memory
    """
    # uintptr_t is guaranteed to be large enough to hold any pointer.
    # In order to safely cast addr to void*, it is firstly cast to uintptr_t.
    ptr = c_mmap(<void*><uintptr_t>addr, length, prot, flags, fd, offset)
    if <void *>ptr == MAP_FAILED:
        raise MemoryError('Failed to mmap memory')
    return <uintptr_t> ptr


def munmap(addr, length):
    """
    Python wrapper for sys munmap function
    :param addr: The address of the mapped memory to unmap
    :param length: The length of this mapped memory
    """
    ret = c_munmap(<void*><uintptr_t>addr, length)
    if ret:
        raise MemoryError('Failed to munmap requested memory')


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


def writebe32(addr, val, offset=0):
    """
    Write 32-bit value <val> as Big Endian to address <addr> and offset <offset>
    :param addr: The start of the address to write the value to
    :param val: Value to write
    :param offset: Offset of the address  to write the value to (in 4-bytes)
    """
    (<uint32_t*><void*><uintptr_t>addr)[offset] = htobe32(val)


def writebe64(addr, val, offset=0):
    """
    Write 64-bit value <val> as Big Endian to address <addr> and offset <offset>
    :param addr: The start of the address to write the value to
    :param val: Value to write
    :param offset: Offset of the address  to write the value to (in 8-bytes)
    """
    (<uint64_t*><void*><uintptr_t>addr)[offset] = htobe64(val)


def read32(addr, offset=0):
    """
    Read 32-bit value from address <addr> and offset <offset>
    :param addr: The start of the address to read from
    :param offset: Offset of the address to read from (in 4-bytes)
    :return: The read value
    """
    return (<uint32_t*><uintptr_t>addr)[offset]


def read64(addr, offset=0):
    """
    Read 64-bit value from address <addr> and offset <offset>
    :param addr: The start of the address to read from
    :param offset: Offset of the address to read from (in 8-bytes)
    :return: The read value
    """
    return (<uint64_t*><uintptr_t>addr)[offset]


# protection bits for mmap/mprotect
PROT_EXEC_ = mm.PROT_EXEC
PROT_READ_ = mm.PROT_READ
PROT_WRITE_ = mm.PROT_WRITE
PROT_NONE_ = mm.PROT_NONE

# flag bits for mmap
MAP_PRIVATE_ = mm.MAP_PRIVATE
MAP_SHARED_ = mm.MAP_SHARED
MAP_FIXED_ = mm.MAP_FIXED
MAP_ANONYMOUS_ = mm.MAP_ANONYMOUS
MAP_STACK_ = mm.MAP_STACK
MAP_LOCKED_ = mm.MAP_LOCKED
MAP_HUGETLB_ = mm.MAP_HUGETLB
MAP_POPULATE_ = mm.MAP_POPULATE
MAP_NORESERVE_ = mm.MAP_NORESERVE
MAP_GROWSDOWN_ = mm.MAP_GROWSDOWN
