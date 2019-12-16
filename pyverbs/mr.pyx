# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

import resource
import logging

from posix.mman cimport mmap, munmap, MAP_PRIVATE, PROT_READ, PROT_WRITE, \
    MAP_ANONYMOUS, MAP_HUGETLB
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from posix.stdlib cimport posix_memalign
from libc.string cimport memcpy, memset
cimport pyverbs.libibverbs_enums as e
from libc.stdint cimport uintptr_t
from pyverbs.device cimport DM
from libc.stdlib cimport free
from .pd cimport PD

cdef extern from 'sys/mman.h':
    cdef void* MAP_FAILED

HUGE_PAGE_SIZE = 0x200000


cdef class MR(PyverbsCM):
    """
    MR class represents ibv_mr. Buffer allocation in done in the c'tor. Freeing
    it is done in close().
    """
    def __init__(self, PD pd not None, length, access, address=None):
        """
        Allocate a user-level buffer of length <length> and register a Memory
        Region of the given length and access flags.
        :param pd: A PD object
        :param length: Length in bytes
        :param access: Access flags, see ibv_access_flags enum
        :param address: Memory address to register (Optional). If it's not
                        provided, a memory will be allocated in the class
                        initialization.
        :return: The newly created MR on success
        """
        super().__init__()
        if self.mr != NULL:
            return
        self.is_huge = True if access & e.IBV_ACCESS_HUGETLB else False
        # We want to enable registering an MR of size 0 but this fails with a
        # buffer of size 0, so in this case lets increase the buffer
        if length == 0:
            length = 10
        if address:
            self.is_user_addr = True
            # uintptr_t is guaranteed to be large enough to hold any pointer.
            # In order to safely cast addr to void*, it is firstly cast to uintptr_t.
            self.buf = <void*><uintptr_t>address
        else:
            if self.is_huge:
                # Rounding up to multiple of HUGE_PAGE_SIZE
                self.mmap_length = length + (HUGE_PAGE_SIZE - length % HUGE_PAGE_SIZE) \
                    if length % HUGE_PAGE_SIZE else length
                self.buf = mmap(NULL, self.mmap_length, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0)
                if self.buf == MAP_FAILED:
                    raise PyverbsError('Failed to allocate MR buffer of size {l}'.
                                       format(l=length))
            else:
                rc = posix_memalign(&self.buf, resource.getpagesize(), length)
                if rc:
                    raise PyverbsError('Failed to allocate MR buffer of size {l}'.
                                       format(l=length))
            memset(self.buf, 0, length)
        self.mr = v.ibv_reg_mr(<v.ibv_pd*>pd.pd, self.buf, length, access)
        if self.mr == NULL:
            raise PyverbsRDMAErrno('Failed to register a MR. length: {l}, access flags: {a}'.
                                   format(l=length, a=access))
        self.pd = pd
        pd.add_ref(self)
        self.logger.debug('Registered ibv_mr. Length: {l}, access flags {a}'.
                          format(l=length, a=access))

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        """
        Closes the underlying C object of the MR and frees the memory allocated.
        MR may be deleted directly or indirectly by closing its context, which
        leaves the Python PD object without the underlying C object, so during
        destruction, need to check whether or not the C object exists.
        :return: None
        """
        self.logger.debug('Closing MR')
        if self.mr != NULL:
            rc = v.ibv_dereg_mr(self.mr)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to dereg MR')
            self.mr = NULL
            self.pd = None
        if not self.is_user_addr:
            if self.is_huge:
                munmap(self.buf, self.mmap_length)
            else:
                free(self.buf)
        self.buf = NULL

    def write(self, data, length):
        """
        Write user data to the MR's buffer using memcpy
        :param data: User data to write
        :param length: Length of the data to write
        :return: None
        """
        # If data is a string, cast it to bytes as Python3 doesn't
        # automatically convert it.
        if isinstance(data, str):
            data = data.encode()
        memcpy(self.buf, <char *>data, length)

    cpdef read(self, length, offset):
        """
        Reads data from the MR's buffer
        :param length: Length of data to read
        :param offset: Reading offset
        :return: The data on the buffer in the requested offset
        """
        cdef char *data
        cdef int off = offset # we can't use offset in the next line, as it is
                              # a Python object and not C
        data = <char*>(self.buf + off)
        return data[:length]

    @property
    def buf(self):
        return <uintptr_t>self.buf

    @property
    def lkey(self):
        return self.mr.lkey

    @property
    def rkey(self):
        return self.mr.rkey


cdef class MW(PyverbsCM):
    def __init__(self, PD pd not None, v.ibv_mw_type mw_type):
        """
        Initializes a memory window object of the given type
        :param pd: A PD object
        :param mw_type: Type of of the memory window, see ibv_mw_type enum
        :return:
        """
        super().__init__()
        self.mw = NULL
        self.mw = v.ibv_alloc_mw(pd.pd, mw_type)
        if self.mw == NULL:
            raise PyverbsRDMAErrno('Failed to allocate MW')
        self.pd = pd
        pd.add_ref(self)
        self.logger.debug('Allocated memory window of type {t}'.
                          format(t=mwtype2str(mw_type)))

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        """
        Closes the underlaying C MW object.
        MW may be deleted directly or by deleting its PD, which leaves the
        Python object without the underlaying MW.
        Need to check that the underlaying MW wasn't dealloced before.
        :return: None
        """
        self.logger.debug('Closing MW')
        if self.mw is not NULL:
            rc = v.ibv_dealloc_mw(self.mw)
            if rc != 0:
               raise PyverbsRDMAErrno('Failed to dealloc MW')
            self.mw = NULL
            self.pd = None


cdef class DMMR(MR):
    def __init__(self, PD pd not None, length, access, DM dm, offset):
        """
        Initializes a DMMR (Device Memory Memory Region) of the given length
        and access flags using the given PD and DM objects.
        :param pd: A PD object
        :param length: Length in bytes
        :param access: Access flags, see ibv_access_flags enum
        :param dm: A DM (device memory) object to be used for this DMMR
        :param offset: Byte offset from the beginning of the allocated device
                       memory buffer
        :return: The newly create DMMR
        """
        # Initialize the logger here as the parent's __init__ is called after
        # the DMMR is allocated. Allocation can fail, which will lead to
        # exceptions thrown during object's teardown.
        self.logger = logging.getLogger(self.__class__.__name__)
        self.mr = v.ibv_reg_dm_mr(pd.pd, dm.dm, offset, length, access)
        if self.mr == NULL:
            raise PyverbsRDMAErrno('Failed to register a device MR. length: {len}, access flags: {flags}'.
                                   format(len=length, flags=access,))
        super().__init__(pd, length, access)
        self.pd = pd
        self.dm = dm
        pd.add_ref(self)
        dm.add_ref(self)
        self.logger.debug('Registered device ibv_mr. Length: {len}, access flags {flags}'.
                          format(len=length, flags=access))

    def write(self, data, length):
        return self.dm.copy_to_dm(0, data, length)

    cpdef read(self, length, offset):
        return self.dm.copy_from_dm(offset, length)


def mwtype2str(mw_type):
    mw_types = {1:'IBV_MW_TYPE_1', 2:'IBV_MW_TYPE_2'}
    try:
        return mw_types[mw_type]
    except KeyError:
        return 'Unknown MW type ({t})'.format(t=mw_type)
