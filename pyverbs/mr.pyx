# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.device cimport DM
from .pd cimport PD
import resource

cdef extern from 'stdlib.h':
    int posix_memalign(void **memptr, size_t alignment, size_t size)
cdef extern from 'stdlib.h':
    void free(void *ptr)
cdef extern from 'string.h':
    void *memcpy(void *dest, const void *src, size_t n)
    void *memset(void *s, int c, size_t n)
cdef extern from 'stdint.h':
    ctypedef int uintptr_t


cdef class MR(PyverbsCM):
    """
    MR class represents ibv_mr. Buffer allocation in done in the c'tor. Freeing
    it is done in close().
    """
    def __cinit__(self, PD pd not None, length, access, **kwargs):
        """
        Allocate a user-level buffer of length <length> and register a Memory
        Region of the given length and access flags.
        :param pd: A PD object
        :param length: Length in bytes
        :param access: Access flags, see ibv_access_flags enum
        :return: The newly created MR on success
        """
        if len(kwargs) != 0:
            return
        #We want to enable registering an MR of size 0 but this fails with a
        #buffer of size 0, so in this case lets increase the buffer
        if length == 0:
            length = 10
        rc = posix_memalign(&self.buf, resource.getpagesize(), length)
        if rc:
            raise PyverbsRDMAError('Failed to allocate MR buffer of size {l}'.
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
    def __cinit__(self, PD pd not None, v.ibv_mw_type mw_type):
        """
        Initializes a memory window object of the given type
        :param pd: A PD object
        :param mw_type: Type of of the memory window, see ibv_mw_type enum
        :return:
        """
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
    def __cinit__(self, PD pd not None, length, access, **kwargs):
        """
        Initializes a DMMR (Device Memory Memory Region) of the given length
        and access flags using the given PD and DM objects.
        :param pd: A PD object
        :param length: Length in bytes
        :param access: Access flags, see ibv_access_flags enum
        :param kwargs: see below
        :return: The newly create DMMR

        :keyword Arguments:
            * *dm* (DM)
               A DM (device memory) object to be used for this DMMR
            * *offset*
               Byte offset from the beginning of the allocated device memory
               buffer
        """
        dm = <DM>kwargs['dm']
        offset = kwargs['offset']
        self.mr = v.ibv_reg_dm_mr(pd.pd, (<DM>dm).dm, offset, length, access)
        if self.mr == NULL:
            raise PyverbsRDMAErrno('Failed to register a device MR. length: {len}, access flags: {flags}'.
                                   format(len=length, flags=access,))
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
