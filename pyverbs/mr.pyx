# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file
# Copyright (c) 2020, Intel Corporation. All rights reserved. See COPYING file

import resource
import logging

from posix.mman cimport mmap, munmap, MAP_PRIVATE, PROT_READ, PROT_WRITE, \
    MAP_ANONYMOUS, MAP_HUGETLB, MAP_SHARED
from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError, \
    PyverbsUserError
from libc.stdint cimport uintptr_t, SIZE_MAX
from pyverbs.utils import rereg_error_to_str
from pyverbs.base import PyverbsRDMAErrno
from posix.stdlib cimport posix_memalign
from libc.string cimport memcpy, memset
cimport pyverbs.libibverbs_enums as e
from pyverbs.device cimport DM
from libc.stdlib cimport free, malloc
from .cmid cimport CMID
from .pd cimport PD
from .dmabuf cimport DmaBuf

cdef extern from 'sys/mman.h':
    cdef void* MAP_FAILED

HUGE_PAGE_SIZE = 0x200000


cdef class MR(PyverbsCM):
    """
    MR class represents ibv_mr. Buffer allocation in done in the c'tor. Freeing
    it is done in close().
    """
    def __init__(self, creator not None, length=0, access=0, address=None,
                 implicit=False, **kwargs):
        """
        Allocate a user-level buffer of length <length> and register a Memory
        Region of the given length and access flags.
        :param creator: A PD/CMID object. In case of CMID is passed the MR will
                        be registered using rdma_reg_msgs/write/read according
                        to the passed access flag of local_write/remote_write or
                        remote_read respectively.
        :param length: Length (in bytes) of MR's buffer.
        :param access: Access flags, see ibv_access_flags enum
        :param address: Memory address to register (Optional). If it's not
                        provided, a memory will be allocated in the class
                        initialization.
        :param implicit: Implicit the MR address.
        :param kwargs: Arguments:
            * *handle*
                A valid kernel handle for a MR object in the given PD (creator).
                If passed, the MR will be imported and associated with the
                context that is associated with the given PD using ibv_import_mr.
        :return: The newly created MR on success
        """
        super().__init__()
        if self.mr != NULL:
            return
        self.is_huge = True if access & e.IBV_ACCESS_HUGETLB else False
        if address:
            self.is_user_addr = True
            # uintptr_t is guaranteed to be large enough to hold any pointer.
            # In order to safely cast addr to void*, it is firstly cast to uintptr_t.
            self.buf = <void*><uintptr_t>address

        mr_handle = kwargs.get('handle')
        # If a MR handle is passed import MR and finish
        if mr_handle is not None:
            pd = <PD>creator
            self.mr = v.ibv_import_mr(pd.pd, mr_handle)
            if self.mr == NULL:
                raise PyverbsRDMAErrno('Failed to import MR')
            self._is_imported = True
            self.pd = pd
            pd.add_ref(self)
            return

        # Allocate a buffer
        if not address and length > 0:
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
        if isinstance(creator, PD):
            pd = <PD>creator
            if implicit:
                self.mr = v.ibv_reg_mr(pd.pd, NULL, SIZE_MAX, access)
            else:
                self.mr = v.ibv_reg_mr(pd.pd, self.buf, length, access)
            self.pd = pd
            pd.add_ref(self)
        elif isinstance(creator, CMID):
            cmid = <CMID>creator
            if access == e.IBV_ACCESS_LOCAL_WRITE:
                self.mr = cm.rdma_reg_msgs(cmid.id, self.buf, length)
            elif access == e.IBV_ACCESS_REMOTE_WRITE:
                self.mr = cm.rdma_reg_write(cmid.id, self.buf, length)
            elif access == e.IBV_ACCESS_REMOTE_READ:
                self.mr = cm.rdma_reg_read(cmid.id, self.buf, length)
            self.cmid = cmid
            cmid.add_ref(self)
        if self.mr == NULL:
            raise PyverbsRDMAErrno('Failed to register a MR. length: {l}, access flags: {a}'.
                                   format(l=length, a=access))
        self.logger.debug('Registered ibv_mr. Length: {l}, access flags {a}'.
                          format(l=length, a=access))

    def unimport(self):
        v.ibv_unimport_mr(self.mr)
        self.close()

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        """
        Closes the underlying C object of the MR and frees the memory allocated.
        MR may be deleted directly or indirectly by closing its context, which
        leaves the Python PD object without the underlying C object, so during
        destruction, need to check whether or not the C object exists.
        In case of an imported MR no deregistration will be done, it's left
        for the original MR, in order to prevent double dereg by the GC.
        :return: None
        """
        if self.mr != NULL:
            self.logger.debug('Closing MR')
            if not self._is_imported:
                rc = v.ibv_dereg_mr(self.mr)
                if rc != 0:
                    raise PyverbsRDMAError('Failed to dereg MR', rc)
                if not self.is_user_addr:
                    if self.is_huge:
                        munmap(self.buf, self.mmap_length)
                    else:
                        free(self.buf)
            self.mr = NULL
            self.pd = None
            self.buf = NULL
            self.cmid = None

    def write(self, data, length, offset=0):
        """
        Write user data to the MR's buffer using memcpy
        :param data: User data to write
        :param length: Length of the data to write
        :param offset: Writing offset
        :return: None
        """
        if not self.buf or length < 0:
            raise PyverbsUserError('The MR buffer isn\'t allocated or length'
                                   f' {length} is invalid')
        # If data is a string, cast it to bytes as Python3 doesn't
        # automatically convert it.
        cdef int off = offset
        if isinstance(data, str):
            data = data.encode()
        memcpy(<char*>(self.buf + off), <char *>data, length)

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
        if offset < 0:
            raise PyverbsUserError(f'Invalid offset {offset}')
        if not self.buf or length < 0:
            raise PyverbsUserError('The MR buffer isn\'t allocated or length'
                                   f' {length} is invalid')
        data = <char*>(self.buf + off)
        return data[:length]

    def rereg(self, flags, PD pd=None, addr=0, length=0, access=0):
        """
        Modifies the attributes of an existing memory region.
        :param flags: Bit-mask used to indicate which of the properties of the
                      MR are being modified
        :param pd: New PD
        :param addr: New addr to reg the MR on
        :param length: New length of memory to reg
        :param access: New MR access
        :return: None
        """
        ret = v.ibv_rereg_mr(self.mr, flags, pd.pd, <void*><uintptr_t>addr,
                             length, access)
        if ret != 0:
            err_msg = rereg_error_to_str(ret)
            raise PyverbsRDMAErrno(f'Failed to rereg MR: {err_msg}')

        if flags & e.IBV_REREG_MR_CHANGE_TRANSLATION:
            if not self.is_user_addr:
                if self.is_huge:
                    munmap(self.buf, self.mmap_length)
                else:
                    free(self.buf)
            self.buf = <void*><uintptr_t>addr
            self.is_user_addr = True

        if flags & e.IBV_REREG_MR_CHANGE_PD:
            (<PD>self.pd).remove_ref(self)
            self.pd = pd
            pd.add_ref(self)

    @property
    def buf(self):
        return <uintptr_t>self.buf

    @property
    def lkey(self):
        return self.mr.lkey

    @property
    def rkey(self):
        return self.mr.rkey

    @property
    def length(self):
        return self.mr.length

    @property
    def handle(self):
        return self.mr.handle

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return 'MR\n' + \
               print_format.format('lkey', self.lkey) + \
               print_format.format('rkey', self.rkey) + \
               print_format.format('length', self.length) + \
               print_format.format('buf', <uintptr_t>self.buf) + \
               print_format.format('handle', self.handle)


cdef class MWBindInfo(PyverbsCM):
    def __init__(self, MR mr not None, addr, length, mw_access_flags):
        super().__init__()
        self.mr = mr
        self.info.mr = mr.mr
        self.info.addr = addr
        self.info.length = length
        self.info.mw_access_flags = mw_access_flags

    @property
    def mw_access_flags(self):
        return self.info.mw_access_flags

    @property
    def length(self):
        return self.info.length

    @property
    def addr(self):
        return self.info.addr

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return 'MWBindInfo:\n' +\
            print_format.format('Addr', self.info.addr) +\
            print_format.format('Length', self.info.length) +\
            print_format.format('MW access flags', self.info.mw_access_flags)


cdef class MWBind(PyverbsCM):
    def __init__(self, MWBindInfo info not None,send_flags, wr_id=0):
        super().__init__()
        self.mw_bind.wr_id = wr_id
        self.mw_bind.send_flags = send_flags
        self.mw_bind.bind_info = info.info

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return 'MWBind:\n' +\
            print_format.format('WR id', self.mw_bind.wr_id) +\
            print_format.format('Send flags', self.mw_bind.send_flags)


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
        if self.mw is not NULL:
            self.logger.debug('Closing MW')
            rc = v.ibv_dealloc_mw(self.mw)
            if rc != 0:
                raise PyverbsRDMAError('Failed to dealloc MW', rc)
            self.mw = NULL
            self.pd = None

    @property
    def handle(self):
        return self.mw.handle

    @property
    def rkey(self):
        return self.mw.rkey

    @property
    def type(self):
        return self.mw.type

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return 'MW:\n' +\
            print_format.format('Rkey', self.mw.rkey) +\
            print_format.format('Handle', self.mw.handle) +\
            print_format.format('MW Type', mwtype2str(self.mw.type))


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

    def write(self, data, length, offset=0):
        if isinstance(data, str):
            data = data.encode()
        return self.dm.copy_to_dm(offset, data, length)

    cpdef read(self, length, offset):
        return self.dm.copy_from_dm(offset, length)

cdef class DmaBufMR(MR):
    def __init__(self, PD pd not None, length, access, DmaBuf dmabuf=None,
                 offset=0, gpu=0, gtt=0):
        """
        Initializes a DmaBufMR (DMA-BUF Memory Region) of the given length
        and access flags using the given PD and DmaBuf objects.
        :param pd: A PD object
        :param length: Length in bytes
        :param access: Access flags, see ibv_access_flags enum
        :param dmabuf: A DmaBuf object. One will be allocated if absent
        :param offset: Byte offset from the beginning of the dma-buf
        :param gpu: GPU unit for internal dmabuf allocation
        :param gtt: If true allocate internal dmabuf from GTT instead of VRAM
        :return: The newly created DMABUFMR
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        if dmabuf is None:
            self.is_dmabuf_internal = True
            dmabuf = DmaBuf(length + offset, gpu, gtt)
        self.mr = v.ibv_reg_dmabuf_mr(pd.pd, offset, length, offset, dmabuf.fd, access)
        if self.mr == NULL:
            raise PyverbsRDMAErrno(f'Failed to register a dma-buf MR. length: {length}, access flags: {access}')
        super().__init__(pd, length, access)
        self.pd = pd
        self.dmabuf = dmabuf
        self.offset = offset
        pd.add_ref(self)
        dmabuf.add_ref(self)
        self.logger.debug(f'Registered dma-buf ibv_mr. Length: {length}, access flags {access}')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        """
        Closes the underlying C object of the MR and frees the memory allocated.
        :return: None
        """
        if self.mr != NULL:
            self.logger.debug('Closing dma-buf MR')
            rc = v.ibv_dereg_mr(self.mr)
            if rc != 0:
                raise PyverbsRDMAError('Failed to dereg dma-buf MR', rc)
            self.pd = None
            self.mr = NULL
            # Set self.mr to NULL before closing dmabuf because this method is
            # re-entered when close_weakrefs() is called inside dmabuf.close().
            if self.is_dmabuf_internal:
                self.dmabuf.close()
            self.dmabuf = None

    @property
    def offset(self):
        return self.offset

    @property
    def dmabuf(self):
        return self.dmabuf

    def write(self, data, length, offset=0):
        """
        Write user data to the dma-buf backing the MR
        :param data: User data to write
        :param length: Length of the data to write
        :param offset: Writing offset
        :return: None
        """
        if isinstance(data, str):
            data = data.encode()
        cdef int off = offset + self.offset
        cdef void *buf = mmap(NULL, length + off, PROT_READ | PROT_WRITE,
                              MAP_SHARED, self.dmabuf.drm_fd,
                              self.dmabuf.map_offset)
        if buf == MAP_FAILED:
            raise PyverbsError(f'Failed to map dma-buf of size {length}')
        memcpy(<char*>(buf + off), <char *>data, length)
        munmap(buf, length + off)

    cpdef read(self, length, offset):
        """
        Reads data from the dma-buf backing the MR
        :param length: Length of data to read
        :param offset: Reading offset
        :return: The data on the buffer in the requested offset
        """
        cdef int off = offset + self.offset
        cdef void *buf = mmap(NULL, length + off, PROT_READ | PROT_WRITE,
                              MAP_SHARED, self.dmabuf.drm_fd,
                              self.dmabuf.map_offset)
        if buf == MAP_FAILED:
            raise PyverbsError(f'Failed to map dma-buf of size {length}')
        cdef char *data =<char*>malloc(length)
        memset(data, 0, length)
        memcpy(data, <char*>(buf + off), length)
        munmap(buf, length + off)
        res = data[:length]
        free(data)
        return res


def mwtype2str(mw_type):
    mw_types = {1:'IBV_MW_TYPE_1', 2:'IBV_MW_TYPE_2'}
    try:
        return mw_types[mw_type]
    except KeyError:
        return 'Unknown MW type ({t})'.format(t=mw_type)
