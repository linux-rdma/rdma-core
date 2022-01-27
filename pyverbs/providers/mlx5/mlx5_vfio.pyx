# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

from cpython.mem cimport PyMem_Malloc, PyMem_Free
from libc.string cimport strcpy
import weakref

from pyverbs.pyverbs_error import PyverbsRDMAError
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v


cdef class Mlx5VfioAttr(PyverbsObject):
    """
    Mlx5VfioAttr class, represents mlx5dv_vfio_context_attr C struct.
    """
    def __init__(self, pci_name, flags=0, comp_mask=0):
        self.pci_name = pci_name
        self.attr.flags = flags
        self.attr.comp_mask = comp_mask

    def __dealloc__(self):
        if self.attr.pci_name != NULL:
            PyMem_Free(<void*>self.attr.pci_name)
            self.attr.pci_name = NULL

    @property
    def flags(self):
        return self.attr.flags
    @flags.setter
    def flags(self, val):
        self.attr.flags = val

    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val

    @property
    def pci_name(self):
        return self.attr.pci_name[:]
    @pci_name.setter
    def pci_name(self, val):
        if self.attr.pci_name != NULL:
            PyMem_Free(<void*>self.attr.pci_name)
        pci_name_bytes = val.encode()
        self.attr.pci_name = <char*>PyMem_Malloc(len(pci_name_bytes))
        strcpy(<char*>self.attr.pci_name, pci_name_bytes)


cdef class Mlx5VfioContext(Mlx5Context):
    """
    Mlx5VfioContext class is used to easily initialize and open a context over
    a mlx5 vfio device.
    It is initialized based on the passed mlx5 vfio attributes (Mlx5VfioAttr),
    by getting the relevant vfio device and opening it (creating a context).
    """
    def __init__(self, Mlx5VfioAttr attr):
        super(Context, self).__init__()
        cdef v.ibv_device **dev_list

        self.name = attr.pci_name
        self.pds = weakref.WeakSet()
        self.devx_umems = weakref.WeakSet()
        self.devx_objs = weakref.WeakSet()
        self.uars = weakref.WeakSet()

        dev_list = dv.mlx5dv_get_vfio_device_list(&attr.attr)
        if dev_list == NULL:
            raise PyverbsRDMAErrno('Failed to get VFIO device list')
        self.device = dev_list[0]
        if self.device == NULL:
            raise PyverbsRDMAError('Failed to get VFIO device')
        try:
            self.context = v.ibv_open_device(self.device)
            if self.context == NULL:
                raise PyverbsRDMAErrno('Failed to open mlx5 VFIO device '
                                       f'({self.device.name.decode()})')
        finally:
            v.ibv_free_device_list(dev_list)

    def get_events_fd(self):
        """
        Gets the file descriptor to manage driver events.
        :return: The file descriptor to be used for managing driver events.
        """
        fd = dv.mlx5dv_vfio_get_events_fd(self.context)
        if fd < 0:
            raise PyverbsRDMAError('Failed to get VFIO events FD', -fd)
        return fd

    def process_events(self):
        """
        Process events on the vfio device.
        This method should run from application thread to maintain device events.
        :return: None
        """
        rc = dv.mlx5dv_vfio_process_events(self.context)
        if rc:
            raise PyverbsRDMAError('VFIO process events failed', rc)

    cpdef close(self):
        if self.context != NULL:
            self.logger.debug('Closing Mlx5VfioContext')
            close_weakrefs([self.pds, self.devx_objs, self.devx_umems, self.uars])
            rc = v.ibv_close_device(self.context)
            if rc != 0:
                raise PyverbsRDMAErrno(f'Failed to close device {self.name}')
            self.context = NULL
