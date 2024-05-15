# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2024 Nvidia, Inc. All rights reserved. See COPYING file

cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.mr cimport DmaBufMR
from pyverbs.pd cimport PD


cdef class Mlx5DmaBufMR(DmaBufMR):
    def __init__(self, PD pd not None, offset, length, iova=0, fd=None,
                 access=0, mlx5_access=0):
        """
        Initializes a DmaBufMR (DMA-BUF Memory Region) of the given length
        and access flags using the given PD and DmaBuf objects.
        :param pd: A PD object
        :param offset: Byte offset from the beginning of the dma-buf
        :param length: Length in bytes
        :param iova: The virtual base address of the MR when accessed through a lkey or rkey.
        :param fd: FD representing a dmabuf.
        :param access: Access flags, see ibv_access_flags enum.
        :param mlx5_access: A specific device access flags.
        :return: The newly created DMABUFMR
        """
        self.mr = dv.mlx5dv_reg_dmabuf_mr(pd.pd, offset, length, iova, fd, access, mlx5_access)
        if self.mr == NULL:
            raise PyverbsRDMAErrno(
                f'Failed to register a mlx5 dma-buf MR. length: {length}, access flags: {access} '
                f'mlx5_access: {mlx5_access}')
        self.pd = pd
        self.dmabuf = fd
        self.offset = offset
        pd.add_ref(self)
