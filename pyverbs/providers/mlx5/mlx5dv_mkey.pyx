# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.pyverbs_error import PyverbsUserError, PyverbsRDMAError
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.pd cimport PD


cdef class Mlx5Mkey(PyverbsCM):
    def __init__(self, PD pd not None, create_flags, max_entries):
        """
        Creates an indirect mkey and store the actual mkey max_entries after the
        mkey creation.
        :param pd: PD instance.
        :param create_flags: Mkey creation flags.
        :param max_entries: Requested max number of pointed entries by this
                            indirect mkey.
        """
        cdef dv.mlx5dv_mkey_init_attr mkey_init
        mkey_init.pd = pd.pd
        mkey_init.create_flags = create_flags
        mkey_init.max_entries = max_entries
        self.mlx5dv_mkey = dv.mlx5dv_create_mkey(&mkey_init)
        if self.mlx5dv_mkey == NULL:
            raise PyverbsRDMAErrno('Failed to create mkey')
        self.max_entries = mkey_init.max_entries
        self.pd = pd
        self.pd.mkeys.add(self)

    @property
    def lkey(self):
        return self.mlx5dv_mkey.lkey

    @property
    def rkey(self):
        return self.mlx5dv_mkey.rkey

    @property
    def max_entries(self):
        return self.max_entries

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.mlx5dv_mkey != NULL:
            rc = dv.mlx5dv_destroy_mkey(self.mlx5dv_mkey)
            if rc:
                raise PyverbsRDMAError('Failed to destroy a mkey', rc)
            self.mlx5dv_mkey = NULL
            self.pd = None
