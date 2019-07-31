# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

from pyverbs.pyverbs_error import PyverbsUserError
cimport pyverbs.providers.mlx5.libmlx5 as dv


cdef class Mlx5DVContextAttr(PyverbsObject):
    """
    Represent mlx5dv_context_attr struct. This class is used to open an mlx5
    device.
    """
    def __cinit__(self, flags=0, comp_mask=0):
        self.attr.flags = flags
        self.attr.comp_mask = comp_mask

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('flags', self.attr.flags) +\
               print_format.format('comp_mask', self.attr.comp_mask)

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


cdef class Mlx5Context(Context):
    """
    Represent mlx5 context, which extends Context.
    """
    def __cinit__(self, **kwargs):
        """
        Open an mlx5 device using the given attributes
        :param kwargs: Arguments:
            * *name* (str)
               The RDMA device's name (used by parent class)
            * *attr* (Mlx5DVContextAttr)
               mlx5-specific device attributes
        :return: None
        """
        cdef Mlx5DVContextAttr attr
        attr = kwargs.get('attr')
        if not attr or not isinstance(attr, Mlx5DVContextAttr):
            raise PyverbsUserError('Missing provider attributes')
        if not dv.mlx5dv_is_supported(self.device):
            raise PyverbsUserError('This is not an MLX5 device')
        self.context = dv.mlx5dv_open_device(self.device, &attr.attr)
