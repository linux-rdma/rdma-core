# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

import sys
from libc.stdint cimport uint8_t
from .pyverbs_error import PyverbsUserError

cdef extern from 'endian.h':
    unsigned long be64toh(unsigned long host_64bits)


cdef class GID(PyverbsObject):
    """
    GID class represents ibv_gid. It enables user to query for GIDs values.
    """
    @property
    def gid(self):
        """
        Expose the inner GID
        :return: A GID string in an 8 words format:
        'xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx'
        """
        return self.__str__()
    @gid.setter
    def gid(self, val):
        """
        Sets the inner GID
        :param val: A GID string in an 8 words format:
        'xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx'
        :return: None
        """
        val = val.split(':')
        if len(val) != 8:
            raise PyverbsUserError("Invalid GID value ({val})".format(val=val))
        if any([len(v) != 4 for v in val]):
            raise PyverbsUserError("Invalid GID value ({val})".format(val=val))
        val_int = int("".join(val), 16)
        vals = []
        for i in range(8):
            vals.append(val[i][0:2])
            vals.append(val[i][2:4])

        for i in range(16):
            self.gid.raw[i] = <uint8_t>int(vals[i],16)

    def __str__(self):
        hex_values = '%016x%016x' % (be64toh(self.gid._global.subnet_prefix),
                                   be64toh(self.gid._global.interface_id))
        return ':'.join([hex_values[0:4], hex_values[4:8], hex_values[8:12],
                         hex_values[12:16], hex_values[16:20], hex_values[20:24],
                         hex_values[24:28],hex_values[28:32]])
