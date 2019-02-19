# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

import struct

from pyverbs.pyverbs_error import PyverbsUserError

be64toh = lambda num: struct.unpack('Q', struct.pack('!Q', num))[0]

def gid_str(subnet_prefix, interface_id):
    hex_values = '%016x%016x' % (be64toh(subnet_prefix), be64toh(interface_id))
    return ':'.join([hex_values[0:4], hex_values[4:8], hex_values[8:12],
                     hex_values[12:16], hex_values[16:20], hex_values[20:24],
                     hex_values[24:28],hex_values[28:32]])


def gid_str_to_array(val):
    """
    Splits a GID to an array of u8 that can be easily assigned to a GID's raw
    array.
    :param val: GID value in 8 words format
    'xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx'
    :return: An array of format xx:xx etc.
    """
    val = val.split(':')
    if len(val) != 8:
        raise PyverbsUserError('Invalid GID value ({val})'.format(val=val))
    if any([len(v) != 4 for v in val]):
        raise PyverbsUserError('Invalid GID value ({val})'.format(val=val))
    val_int = int(''.join(val), 16)
    vals = []
    for i in range(8):
        vals.append(val[i][0:2])
        vals.append(val[i][2:4])
    return vals
