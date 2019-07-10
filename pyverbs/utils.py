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


def qp_type_to_str(qp_type):
    types = {2: 'RC', 3: 'UC', 4: 'UD', 8: 'Raw Packet', 9: 'XRCD_SEND',
             10: 'XRCD_RECV', 0xff:'Driver QP'}
    try:
        return types[qp_type]
    except KeyError:
        return 'Unknown ({qpt})'.format(qpt=qp_type)


def qp_state_to_str(qp_state):
    states = {0: 'Reset', 1: 'Init', 2: 'RTR', 3: 'RTS', 4: 'SQD',
              5: 'SQE', 6: 'Error', 7: 'Unknown'}
    try:
        return states[qp_state]
    except KeyError:
        return 'Unknown ({qps})'.format(qps=qp_state_to_str)


def mtu_to_str(mtu):
    mtus = {1: 256, 2: 512, 3: 1024, 4: 2048, 5: 4096}
    try:
        return mtus[mtu]
    except KeyError:
        return 0


def access_flags_to_str(flags):
    access_flags = {1: 'Local write', 2: 'Remote write', 4: 'Remote read',
                    8: 'Remote atomic', 16: 'MW bind', 32: 'Zero based',
                    64: 'On demand'}
    access_str = ''
    for f in access_flags:
        if flags & f:
            access_str += access_flags[f]
            access_str += ' '
    return access_str


def mig_state_to_str(mig):
    mig_states = {0: 'Migrated', 1: 'Re-arm', 2: 'Armed'}
    try:
        return mig_states[mig]
    except KeyError:
        return 'Unknown ({m})'.format(m=mig)
