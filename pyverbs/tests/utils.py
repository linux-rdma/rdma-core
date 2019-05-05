# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.  See COPYING file
"""
Provide some useful helper function for pyverbs' tests.
"""
from itertools import combinations as com
from string import ascii_lowercase as al
import random

import pyverbs.device as d
import pyverbs.enums as e


MAX_MR_SIZE = 4194304
# Some HWs limit DM address and length alignment to 4 for read and write
# operations. Use a minimal length and alignment that respect that.
# For creation purposes use random alignments. As this is log2 of address
# alignment, no need for large numbers.
MIN_DM_SIZE = 4
DM_ALIGNMENT = 4
MIN_DM_LOG_ALIGN = 0
MAX_DM_LOG_ALIGN = 6


def get_mr_length():
    """
    Provide a random value for MR length. We avoid large buffers as these
    allocations typically fails.
    We use random.random() instead of randrange() or randint() due to
    performance issues when generating very large pseudo random numbers.
    :return: A random MR length
    """
    return int(MAX_MR_SIZE * random.random())


def filter_illegal_access_flags(element):
    """
    Helper function to filter illegal access flags combinations
    :param element: A list of access flags to check
    :return: True if this list is legal, else False
    """
    if e.IBV_ACCESS_REMOTE_ATOMIC in element or e.IBV_ACCESS_REMOTE_WRITE:
        if e.IBV_ACCESS_LOCAL_WRITE:
            return False
    return True


def get_access_flags(ctx):
    """
    Provide an array of random legal access flags for an MR.
    Since remote write and remote atomic require local write permission, if
    one of them is randomly selected without local write, local write will be
    added as well.
    After verifying that the flags selection is legal, it is appended to an
    array, assuming it wasn't previously appended.
    :param ctx: Device Context to check capabilities
    :param num: Size of initial collection
    :return: A random legal value for MR flags
    """
    attr = ctx.query_device()
    attr_ex = ctx.query_device_ex()
    vals = list(e.ibv_access_flags)
    if not attr_ex.odp_caps.general_caps & e.IBV_ODP_SUPPORT:
        vals.remove(e.IBV_ACCESS_ON_DEMAND)
    if not attr.device_cap_flags & e.IBV_DEVICE_MEM_WINDOW:
        vals.remove(e.IBV_ACCESS_MW_BIND)
    if not attr.atomic_caps & e.IBV_ATOMIC_HCA:
        vals.remove(e.IBV_ACCESS_REMOTE_ATOMIC)
    arr = []
    for i in range(1, len(vals)):
        tmp = list(com(vals, i))
        tmp = filter(filter_illegal_access_flags, tmp)
        for t in tmp:  # Iterate legal combinations and bitwise OR them
            val = 0
            for flag in t:
                val += flag.value
            arr.append(val)
    return arr


def get_dm_attrs(dm_len):
    """
    Initializes an AllocDmAttr member with the given length and random
    alignment. It currently sets comp_mask = 0 since other comp_mask values
    are not supported.
    :param dm_len:
    :return: An initialized AllocDmAttr object
    """
    align = random.randint(MIN_DM_LOG_ALIGN, MAX_DM_LOG_ALIGN)
    return d.AllocDmAttr(dm_len, align, 0)


def sample(coll):
    """
    Returns a random-length subset of the given collection.
    :param coll: The collection to sample
    :return: A subset of <collection>
    """
    return random.sample(coll, int((len(coll) + 1) * random.random()))
