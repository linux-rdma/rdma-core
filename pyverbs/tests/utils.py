# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.  See COPYING file
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
    # Allocating large buffers typically fails
    return random.randint(0, MAX_MR_SIZE)


def get_access_flags():
    vals = list(e.ibv_access_flags)
    selected = random.sample(vals, random.randint(1, 7))
    # Remote write / remote atomic are not allowed without local write
    if e.IBV_ACCESS_REMOTE_WRITE in selected or e.IBV_ACCESS_REMOTE_ATOMIC in selected:
        if not e.IBV_ACCESS_LOCAL_WRITE in selected:
            selected.append(e.IBV_ACCESS_LOCAL_WRITE)
    flags = 0
    for i in selected:
        flags += i.value
    return flags


def get_data(length):
    return ''.join(random.choice(al) for i in range(length))


def get_dm_attrs(dm_len):
    align = random.randint(MIN_DM_LOG_ALIGN, MAX_DM_LOG_ALIGN)
    # Comp mask != 0 is not supported
    return d.AllocDmAttr(dm_len, align, 0)
