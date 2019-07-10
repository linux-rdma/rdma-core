# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file
"""
Provide some useful helper function for pyverbs' tests.
"""
from itertools import combinations as com
from string import ascii_lowercase as al
import random

from pyverbs.qp import QPCap, QPInitAttrEx
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
# Raw Packet QP supports TSO header, which creates a larger send WQE.
MAX_RAW_PACKET_SEND_WR = 2500


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


def random_qp_cap(attr):
    """
    Initializes a QPCap object with valid values based on the device's
    attributes.
    It doesn't check the max WR limits since they're reported for smaller WR
    sizes.
    :return: A QPCap object
    """
    # We use significantly smaller values than those in device attributes.
    # The attributes reported by the device don't take into account possible
    # larger WQEs that include e.g. memory window.
    send_wr = random.randint(1, int(attr.max_qp_wr / 8))
    recv_wr = random.randint(1, int(attr.max_qp_wr / 8))
    send_sge = random.randint(1, int(attr.max_sge / 2))
    recv_sge = random.randint(1, int(attr.max_sge / 2))
    inline = random.randint(0, 16)
    return QPCap(send_wr, recv_wr, send_sge, recv_sge, inline)


def random_qp_create_mask(qpt, attr_ex):
    """
    Select a random sublist of ibv_qp_init_attr_mask. Some of the options are
    not yet supported by pyverbs and will not be returned. TSO support is
    checked for the device and the QP type. If it doesn't exist, TSO will not
    be set.
    :param qpt: Current QP type
    :param attr_ex: Extended device attributes for capability checks
    :return: A sublist of ibv_qp_init_attr_mask
    """
    has_tso = attr_ex.tso_caps.max_tso > 0 and \
        attr_ex.tso_caps.supported_qpts & 1 << qpt
    supp_flags = [e.IBV_QP_INIT_ATTR_CREATE_FLAGS,
                  e.IBV_QP_INIT_ATTR_MAX_TSO_HEADER]
    # Either PD or XRCD flag is needed, XRCD is not supported yet
    selected = sample(supp_flags)
    selected.append(e.IBV_QP_INIT_ATTR_PD)
    if e.IBV_QP_INIT_ATTR_MAX_TSO_HEADER in selected and not has_tso:
        selected.remove(e.IBV_QP_INIT_ATTR_MAX_TSO_HEADER)
    mask = 0
    for s in selected:
        mask += s.value
    return mask


def get_create_qp_flags_raw_packet(attr_ex):
    """
    Select random QP creation flags for Raw Packet QP. Filter out unsupported
    flags prior to selection.
    :param attr_ex: Device extended attributes to check capabilities
    :return: A random combination of QP creation flags
    """
    has_fcs = attr_ex.device_cap_flags_ex & e._IBV_DEVICE_RAW_SCATTER_FCS
    has_cvlan = attr_ex.raw_packet_caps & e.IBV_RAW_PACKET_CAP_CVLAN_STRIPPING
    has_padding = attr_ex.device_cap_flags_ex & \
        e._IBV_DEVICE_PCI_WRITE_END_PADDING
    l = list(e.ibv_qp_create_flags)
    l.remove(e.IBV_QP_CREATE_SOURCE_QPN)  # UD only
    if not has_fcs:
        l.remove(e.IBV_QP_CREATE_SCATTER_FCS)
    if not has_cvlan:
        l.remove(e.IBV_QP_CREATE_CVLAN_STRIPPING)
    if not has_padding:
        l.remove(e.IBV_QP_CREATE_PCI_WRITE_END_PADDING)
    flags = sample(l)
    val = 0
    for i in flags:
        val |= i.value
    return val


def random_qp_create_flags(qpt, attr_ex):
    """
    Select a random sublist of ibv_qp_create_flags according to the QP type.
    :param qpt: Current QP type
    :param attr_ex: Used for Raw Packet QP to check device capabilities
    :return: A sublist of ibv_qp_create_flags
    """
    if qpt == e.IBV_QPT_RAW_PACKET:
        return get_create_qp_flags_raw_packet(attr_ex)
    elif qpt == e.IBV_QPT_UD:
        # IBV_QP_CREATE_SOURCE_QPN is only supported by mlx5 driver and is not
        # to be check in unittests.
        return random.choice([0, 2])  # IBV_QP_CREATE_BLOCK_SELF_MCAST_LB
    else:
        return 0


def random_qp_init_attr_ex(attr_ex, attr, qpt=None):
    """
    Create a random-valued QPInitAttrEX object with the given QP type.
    QP type affects QP capabilities, so allow users to set it and still get
    valid attributes.
    :param attr_ex: Extended device attributes for capability checks
    :param attr: Device attributes for capability checks
    :param qpt: Requested QP type
    :return: A valid initialized QPInitAttrEx object
    """
    max_tso = 0
    if qpt is None:
        qpt = random.choice([e.IBV_QPT_RC, e.IBV_QPT_UC, e.IBV_QPT_UD,
                             e.IBV_QPT_RAW_PACKET])
    qp_cap = random_qp_cap(attr)
    if qpt == e.IBV_QPT_RAW_PACKET and \
       qp_cap.max_send_wr > MAX_RAW_PACKET_SEND_WR:
        qp_cap.max_send_wr = MAX_RAW_PACKET_SEND_WR
    sig = random.randint(0, 1)
    mask = random_qp_create_mask(qpt, attr_ex)
    if mask & e.IBV_QP_INIT_ATTR_CREATE_FLAGS:
        cflags = random_qp_create_flags(qpt, attr_ex)
    else:
        cflags = 0
    if mask & e.IBV_QP_INIT_ATTR_MAX_TSO_HEADER:
        if qpt != e.IBV_QPT_RAW_PACKET:
            mask -= e.IBV_QP_INIT_ATTR_MAX_TSO_HEADER
        else:
            max_tso = \
                random.randint(16, int(attr_ex.tso_caps.max_tso / 400))
    qia = QPInitAttrEx(qp_type=qpt, cap=qp_cap, sq_sig_all=sig, comp_mask=mask,
                       create_flags=cflags, max_tso_header=max_tso)
    return qia
