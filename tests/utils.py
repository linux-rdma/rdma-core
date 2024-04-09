# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file
# Copyright (c) 2020 Intel Corporation. All rights reserved. See COPYING file
"""
Provide some useful helper function for pyverbs' tests.
"""
from itertools import combinations as com
import errno
import subprocess
import unittest
import random
import socket
import struct
import string
import glob
import time
import os

from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError, PyverbsUserError
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr
from pyverbs.qp import QPCap, QPInitAttr, QPInitAttrEx, QPAttr, QPEx, QP
from tests.mlx5_base import Mlx5DcResources, Mlx5DcStreamsRes
from tests.base import XRCResources, DCT_KEY, MLNX_VENDOR_ID
from pyverbs.addr import AHAttr, AH, GlobalRoute
from pyverbs.providers.efa.efadv import EfaCQ
from pyverbs.wr import SGE, SendWR, RecvWR
from pyverbs.base import PyverbsRDMAErrno
from tests.efa_base import SRDResources
from pyverbs.cq import PollCqAttr, CQEX
from pyverbs.mr import MW, MWBindInfo
from pyverbs.mem_alloc import madvise
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.mr import MR


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
GRH_SIZE = 40
IMM_DATA = 1234
POLL_CQ_TIMEOUT = 10  # In seconds


class MatchCriteriaEnable:
    NONE = 0
    OUTER = 1
    MISC = 1 << 1
    INNER = 1 << 2
    MISC_2 = 1 << 3
    MISC_3 = 1 << 4


class PacketConsts:
    """
    Class to hold constant packets' values.
    """
    ETHER_HEADER_SIZE = 14
    IPV4_HEADER_SIZE = 20
    IPV6_HEADER_SIZE = 40
    UDP_HEADER_SIZE = 8
    TCP_HEADER_SIZE = 20
    VLAN_HEADER_SIZE = 4
    TCP_HEADER_SIZE_WORDS = 5
    IP_V4 = 4
    IP_V6 = 6
    TCP_PROTO = 'tcp'
    UDP_PROTO = 'udp'
    IP_V4_FLAGS = 2  # Don't fragment is set
    TTL_HOP_LIMIT = 64
    IHL = 5
    # Hardcoded values for flow matchers
    ETHER_TYPE_ETH = 0x6558
    ETHER_TYPE_IPV4 = 0x800
    MAC_MASK = "ff:ff:ff:ff:ff:ff"
    ETHER_TYPE_IPV6 = 0x86DD
    SRC_MAC = "24:8a:07:a5:28:c8"
    # DST mac must be multicast
    DST_MAC = "01:50:56:19:20:a7"
    SRC_IP = "1.1.1.1"
    DST_IP = "2.2.2.2"
    SRC_PORT = 1234
    DST_PORT = 5678
    SRC_IP6 = "a0a1::a2a3:a4a5:a6a7:a8a9"
    DST_IP6 = "b0b1::b2b3:b4b5:b6b7:b8b9"
    SEQ_NUM = 1
    WINDOW_SIZE = 65535
    VXLAN_PORT = 4789
    VXLAN_VNI = 7777777
    VXLAN_FLAGS = 0x8
    VXLAN_HEADER_SIZE = 8
    VLAN_TPID = 0x8100
    VLAN_PRIO = 5
    VLAN_CFI = 1
    VLAN_ID = 0xc0c
    GRE_VER = 1
    GRE_FLAGS = 2
    GRE_KEY = 0x12345678
    GENEVE_VNI = 2
    GENEVE_OAM = 0
    GENEVE_PORT = 6081
    BTH_HEADER_SIZE = 16
    BTH_OPCODE = 0x81
    BTH_DST_QP = 0xd2
    BTH_A = 0x1
    BTH_PARTITION_KEY = 0xffff
    BTH_BECN = 1
    ROCE_PORT = 4791


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
    if e.IBV_ACCESS_REMOTE_ATOMIC in element or e.IBV_ACCESS_REMOTE_WRITE in element:
        if not e.IBV_ACCESS_LOCAL_WRITE in element:
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


def get_dmabuf_access_flags(ctx):
    """
    Similar to get_access_flags, except that dma-buf MR only support
    a subset of the flags.
    :param ctx: Device Context to check capabilities
    :return: A random legal value for MR flags
    """
    attr = ctx.query_device()
    vals = [e.IBV_ACCESS_LOCAL_WRITE, e.IBV_ACCESS_REMOTE_WRITE,
            e.IBV_ACCESS_REMOTE_READ, e.IBV_ACCESS_REMOTE_ATOMIC,
            e.IBV_ACCESS_RELAXED_ORDERING]
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
    return QPCap(send_wr, recv_wr, send_sge, recv_sge)


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


def random_valid_qp_create_flags(qpt, attr, attr_ex):
    """
    Select a random sublist of ibv_qp_create_flags according to the QP type.
    :param qpt: Current QP type
    :param attr_ex: Used for Raw Packet QP to check device capabilities
    :return: A sublist of ibv_qp_create_flags
    """
     # Most HCAs doesn't support any create_flags so far except mlx4/mlx5
    if attr.vendor_id != MLNX_VENDOR_ID:
        return 0

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
    Create a random-valued QPInitAttrEx object with the given QP type.
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
        cflags = random_valid_qp_create_flags(qpt, attr, attr_ex)
    else:
        cflags = 0
    if mask & e.IBV_QP_INIT_ATTR_MAX_TSO_HEADER:
        if qpt != e.IBV_QPT_RAW_PACKET:
            mask -= e.IBV_QP_INIT_ATTR_MAX_TSO_HEADER
        else:
            max_tso = \
                random.randint(16, int(attr_ex.tso_caps.max_tso / 800))
    qia = QPInitAttrEx(qp_type=qpt, cap=qp_cap, sq_sig_all=sig, comp_mask=mask,
                       create_flags=cflags, max_tso_header=max_tso)
    if mask & e.IBV_QP_INIT_ATTR_MAX_TSO_HEADER:
        # TSO increases send WQE size, let's be on the safe side
        qia.cap.max_send_sge = 2
    return qia


def get_qp_init_attr(cq, attr):
    """
    Creates a QPInitAttr object with a QP type of the provided <qpts> array and
    other random values.
    :param cq: CQ to be used as send and receive CQ
    :param attr: Device attributes for capability checks
    :return: An initialized QPInitAttr object
    """
    qp_cap = random_qp_cap(attr)
    sig = random.randint(0, 1)
    return QPInitAttr(scq=cq, rcq=cq, cap=qp_cap, sq_sig_all=sig)


def wc_status_to_str(status):
    try:
        return \
            {0: 'Success', 1: 'Local length error',
             2: 'local QP operation error', 3: 'Local EEC operation error',
             4: 'Local protection error', 5: 'WR flush error',
             6: 'Memory window bind error', 7: 'Bad response error',
             8: 'Local access error', 9: 'Remote invalidate request error',
             10: 'Remote access error', 11: 'Remote operation error',
             12: 'Retry exceeded', 13: 'RNR retry exceeded',
             14: 'Local RDD violation error',
             15: 'Remote invalidate RD request error',
             16: 'Remote aort error', 17: 'Invalidate EECN error',
             18: 'Invalidate EEC state error', 19: 'Fatal error',
             20: 'Response timeout error', 21: 'General error'}[status]
    except KeyError:
        return 'Unknown WC status ({s})'.format(s=status)


def create_custom_mr(agr_obj, additional_access_flags=0, size=None, user_addr=None):
    """
    Creates a memory region using the aggregation object's PD.
    If size is None, the agr_obj's message size is used to set the MR's size.
    The access flags are local write and the additional_access_flags.
    :param agr_obj: The aggregation object that creates the MR
    :param additional_access_flags: Addition access flags to set in the MR
    :param size: MR's length. If None, agr_obj.msg_size is used.
    :param user_addr: The MR's buffer address. If None, the buffer will be allocated by pyverbs.
    """
    mr_length = size if size else agr_obj.msg_size
    try:
        return MR(agr_obj.pd, mr_length,
                  e.IBV_ACCESS_LOCAL_WRITE | additional_access_flags, address=user_addr)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest(f'Create custom mr with additional access flags {additional_access_flags} is not supported')
        raise ex

# Traffic helpers

def get_send_elements(agr_obj, is_server, opcode=e.IBV_WR_SEND):
    """
    Creates a single SGE and a single Send WR for agr_obj's QP type. The content
    of the message is either 's' for server side or 'c' for client side.
    :param agr_obj: Aggregation object which contains all resources necessary
    :param is_server: Indicates whether this is server or client side
    :return: send wr and its SGE
    """
    if hasattr(agr_obj, 'use_mixed_mr') and agr_obj.use_mixed_mr:
        return get_send_elements_mixed_mr(agr_obj, is_server, opcode)
    if opcode == e.IBV_WR_ATOMIC_WRITE:
        atomic_wr = agr_obj.msg_size * (b's' if is_server else b'c')
        return None, atomic_wr

    qp_type = agr_obj.sqp_lst[0].qp_type if isinstance(agr_obj, XRCResources) \
                else agr_obj.qp.qp_type
    offset = GRH_SIZE if qp_type == e.IBV_QPT_UD else 0
    msg = (agr_obj.msg_size + offset) * ('s' if is_server else 'c')
    agr_obj.mem_write(msg, agr_obj.msg_size + offset)
    sge = SGE(agr_obj.mr.buf + offset, agr_obj.msg_size, agr_obj.mr_lkey)
    send_wr = SendWR(opcode=opcode, num_sge=1, sg=[sge])
    if opcode in [e.IBV_WR_RDMA_WRITE, e.IBV_WR_RDMA_WRITE_WITH_IMM, e.IBV_WR_RDMA_READ]:
        send_wr.set_wr_rdma(int(agr_obj.rkey), int(agr_obj.raddr))
    return send_wr, sge


def get_send_elements_mixed_mr(agr_obj, is_server, opcode=e.IBV_WR_SEND):
    """
    Creates 2 SGEs and a single Send WR for agr_obj's QP type. There are 2 messages,
    one for each MR. The content of the message is either 's' for server side or 'c'
    for client side.
    :param agr_obj: Aggregation object which contains all resources necessary
    :param is_server: Indicates whether this is server or client side
    :param opcode: send WR opcode
    :return: send wr and its SG list
    """
    msg = (agr_obj.msg_size) * ('s' if is_server else 'c')
    agr_obj.mr.write(msg, agr_obj.msg_size)
    agr_obj.non_odp_mr.write(msg, agr_obj.msg_size)
    sge1 = SGE(agr_obj.mr.buf, agr_obj.msg_size, agr_obj.mr.lkey)
    sge2 = SGE(agr_obj.non_odp_mr.buf, agr_obj.msg_size, agr_obj.non_odp_mr.lkey)
    send_wr = SendWR(opcode=opcode, num_sge=2, sg=[sge1, sge2])
    return send_wr, [sge1, sge2]


def get_recv_wr(agr_obj):
    """
    Creates a single SGE Recv WR for agr_obj's QP type. In case of mixed MRs,
    creates 2 SGEs accordingly.
    :param agr_obj: Aggregation object which contains all resources necessary
    :return: recv wr
    """
    qp_type = agr_obj.rqp_lst[0].qp_type if isinstance(agr_obj, XRCResources) \
        else agr_obj.qp.qp_type if isinstance(agr_obj.qp, QP) else None
    mr = agr_obj.mr
    length = agr_obj.msg_size + GRH_SIZE if qp_type == e.IBV_QPT_UD \
             else agr_obj.msg_size
    recv_sgl = [SGE(mr.buf, length, mr.lkey)]
    if hasattr(agr_obj, 'use_mixed_mr') and agr_obj.use_mixed_mr:
        sec_mr = agr_obj.non_odp_mr
        recv_sgl.append(SGE(sec_mr.buf,length,sec_mr.lkey))
    return RecvWR(sg=recv_sgl, num_sge=len(recv_sgl))


def get_global_ah(agr_obj, gid_index, port):
    gr = GlobalRoute(dgid=agr_obj.ctx.query_gid(port, gid_index),
                     sgid_index=gid_index)
    ah_attr = AHAttr(port_num=port, is_global=1, gr=gr,
                     dlid=agr_obj.port_attr.lid)
    return AH(agr_obj.pd, attr=ah_attr)


def get_global_route(ctx, gid_index=0, port_num=1):
    """
    Queries the provided Context's gid <gid_index> and creates a GlobalRoute
    object with sgid_index <gid_index> and the queried GID as dgid.
    :param ctx: Context object to query
    :param gid_index: GID index to query and use. Default: 0, as it's always
                      valid
    :param port_num: Number of the port to query. Default: 1
    :return: GlobalRoute object
    """
    if ctx.query_port(port_num).gid_tbl_len == 0:
        raise unittest.SkipTest(f'Not supported without GID table')
    gid = ctx.query_gid(port_num, gid_index)
    gr = GlobalRoute(dgid=gid, sgid_index=gid_index)
    return gr


def xrc_post_send(agr_obj, qp_num, send_object, send_op=None):
    agr_obj.qps = agr_obj.sqp_lst
    if send_op:
        post_send_ex(agr_obj, send_object, send_op)
    else:
        post_send(agr_obj, send_object)


def post_send_ex(agr_obj, send_object, send_op=None, qp_idx=0, ah=None, **kwargs):
    qp = agr_obj.qps[qp_idx]
    qp_type = qp.qp_type
    qp.wr_start()
    qp.wr_id = 0x123
    qp.wr_flags = e.IBV_SEND_SIGNALED
    if send_op == e.IBV_WR_SEND:
        qp.wr_send()
    elif send_op == e.IBV_WR_RDMA_WRITE:
        qp.wr_rdma_write(agr_obj.rkey, agr_obj.raddr)
    elif send_op == e.IBV_WR_SEND_WITH_IMM:
        qp.wr_send_imm(IMM_DATA)
    elif send_op == e.IBV_WR_RDMA_WRITE_WITH_IMM:
        qp.wr_rdma_write_imm(agr_obj.rkey, agr_obj.raddr, IMM_DATA)
    elif send_op == e.IBV_WR_ATOMIC_WRITE:
        qp.wr_atomic_write(agr_obj.rkey, agr_obj.raddr, send_object)
    elif send_op == e.IBV_WR_FLUSH:
        qp.wr_flush(agr_obj.rkey, agr_obj.raddr, agr_obj.msg_size,
                    agr_obj.ptype, agr_obj.level)
    elif send_op == e.IBV_WR_RDMA_READ:
        qp.wr_rdma_read(agr_obj.rkey, agr_obj.raddr)
    elif send_op == e.IBV_WR_ATOMIC_CMP_AND_SWP:
        cmp_add = kwargs.get('cmp_add')
        swp = kwargs.get('swap')
        qp.wr_atomic_cmp_swp(agr_obj.rkey, agr_obj.raddr,
                             int8b_from_int(cmp_add), int8b_from_int(swp))
    elif send_op == e.IBV_WR_ATOMIC_FETCH_AND_ADD:
        cmp_add = kwargs.get('cmp_add')
        qp.wr_atomic_fetch_add(agr_obj.rkey, agr_obj.raddr,
                               int8b_from_int(cmp_add))
    elif send_op == e.IBV_WR_BIND_MW:
        bind_info = MWBindInfo(agr_obj.mr, agr_obj.mr.buf, agr_obj.mr.rkey,
                               e.IBV_ACCESS_REMOTE_WRITE)
        mw = MW(agr_obj.pd, mw_type=e.IBV_MW_TYPE_2)
        # A new rkey is needed to be set into bind_info, modify rkey
        qp.wr_bind_mw(mw, agr_obj.mr.rkey + 12, bind_info)
        qp.wr_send()
    if qp_type == e.IBV_QPT_UD:
        qp.wr_set_ud_addr(ah, agr_obj.rqps_num[qp_idx], agr_obj.UD_QKEY)
    if isinstance(agr_obj, SRDResources):
        qp.wr_set_ud_addr(ah, agr_obj.rqps_num[qp_idx], agr_obj.SRD_QKEY)
    if qp_type == e.IBV_QPT_XRC_SEND:
        qp.wr_set_xrc_srqn(agr_obj.remote_srqn)
    if hasattr(agr_obj, 'remote_dct_num'):
        if isinstance(agr_obj, Mlx5DcStreamsRes):
            stream_id = agr_obj.generate_stream_id(qp_idx)
            agr_obj.check_bad_flow(qp_idx)
            qp.wr_set_dc_addr_stream(ah, agr_obj.remote_dct_num, DCT_KEY,
                                     stream_id)
        else:
            qp.wr_set_dc_addr(ah, agr_obj.remote_dct_num, DCT_KEY)
    if send_op != e.IBV_WR_ATOMIC_WRITE and \
            send_op != e.IBV_WR_FLUSH:
        qp.wr_set_sge(send_object)
    qp.wr_complete()


def post_send(agr_obj, send_wr, qp_idx=0, ah=None, is_imm=False):
    """
    Post a single send WR to the QP. Post_send's second parameter (send bad wr)
    is ignored for simplicity. For UD traffic an address vector is added as
    well.
    :param agr_obj: aggregation object which contains all resources necessary
    :param send_wr: Send work request to post send
    :param qp_idx: QP index to use
    :param ah: The destination address handle
    :param is_imm: If True, send with imm_data, relevant for old post send API
    :return: None
    """
    qp_type = agr_obj.qp.qp_type
    if is_imm:
        send_wr.imm_data = socket.htonl(IMM_DATA)
    if qp_type == e.IBV_QPT_UD:
        send_wr.set_wr_ud(ah, agr_obj.rqps_num[qp_idx], agr_obj.UD_QKEY)
    if isinstance(agr_obj, SRDResources):
        send_wr.set_wr_ud(ah, agr_obj.rqps_num[qp_idx], agr_obj.SRD_QKEY)
    agr_obj.qps[qp_idx].post_send(send_wr, None)


def post_recv(agr_obj, recv_wr, qp_idx=0 ,num_wqes=1):
    """
    Call the QP's post_recv() method <num_wqes> times. Post_recv's second
    parameter (recv bad wr) is ignored for simplicity.
    :param recv_wr: Receive work request to post
    :param qp_idx: QP index which posts receive work request
    :param num_wqes: Number of WQEs to post
    :return: None
    """
    receive_queue = agr_obj.srq if agr_obj.srq else agr_obj.qps[qp_idx]
    for _ in range(num_wqes):
        if isinstance(receive_queue, QPEx) and receive_queue.ind_table:
            for wq in receive_queue.ind_table.wqs:
                wq.post_recv(recv_wr, None)
        else:
            receive_queue.post_recv(recv_wr, None)


def _poll_cq(cq, count=1, data=None):
    """
    Poll <count> completions from the CQ.
    Note: This function calls the blocking poll() method of the CQ
    until <count> completions were received. Alternatively, gets a
    single CQ event when events are used.
    :param cq: CQ to poll from
    :param count: How many completions to poll
    :param data: In case of a work request with immediate, the immediate data
                 to be compared after poll
    :return: An array of work completions of length <count>, None
             when events are used
    """
    wcs = []
    channel = cq.comp_channel
    start_poll_t = time.perf_counter()
    while count > 0 and (time.perf_counter() - start_poll_t < POLL_CQ_TIMEOUT):
        if channel:
            channel.get_cq_event(cq)
            cq.req_notify()
        nc, tmp_wcs = cq.poll(count)
        for wc in tmp_wcs:
            if wc.status != e.IBV_WC_SUCCESS:
                wcs.append(wc)
                return wcs
            if data:
                if wc.wc_flags & e.IBV_WC_WITH_IMM == 0:
                    raise PyverbsRDMAError('Completion without immediate')
                assert socket.ntohl(wc.imm_data) == data
        count -= nc
        wcs.extend(tmp_wcs)

    if count > 0:
        raise PyverbsError(f'Got timeout on polling ({count} CQEs remaining)')

    return wcs


def poll_cq(cq, count=1, data=None):
    """
    Poll <count> completions from the CQ.
    Note: This function calls the blocking poll() method of the CQ
    until <count> completions were received. Alternatively, gets a
    single CQ event when events are used.
    :param cq: CQ to poll from
    :param count: How many completions to poll
    :param data: In case of a work request with immediate, the immediate data
                 to be compared after poll
    :return: An array of work completions of length <count>, None
             when events are used
    """
    wcs = _poll_cq(cq, count, data)
    if wcs[0].status != e.IBV_WC_SUCCESS:
        raise PyverbsRDMAError(f'Completion status is {wc_status_to_str(wcs[0].status)}')

    return wcs


def poll_cq_ex(cqex, count=1, data=None, sgid=None):
    """
    Poll <count> completions from the extended CQ.
    :param cq: CQEX to poll from
    :param count: How many completions to poll
    :param data: In case of a work request with immediate, the immediate data
                 to be compared after poll
    :param sgid: In case of EFA receive completion, the sgid to be compared
                 after poll
    :return: None
    """
    try:
        start_poll_t = time.perf_counter()
        poll_attr = PollCqAttr()
        ret = cqex.start_poll(poll_attr)
        while ret == 2 and (time.perf_counter() - start_poll_t < POLL_CQ_TIMEOUT):
            ret = cqex.start_poll(poll_attr)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to poll CQ')
        count -= 1
        if cqex.status != e.IBV_WC_SUCCESS:
            raise PyverbsRDMAErrno('Completion status is {s}'.
                                   format(s=cqex.status))
        if data:
            assert data == socket.ntohl(cqex.read_imm_data())

        if isinstance(cqex, EfaCQ):
            if sgid is not None and cqex.read_opcode() == e.IBV_WC_RECV:
                assert sgid.gid == cqex.read_sgid().gid
        # Now poll the rest of the packets
        while count > 0 and (time.perf_counter() - start_poll_t < POLL_CQ_TIMEOUT):
            ret = cqex.poll_next()
            while ret == 2:
                ret = cqex.poll_next()
            if ret != 0:
                raise PyverbsRDMAErrno('Failed to poll CQ')
            count -= 1
            if cqex.status != e.IBV_WC_SUCCESS:
                raise PyverbsRDMAErrno('Completion status is {s}'.
                                       format(s=cqex.status))
            if data:
                assert data == socket.ntohl(cqex.read_imm_data())

            if isinstance(cqex, EfaCQ):
                if sgid is not None and cqex.read_opcode() == e.IBV_WC_RECV:
                    assert sgid.gid == cqex.read_sgid().gid
        if count > 0:
            raise PyverbsError(f'Got timeout on polling ({count} CQEs remaining)')
    finally:
        cqex.end_poll()


def validate(received_str, is_server, msg_size):
    """
    Validates the received buffer against the expected result.
    The application should set client's send buffer to 'c's and the
    server's send buffer to 's's.
    If the expected buffer is different than the actual, an exception will
    be raised.
    :param received_str: The received buffer to check
    :param is_server: Indicates whether this is the server (receiver) or
                      client side
    :param msg_size: the message size of the received packet
    :return: None
    """
    expected_str = msg_size * ('c' if is_server else 's')
    received_str = received_str.decode()
    if received_str[0:msg_size] == \
            expected_str[0:msg_size]:
        return
    else:
        raise PyverbsError(
            'Data validation failure: expected {exp}, received {rcv}'.
                format(exp=expected_str, rcv=received_str))


def send(agr_obj, send_object, send_op=None, new_send=False, qp_idx=0, ah=None, is_imm=False,
         **kwargs):
    if isinstance(agr_obj, XRCResources):
        agr_obj.qps = agr_obj.sqp_lst
    if new_send:
        return post_send_ex(agr_obj, send_object, send_op, qp_idx, ah, **kwargs)
    return post_send(agr_obj, send_object, qp_idx, ah, is_imm)


def traffic(client, server, iters, gid_idx, port, is_cq_ex=False, send_op=e.IBV_WR_SEND,
            new_send=False, force_page_faults=False):
    """
    Runs basic traffic between two sides
    :param client: client side, clients base class is BaseTraffic
    :param server: server side, servers base class is BaseTraffic
    :param iters: number of traffic iterations
    :param gid_idx: local gid index
    :param port: IB port
    :param is_cq_ex: If True, use poll_cq_ex() rather than poll_cq()
    :param send_op: The send_wr opcode.
    :param new_send: If True use new post send API.
    :param force_page_faults: If True, use madvise to hint that we don't need the MR's buffer to
                              force page faults (useful for ODP testing).
    :return:
    """
    if is_datagram_qp(client):
        ah_client = get_global_ah(client, gid_idx, port)
        ah_server = get_global_ah(server, gid_idx, port)
    else:
        ah_client = None
        ah_server = None
    poll = poll_cq_ex if is_cq_ex else poll_cq

    imm_data = None
    if send_op in [e.IBV_WR_SEND_WITH_IMM, e.IBV_WR_RDMA_WRITE_WITH_IMM]:
        imm_data = IMM_DATA

    s_recv_wr = get_recv_wr(server)
    c_recv_wr = get_recv_wr(client)
    for qp_idx in range(server.qp_count):
        # prepare the receive queue with RecvWR
        post_recv(client, c_recv_wr, qp_idx=qp_idx)
        post_recv(server, s_recv_wr, qp_idx=qp_idx)
    read_offset = GRH_SIZE if client.qp.qp_type == e.IBV_QPT_UD else 0
    for _ in range(iters):
        for qp_idx in range(server.qp_count):
            if force_page_faults:
                madvise(client.mr.buf, client.msg_size)
                madvise(server.mr.buf, server.msg_size)
            c_send_wr, c_sg = get_send_elements(client, False, send_op)
            if client.use_mr_prefetch:
                flags = e._IBV_ADVISE_MR_FLAG_FLUSH
                if client.use_mr_prefetch == 'async':
                    flags = 0
                prefetch_mrs(client, [c_sg], advice=client.prefetch_advice,
                             flags=flags)
            c_send_object = c_sg if new_send else c_send_wr
            send(client, c_send_object, send_op, new_send, qp_idx,
                 ah_client, is_imm=(imm_data != None))
            poll(client.cq)
            poll(server.cq, data=imm_data)
            post_recv(server, s_recv_wr, qp_idx=qp_idx)
            msg_received_list = get_msg_received(server, read_offset)
            for msg in msg_received_list:
                validate(msg, True, server.msg_size)
            s_send_wr, s_sg = get_send_elements(server, True, send_op)
            if server.use_mr_prefetch:
                flags = e._IBV_ADVISE_MR_FLAG_FLUSH
                if server.use_mr_prefetch == 'async':
                    flags = 0
                prefetch_mrs(server, [s_sg], advice=server.prefetch_advice,
                             flags=flags)
            s_send_object = s_sg if new_send else s_send_wr
            send(server, s_send_object, send_op, new_send, qp_idx,
                 ah_server, is_imm=(imm_data != None))
            poll(server.cq)
            poll(client.cq, data=imm_data)
            post_recv(client, c_recv_wr, qp_idx=qp_idx)
            msg_received_list = get_msg_received(client,read_offset)
            for msg in msg_received_list:
                validate(msg, False, server.msg_size)


def get_msg_received(agr_obj, read_offset):
    msg_received_list = [agr_obj.mr.read(agr_obj.msg_size, read_offset)]
    if hasattr(agr_obj, 'use_mixed_mr') and agr_obj.use_mixed_mr:
        msg_received_list.append(agr_obj.non_odp_mr.read(agr_obj.msg_size, read_offset))
    return msg_received_list


def gen_ethernet_header(dst_mac=PacketConsts.DST_MAC, src_mac=PacketConsts.SRC_MAC,
                        ether_type=PacketConsts.ETHER_TYPE_IPV4):
    """
    Generates Ethernet header using the values from the PacketConst class by default.
    :param dst_mac: Destination mac address
    :param src_mac: Source mac address
    :param ether_type: Ether type of next header
    :return: Ethernet header
    """
    header = struct.pack('!6s6s',
                        bytes.fromhex(dst_mac.replace(':', '')),
                        bytes.fromhex(src_mac.replace(':', '')))
    header += ether_type.to_bytes(2, 'big')
    return header


def gen_ipv4_header(packet_len, next_proto=socket.IPPROTO_UDP, src_ip=PacketConsts.SRC_IP,
                    dst_ip=PacketConsts.DST_IP):
    """
    Generates IPv4 header using the values from the PacketConst class by default.
    :param packet_len: Length of all fields following the IP header
    :param next_proto: protocol type of next header
    :param src_ip: Source mac address
    :param dst_ip: Destination mac address
    :return: IPv4 header
    """
    ip_total_len = packet_len + PacketConsts.IPV4_HEADER_SIZE
    return struct.pack('!2B3H2BH4s4s', (PacketConsts.IP_V4 << 4) +
                       PacketConsts.IHL, 0, ip_total_len, 0,
                       PacketConsts.IP_V4_FLAGS << 13,
                       PacketConsts.TTL_HOP_LIMIT, next_proto, 0,
                       socket.inet_aton(src_ip),
                       socket.inet_aton(dst_ip))


def gen_udp_header(packet_len, src_port=PacketConsts.SRC_PORT, dst_port=PacketConsts.DST_PORT):
    """
    Generates UDP header using the values from the PacketConst class by default.
    :param packet_len: Length of all fields following the UDP header
    :param src_port: Source port
    :param dst_port: Destination port
    :return: UDP header
    """
    udp_total_len = packet_len + PacketConsts.UDP_HEADER_SIZE
    return struct.pack('!4H', src_port, dst_port, udp_total_len, 0)


def gen_gre_header(ether_type=PacketConsts.ETHER_TYPE_IPV4):
    """
    Generates GRE header using the values from the PacketConst class by default.
    :param ether_type: Ether type of tunneled next header
    :return: GRE header
    """
    return struct.pack('!2BHI', PacketConsts.GRE_FLAGS << 4, PacketConsts.GRE_VER,
                       ether_type, PacketConsts.GRE_KEY)


def gen_vxlan_header():
    """
    Generates VXLAN header using the values from the PacketConst class by default.
    :return: VXLAN header
    """
    return struct.pack('!II', PacketConsts.VXLAN_FLAGS << 24, PacketConsts.VXLAN_VNI << 8)


def gen_geneve_header(vni=PacketConsts.GENEVE_VNI, oam=PacketConsts.GENEVE_OAM,
                      proto=PacketConsts.ETHER_TYPE_ETH):
    """
    Generates Geneve header using the values from the PacketConst class by default.
    :param vni: geneve vni
    :param oam: geneve oam
    :param proto: Ether type of next header inside the tunnel
    :return: Geneve header
    """
    return struct.pack('!BBHL', (0 << 6) + 0, (oam << 7) + (0 << 6) + 0, proto, (vni << 8) + 0)

def gen_bth_header(opcode=PacketConsts.BTH_OPCODE, dst_qp=PacketConsts.BTH_DST_QP, a=PacketConsts.BTH_A):
    """
    Generates ROCE BTH header using the values from the PacketConst class by default.
    :param opcode: BTH opcode
    :param dst_qp: BTH dst QP
    :param a: BTH acknowledgment bit
    :return: ROCE BTH header
    """
    return struct.pack('!2BH2BH2L', opcode, 0, PacketConsts.BTH_PARTITION_KEY,
                       PacketConsts.BTH_BECN << 6, dst_qp >> 16, dst_qp & 0xffff, a << 31, 0)


def gen_packet(msg_size, l3=PacketConsts.IP_V4, l4=PacketConsts.UDP_PROTO, with_vlan=False, **kwargs):
    """
    Generates a Eth | IPv4 or IPv6 | UDP or TCP packet with hardcoded values in
    the headers and randomized payload.
    :param msg_size: total packet size
    :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
    :param l4: Packet layer 4 type: 'tcp' or 'udp'
    :param with_vlan: if True add VLAN header to the packet
    :param kwargs: Arguments:
            * *src_mac*
                Source MAC address to use in the packet.
            * *src_ipv4*
                Source IPv4 address to use in the packet.
    :return: packet
    """
    l3_header_size = getattr(PacketConsts, f'IPV{str(l3)}_HEADER_SIZE')
    l4_header_size = getattr(PacketConsts, f'{l4.upper()}_HEADER_SIZE')
    payload_size = max(0, msg_size - l3_header_size - l4_header_size -
                       PacketConsts.ETHER_HEADER_SIZE)
    next_hdr = getattr(socket, f'IPPROTO_{l4.upper()}')
    ip_total_len = msg_size - PacketConsts.ETHER_HEADER_SIZE

    # Ethernet header
    src_mac = kwargs.get('src_mac', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
    packet = struct.pack('!6s6s',
                         bytes.fromhex(PacketConsts.DST_MAC.replace(':', '')), src_mac)
    if with_vlan:
        packet += struct.pack('!HH', PacketConsts.VLAN_TPID, (PacketConsts.VLAN_PRIO << 13) +
                              (PacketConsts.VLAN_CFI << 12) + PacketConsts.VLAN_ID)
        payload_size -= PacketConsts.VLAN_HEADER_SIZE
        ip_total_len -= PacketConsts.VLAN_HEADER_SIZE

    if l3 == PacketConsts.IP_V4:
        packet += PacketConsts.ETHER_TYPE_IPV4.to_bytes(2, 'big')
    else:
        packet += PacketConsts.ETHER_TYPE_IPV6.to_bytes(2, 'big')

    if l3 == PacketConsts.IP_V4:
        # IPv4 header
        src_ipv4 = kwargs.get('src_ipv4', PacketConsts.SRC_IP)
        packet += struct.pack('!2B3H2BH4s4s', (PacketConsts.IP_V4 << 4) +
                              PacketConsts.IHL, 0, ip_total_len, 0,
                              PacketConsts.IP_V4_FLAGS << 13,
                              PacketConsts.TTL_HOP_LIMIT, next_hdr, 0,
                              socket.inet_aton(src_ipv4),
                              socket.inet_aton(PacketConsts.DST_IP))
    else:
        # IPv6 header
        packet += struct.pack('!IH2B16s16s', (PacketConsts.IP_V6 << 28),
                       ip_total_len, next_hdr, PacketConsts.TTL_HOP_LIMIT,
                       socket.inet_pton(socket.AF_INET6, PacketConsts.SRC_IP6),
                       socket.inet_pton(socket.AF_INET6, PacketConsts.DST_IP6))

    if l4 == PacketConsts.UDP_PROTO:
        # UDP header
        packet += struct.pack('!4H', PacketConsts.SRC_PORT,
                              PacketConsts.DST_PORT,
                              payload_size + PacketConsts.UDP_HEADER_SIZE, 0)
    else:
        # TCP header
        packet += struct.pack('!2H2I4H', PacketConsts.SRC_PORT,
                              PacketConsts.DST_PORT, 0, 0,
                              PacketConsts.TCP_HEADER_SIZE_WORDS << 12,
                              PacketConsts.WINDOW_SIZE, 0, 0)
    # Payload
    packet += str.encode('a' * payload_size)
    return packet


def get_send_elements_raw_qp(agr_obj, l3=PacketConsts.IP_V4,
                             l4=PacketConsts.UDP_PROTO, with_vlan=False,
                             packet_to_send=None, **packet_args):
    """
    Creates a single SGE and a single Send WR for agr_obj's RAW QP type. The
    content of the message is Eth | Ipv4 | UDP packet.
    :param agr_obj: Aggregation object which contains all resources necessary
    :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
    :param l4: Packet layer 4 type: 'tcp' or 'udp'
    :param with_vlan: if True add VLAN header to the packet
    :param packet_to_send: If passed, the other packet related parameters would
                           be ignored, and this will be the packet to send.
    :param packet_args: Pass packet_args to gen_packets method.
    :return: send wr, its SGE, and message
    """
    mr = agr_obj.mr
    msg = packet_to_send if packet_to_send is not None else \
        gen_packet(agr_obj.msg_size, l3, l4, with_vlan, **packet_args)
    mr.write(msg, agr_obj.msg_size)
    sge = SGE(mr.buf, agr_obj.msg_size, mr.lkey)
    send_wr = SendWR(opcode=e.IBV_WR_SEND, num_sge=1, sg=[sge])
    return send_wr, sge, msg


def validate_raw(msg_received, msg_expected, skip_idxs):
    size = len(msg_expected)
    for i in range(size):
        if (msg_received[i] != msg_expected[i]) and i not in skip_idxs:
            err_msg = f'Data validation failure:\nexpected {msg_expected}\n\nreceived {msg_received}'
            raise PyverbsError(err_msg)


def sampler_traffic(client, server, iters, l3=PacketConsts.IP_V4, l4=PacketConsts.UDP_PROTO):
    """
    Send raw ethernet traffic
    :param client: client side, clients base class is BaseTraffic
    :param server: server side, servers base class is BaseTraffic
    :param iters: number of traffic iterations
    :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
    :param l4: Packet layer 4 type: 'tcp' or 'udp'
    """
    s_recv_wr = get_recv_wr(server)
    c_recv_wr = get_recv_wr(client)
    for qp_idx in range(server.qp_count):
        # Prepare the receive queue with RecvWR
        post_recv(client, c_recv_wr, qp_idx=qp_idx)
        post_recv(server, s_recv_wr, qp_idx=qp_idx)
    poll = poll_cq_ex if isinstance(client.cq, CQEX) else poll_cq
    for _ in range(iters):
        for qp_idx in range(server.qp_count):
            c_send_wr, c_sg, msg = get_send_elements_raw_qp(client, l3, l4, False)
            send(client, c_send_wr, e.IBV_WR_SEND, False, qp_idx)
            poll(client.cq)


def raw_traffic(client, server, iters, l3=PacketConsts.IP_V4,
                l4=PacketConsts.UDP_PROTO, with_vlan=False, expected_packet=None,
                skip_idxs=None, packet_to_send=None):
    """
    Runs raw ethernet traffic between two sides
    :param client: client side, clients base class is BaseTraffic
    :param server: server side, servers base class is BaseTraffic
    :param iters: number of traffic iterations
    :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
    :param l4: Packet layer 4 type: 'tcp' or 'udp'
    :param with_vlan: if True add VLAN header to the packet
    :param expected_packet: Expected packet for validation (when different from
                            the originally sent).
    :param skip_idxs: indexes to skip during packet validation
    :param packet_to_send: If passed, the other packet related parameters would
                           be ignored, and this will be the packet to send.
    """
    skip_idxs = [] if skip_idxs is None else skip_idxs
    s_recv_wr = get_recv_wr(server)
    c_recv_wr = get_recv_wr(client)
    for qp_idx in range(server.qp_count):
        # prepare the receive queue with RecvWR
        post_recv(client, c_recv_wr, qp_idx=qp_idx)
        post_recv(server, s_recv_wr, qp_idx=qp_idx)
    read_offset = 0
    poll = poll_cq_ex if isinstance(client.cq, CQEX) else poll_cq
    for _ in range(iters):
        for qp_idx in range(server.qp_count):
            c_send_wr, c_sg, msg = get_send_elements_raw_qp(client, l3, l4, with_vlan,
                                                            packet_to_send=packet_to_send)
            send(client, c_send_wr, e.IBV_WR_SEND, False, qp_idx)
            poll(client.cq)
            poll(server.cq)
            post_recv(server, s_recv_wr, qp_idx=qp_idx)
            msg_received = server.mr.read(server.msg_size, read_offset)
            # Validate received packet
            validate_raw(msg_received,
                         expected_packet if expected_packet else msg, skip_idxs)


def raw_rss_traffic(client, server, iters, l3=PacketConsts.IP_V4,
                    l4=PacketConsts.UDP_PROTO, with_vlan=False, num_packets=1):
    """
    Runs raw ethernet rss traffic between two sides.
    :param client: client side, clients base class is BaseTraffic
    :param server: server side, servers base class is BaseTraffic
    :param iters: number of traffic iterations
    :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
    :param l4: Packet layer 4 type: 'tcp' or 'udp'
    :param with_vlan: if True add VLAN header to the packet
    :param num_packets: Number of packets to send with different ipv4 src
                        address in each iteration.
    :return: None
    """
    s_recv_wr = get_recv_wr(server)
    for qp_idx in range(server.qp_count):
        # prepare the receive queue with RecvWR
        post_recv(server, s_recv_wr, qp_idx=qp_idx, num_wqes=num_packets)
    for _ in range(iters):
        for qp_idx in range(server.qp_count):
            for i in range(num_packets):
                c_send_wr, c_sg, msg = get_send_elements_raw_qp(
                    client, l3, l4, with_vlan,
                    src_ipv4='.'.join([str(num) for num in range(i, i + 4)]))
                send(client, c_send_wr, e.IBV_WR_SEND, False, qp_idx)
                poll_cq(client.cq)
            completions = 0
            start_poll_t = time.perf_counter()
            while completions < num_packets and \
                    (time.perf_counter() - start_poll_t < POLL_CQ_TIMEOUT):
                for cq in server.cqs:
                    n, wcs = cq.poll()
                    if n > 0:
                        if wcs[0].status != e.IBV_WC_SUCCESS:
                            raise PyverbsRDMAError(
                                f'Completion status is {wc_status_to_str(wcs[0].status)}',
                                wcs[0].status)
                        completions += 1
                        if completions >= num_packets:
                            break
            if completions < num_packets:
                raise PyverbsError(f'Expected {num_packets} completions - got {completions}')
            post_recv(server, s_recv_wr, qp_idx=qp_idx, num_wqes=num_packets)


def flush_traffic(client, server, iters, gid_idx, port, new_send=False,
                  send_op=None):
    """
    Runs basic RDMA FLUSH traffic that client requests a FLUSH to server.
    Simply, run RDMA WRITE and then follow up by a RDMA FLUSH.
    No receive WQEs are posted.
    :param client: client side, clients base class is BaseTraffic
    :param server: server side, servers base class is BaseTraffic
    :param iters: number of traffic iterations
    :param gid_idx: local gid index
    :param port: IB port
    :param new_send: If True use new post send API.
    :param send_op: The send_wr opcode.
    :return:
    """
    rdma_traffic(client, server, iters, gid_idx, port, new_send, e.IBV_WR_RDMA_WRITE)
    for i in range(iters):
        if client.level == e.IBV_FLUSH_MR:
            client.msg_size = 0 if i == 0 else random.randint(0, 12345678)
        send(client, None, send_op, new_send)
        wcs = _poll_cq(client.cq)
        if (wcs[0].status != e.IBV_WC_SUCCESS):
            break
    return wcs


def prepare_validate_data(client=None, server=None):
    if server:
        server.mem_write('s' * server.msg_size, server.msg_size)
    if client:
        client.mem_write('c' * client.msg_size, client.msg_size)


def rdma_traffic(client, server, iters, gid_idx, port, new_send=False,
                 send_op=None, force_page_faults=False):
    """
    Runs basic RDMA traffic between two sides. No receive WQEs are posted. For
    RDMA send with immediate, use traffic().
    :param client: client side, clients base class is BaseTraffic
    :param server: server side, servers base class is BaseTraffic
    :param iters: number of traffic iterations
    :param gid_idx: local gid index
    :param port: IB port
    :param new_send: If True use new post send API.
    :param send_op: The send_wr opcode.
    :param force_page_faults: If True, use madvise to hint that we don't need the MR's buffer to
                              force page faults (useful for ODP testing).
    :return:
    """
    # Using the new post send API, we need the SGE, not the SendWR
    if isinstance(client, Mlx5DcResources) or \
       isinstance(client, SRDResources):
        ah_client = get_global_ah(client, gid_idx, port)
        ah_server = get_global_ah(server, gid_idx, port)
    else:
        ah_client = None
        ah_server = None
    send_element_idx = 1 if new_send else 0
    same_side_check =  send_op in [e.IBV_WR_RDMA_READ,
                                   e.IBV_WR_ATOMIC_CMP_AND_SWP,
                                   e.IBV_WR_ATOMIC_FETCH_AND_ADD]
    for _ in range(iters):
        if force_page_faults:
            madvise(client.mr.buf, client.msg_size)
            madvise(server.mr.buf, server.msg_size)
        prepare_validate_data(client=client, server=server)
        c_send_wr = get_send_elements(client, False, send_op)[send_element_idx]
        send(client, c_send_wr, send_op, new_send, ah=ah_client)
        poll_cq(client.cq)
        if same_side_check:
            msg_received = client.mem_read(client.msg_size)
        else:
            msg_received = server.mem_read(server.msg_size)
        validate(msg_received, False if same_side_check else True,
                 server.msg_size)
        s_send_wr = get_send_elements(server, True, send_op)[send_element_idx]
        prepare_validate_data(client=client, server=server)
        send(server, s_send_wr, send_op, new_send, ah=ah_server)
        poll_cq(server.cq)
        if same_side_check:
            msg_received = server.mem_read(client.msg_size)
        else:
            msg_received = client.mem_read(server.msg_size)
        validate(msg_received, True if same_side_check else False,
                 client.msg_size)


def atomic_traffic(client, server, iters, gid_idx, port, new_send=False,
                   send_op=None, receiver_val=1, sender_val=2, swap=0,
                   client_wr=1, server_wr=1, **kwargs):
    """
    Runs atomic traffic between two sides.
    :param client: Client side, clients base class is BaseTraffic
    :param server: Server side, servers base class is BaseTraffic
    :param iters: Number of traffic iterations
    :param gid_idx: Local gid index
    :param port: IB port
    :param new_send: If True use new post send API.
    :param send_op: The send_wr opcode.
    :param receiver_val: The requested value on the reciver MR.
    :param sender_val: The requested value on the sender SendWR.
    :param client_wr: Number of WR the client will post before polling all of them
    :param server_wr: Number of WR the server will post before polling all of them
    :param kwargs: General arguments (shared with other traffic functions).
    """
    send_element_idx = 1 if new_send else 0
    if is_datagram_qp(client):
        ah_client = get_global_ah(client, gid_idx, port)
        ah_server = get_global_ah(server, gid_idx, port)
    else:
        ah_client = None
        ah_server = None

    for _ in range(iters):
        client.mr.write(int.to_bytes(sender_val, 1, byteorder='big') * 8, 8)
        server.mr.write(int.to_bytes(receiver_val, 1, byteorder='big') * 8, 8)
        for _ in range(client_wr):
            c_send_wr = get_atomic_send_elements(client,
                                                 send_op,
                                                 cmp_add=sender_val,
                                                 swap=swap)[send_element_idx]
            if isinstance(server, XRCResources):
                c_send_wr.set_qp_type_xrc(server.srq.get_srq_num())
            send(client, c_send_wr, send_op, new_send, ah=ah_client,
                 cmp_add=sender_val, swap=swap)
        poll_cq(client.cq, count=client_wr)
        validate_atomic(send_op, server, client,
                        receiver_val=receiver_val + sender_val * (client_wr - 1),
                        send_cmp_add=sender_val, send_swp=swap)
        server.mr.write(int.to_bytes(sender_val, 1, byteorder='big') * 8, 8)
        client.mr.write(int.to_bytes(receiver_val, 1, byteorder='big') * 8, 8)
        for _ in range(server_wr):
            s_send_wr = get_atomic_send_elements(server,
                                                 send_op,
                                                 cmp_add=sender_val,
                                                 swap=swap)[send_element_idx]
            if isinstance(client, XRCResources):
                s_send_wr.set_qp_type_xrc(client.srq.get_srq_num())
            send(server, s_send_wr, send_op, new_send, ah=ah_server,
                 cmp_add=sender_val, swap=swap)
        poll_cq(server.cq, count=server_wr)
        validate_atomic(send_op, client, server,
                        receiver_val=receiver_val + sender_val * (server_wr - 1),
                        send_cmp_add=sender_val, send_swp=swap)


def validate_atomic(opcode, recv_player, send_player, receiver_val,
                    send_cmp_add, send_swp):
    """
    Validate the data after atomic operations. The expected data in each side of
    traffic depends on the atomic type and the sender SendWR values.
    :param opcode: The atomic opcode.
    :param recv_player: The receiver player.
    :param send_player: The sender player.
    :param receiver_val: The value on the receiver MR before the atomic action.
    :param send_cmp_add: The send WR compare/add value depende on the atomic
                         type.
    :param send_swp: The send WR swap value, used only in atomic compare and
                     swap.
    """
    send_expected = receiver_val
    if opcode in [e.IBV_WR_ATOMIC_CMP_AND_SWP,
                  e.IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP]:
        recv_expected = send_swp if receiver_val == send_cmp_add \
            else receiver_val
    if opcode in [e.IBV_WR_ATOMIC_FETCH_AND_ADD,
                  e.IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD]:
        recv_expected = receiver_val + send_cmp_add
    send_actual = int.from_bytes(send_player.mr.read(length=8, offset=0),
                                 byteorder='big')
    recv_actual = int.from_bytes(recv_player.mr.read(length=8, offset=0),
                                 byteorder='big')
    if send_actual != int8b_from_int(send_expected):
        raise PyverbsError(
            'Atomic sender data validation failed: expected {exp}, received {rcv}'.
                format(exp=int8b_from_int(send_expected), rcv=send_actual))
    if recv_actual != int8b_from_int(recv_expected):
        raise PyverbsError(
            'Atomic reciver data validation failed: expected {exp}, received {rcv}'.
                format(exp=int8b_from_int(recv_expected), rcv=recv_actual))


def int8b_from_int(num):
    """
    Duplicate one-byte value int to 8 bytes.
    e.g. 1 => b'\x01\x01\x01\x01\x01\x01\x01\x01' == 72340172838076673
    :param num: One byte int number (0 <= num < 256).
    :return: The new number in int format.
    """
    num_multi_8_str = int.to_bytes(num, 1, byteorder='big') * 8
    return int.from_bytes(num_multi_8_str, byteorder='big')


def get_atomic_send_elements(agr_obj, opcode, cmp_add=0, swap=0):
    """
    Creates a single SGE and a single Send WR for atomic operations.
    :param agr_obj: Aggregation object which contains all resources necessary
    :param opcode: The send opcode
    :param cmp_add: The compare or add value (depends on the opcode).
    :param swap: The swap value.
    :return: Send WR and its SGE
    """
    sge = SGE(agr_obj.mr.buf, 8, agr_obj.mr_lkey)
    send_wr = SendWR(opcode=opcode, num_sge=1, sg=[sge])
    send_wr.set_wr_atomic(rkey=int(agr_obj.rkey), addr=int(agr_obj.raddr),
                          compare_add=int8b_from_int(cmp_add),
                          swap=int8b_from_int(swap))
    return send_wr, sge


def xrc_traffic(client, server, is_cq_ex=False, send_op=None, force_page_faults=False):
    """
    Runs basic xrc traffic, this function assumes that number of QPs, which
    server and client have are equal, server.send_qp[i] is connected to
    client.recv_qp[i], each time server.send_qp[i] sends a message, it is
    redirected to client.srq because client.recv_qp[i] and client.srq are
    under the same xrcd. The traffic flow in the opposite direction is the same.
    :param client: Aggregation object of the active side, should be an instance
    of XRCResources class
    :param server: Aggregation object of the passive side, should be an instance
    of XRCResources class
    :param is_cq_ex: If True, use poll_cq_ex() rather than poll_cq()
    :param send_op: If not None, new post send API is assumed.
    :param force_page_faults: If True, use madvise to hint that we don't need the MR's buffer to
                              force page faults (useful for ODP testing).
    :return: None
    """
    poll = poll_cq_ex if is_cq_ex else poll_cq
    server.remote_srqn = client.srq.get_srq_num()
    client.remote_srqn = server.srq.get_srq_num()
    s_recv_wr = get_recv_wr(server)
    c_recv_wr = get_recv_wr(client)
    post_recv(client, c_recv_wr, num_wqes=client.qp_count*client.num_msgs)
    post_recv(server, s_recv_wr, num_wqes=server.qp_count*server.num_msgs)
    # Using the new post send API, we need the SGE, not the SendWR
    send_element_idx = 1 if send_op else 0
    for _ in range(client.num_msgs):
        for i in range(server.qp_count):
            if force_page_faults:
                madvise(client.mr.buf, client.msg_size)
                madvise(server.mr.buf, server.msg_size)
            c_send_wr = get_send_elements(client, False)[send_element_idx]
            if send_op is None:
                c_send_wr.set_qp_type_xrc(client.remote_srqn)
            xrc_post_send(client, i, c_send_wr, send_op)
            poll(client.cq)
            poll(server.cq)
            msg_received = server.mr.read(server.msg_size, 0)
            validate(msg_received, True, server.msg_size)
            s_send_wr = get_send_elements(server, True)[send_element_idx]
            if send_op is None:
                s_send_wr.set_qp_type_xrc(server.remote_srqn)
            xrc_post_send(server, i, s_send_wr, send_op)
            poll(server.cq)
            poll(client.cq)
            msg_received = client.mr.read(client.msg_size, 0)
            validate(msg_received, False, client.msg_size)


# Decorators
def requires_odp(qp_type, required_odp_caps):
    def outer(func):
        def inner(instance):
            ctx = getattr(instance, 'ctx', d.Context(name=instance.dev_name))
            odp_supported(ctx, qp_type, required_odp_caps)
            if getattr(instance, 'is_implicit', False):
                odp_implicit_supported(instance.ctx)
            return func(instance)
        return inner
    return outer


def requires_root_on_eth(port_num=1):
    def outer(func):
        def inner(instance):
            if not (is_eth(instance.ctx, port_num) and is_root()):
                raise unittest.SkipTest('Must be run by root on Ethernet link layer')
            return func(instance)
        return inner
    return outer


def requires_mcast_support():
    """
    Check if the device support multicast
    return: True if multicast is supported
    """
    def outer(func):
        def inner(instance):
            ctx = d.Context(name=instance.dev_name)
            if ctx.query_device().max_mcast_grp == 0:
                raise unittest.SkipTest('Multicast is not supported on this device')
            return func(instance)
        return inner
    return outer


def odp_supported(ctx, qp_type, required_odp_caps):
    """
    Check device ODP capabilities
    :param ctx: Device Context
    :param qp_type: QP type ('rc', 'ud' or 'uc')
    :param required_odp_caps: ODP Capability mask of specified device
    :return: None
    """
    odp_caps = ctx.query_device_ex().odp_caps
    if odp_caps.general_caps == 0:
        raise unittest.SkipTest('ODP is not supported - No ODP caps')
    qp_odp_caps = getattr(odp_caps, '{}_odp_caps'.format(qp_type))
    if required_odp_caps & qp_odp_caps != required_odp_caps:
        raise unittest.SkipTest('ODP is unavailable - Operation not supported on this device')


def odp_implicit_supported(ctx):
    """
    Check device ODP implicit capability.
    :param ctx: Device Context
    :return: None
    """
    odp_caps = ctx.query_device_ex().odp_caps
    has_odp_implicit = odp_caps.general_caps & e.IBV_ODP_SUPPORT_IMPLICIT
    if has_odp_implicit == 0:
        raise unittest.SkipTest('ODP implicit is not supported')


def odp_v2_supported(ctx):
    """
    ODPv2 check
    :return: True/False if ODPv2 supported
    """
    from tests.mlx5_prm_structs import QueryHcaCapIn, QueryOdpCapOut, DevxOps, QueryHcaCapMod
    query_cap_in = QueryHcaCapIn(op_mod=DevxOps.MLX5_CMD_OP_QUERY_ODP_CAP << 1 | \
                                        QueryHcaCapMod.CURRENT)
    cmd_res = ctx.devx_general_cmd(query_cap_in, len(QueryOdpCapOut()))
    query_cap_out = QueryOdpCapOut(cmd_res)
    if query_cap_out.status:
        raise PyverbsRDMAError(f'QUERY_HCA_CAP has failed with status ({query_cap_out.status}) '
                               f'and syndrome ({query_cap_out.syndrome})')
    return query_cap_out.capability.mem_page_fault == 1


def requires_odpv2(func):
    def inner(instance):
        if not odp_v2_supported(instance.ctx):
            raise unittest.SkipTest('ODPv2 is not supported')
        return func(instance)
    return inner


def get_pci_name(dev_name):
    pci_name = glob.glob(f'/sys/bus/pci/devices/*/infiniband/{dev_name}')
    if not pci_name:
        raise unittest.SkipTest(f'Could not find the PCI device of {dev_name}')
    return pci_name[0].split('/')[5]


def requires_eswitch_on(func):
    def inner(instance):
        if not (is_eth(d.Context(name=instance.dev_name), instance.ib_port)
                and eswitch_mode_check(instance.dev_name)):
            raise unittest.SkipTest('Must be run on Ethernet link layer with Eswitch on')
        return func(instance)
    return inner


def eswitch_mode_check(dev_name):
    pci_name = get_pci_name(dev_name)
    eswicth_off_msg = f'Device {dev_name} must be in switchdev mode'
    try:
        cmd_out = subprocess.check_output(['devlink', 'dev', 'eswitch', 'show', f'pci/{pci_name}'],
                                          stderr=subprocess.DEVNULL)
        if 'switchdev' not in str(cmd_out):
            raise unittest.SkipTest(eswicth_off_msg)
    except subprocess.CalledProcessError:
        raise unittest.SkipTest(eswicth_off_msg)
    return True


def requires_roce_disabled(func):
    def inner(instance):
        if is_roce_enabled(instance.dev_name):
            raise unittest.SkipTest('ROCE must be disabled')
        return func(instance)
    return inner


def is_roce_enabled(dev_name):
    pci_name = get_pci_name(dev_name)
    cmd_out = subprocess.check_output(['devlink', 'dev', 'param', 'show', f'pci/{pci_name}',
                                       'name', 'enable_roce'],
                                      stderr=subprocess.DEVNULL)
    if 'value true' in str(cmd_out):
        return True
    return False


def requires_encap_disabled_if_eswitch_on(func):
    def inner(instance):
        if not (is_eth(d.Context(name=instance.dev_name), instance.ib_port)
                and encap_mode_check(instance.dev_name)):
            raise unittest.SkipTest('Encap must be disabled when Eswitch on')
        return func(instance)
    return inner


def encap_mode_check(dev_name):
    pci_name = get_pci_name(dev_name)
    encap_enable_msg = f'Device {dev_name}: Encap must be disabled over switchdev mode'
    try:
        cmd_out = subprocess.check_output(['devlink', 'dev', 'eswitch', 'show', f'pci/{pci_name}'],
                                          stderr=subprocess.DEVNULL)
        if 'switchdev' in str(cmd_out):
            if any([i for i in ['encap enable', 'encap-mode basic'] if i in str(cmd_out)]):
                raise unittest.SkipTest(encap_enable_msg)
    except subprocess.CalledProcessError:
        raise unittest.SkipTest(encap_enable_msg)
    return True

def requires_huge_pages():
    def outer(func):
        def inner(instance):
            huge_pages_supported()
            return func(instance)
        return inner
    return outer


def skip_unsupported(func):
    def func_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest(f'Operation not supported ({str(ex)})')
            raise ex
    return func_wrapper


def huge_pages_supported():
    """
    Check if huge pages are supported in the kernel.
    :return: None
    """
    huge_path = '/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'
    if not os.path.isfile(huge_path):
        raise unittest.SkipTest('Huge pages of size 2M is not supported in this platform')
    with open(huge_path, 'r') as f:
        if not int(f.read()):
            raise unittest.SkipTest('There are no huge pages of size 2M allocated')


@skip_unsupported
def query_nic_flow_table_caps(instance):
    from tests.mlx5_prm_structs import QueryHcaCapIn, QueryQosCapOut, QueryHcaCapOp, \
        QueryHcaCapMod, QueryCmdHcaNicFlowTableCapOut
    try:
        ctx = Mlx5Context(Mlx5DVContextAttr(), instance.dev_name)
    except PyverbsUserError as ex:
        raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
    except PyverbsRDMAError:
        raise unittest.SkipTest('Opening mlx5 context is not supported')
    # Query NIC Flow Table capabilities
    query_cap_in = QueryHcaCapIn(op_mod=(QueryHcaCapOp.HCA_NIC_FLOW_TABLE_CAP << 0x1) | \
                                        QueryHcaCapMod.CURRENT)
    cmd_res = ctx.devx_general_cmd(query_cap_in, len(QueryQosCapOut()))
    query_cap_out = QueryCmdHcaNicFlowTableCapOut(cmd_res)
    if query_cap_out.status:
        raise PyverbsRDMAError(f'QUERY_HCA_CAP has failed with status ({query_cap_out.status}) '
                               f'and syndrome ({query_cap_out.syndrome})')
    return query_cap_out.capability


def prefetch_mrs(agr_obj, sg_list, advice=e._IBV_ADVISE_MR_ADVICE_PREFETCH_WRITE,
                 flags=e._IBV_ADVISE_MR_FLAG_FLUSH):
    """
    Pre-fetch a range of an on-demand paging MR.
    :param agr_obj: Aggregation object which contains all resources necessary
    :param sg_list: SGE list
    :param advice: The requested advice value
    :param flags: Describes the properties of the advice operation
    :return: None
    """
    try:
        agr_obj.pd.advise_mr(advice, flags, sg_list)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EOPNOTSUPP:
            raise unittest.SkipTest(f'Advise MR with flags ({flags}) and advice ({advice}) is not supported')
        raise ex


def is_eth(ctx, port_num):
    """
    Querires the device's context's <port_num> port for its link layer.
    :param ctx: The Context to query
    :param port_num: Which Context's port to query
    :return: True if the port's link layer is Ethernet, else False
    """
    return ctx.query_port(port_num).link_layer == e.IBV_LINK_LAYER_ETHERNET


def is_datagram_qp(agr_obj):
    if agr_obj.qp.qp_type == e.IBV_QPT_UD or \
       isinstance(agr_obj, SRDResources) or \
       isinstance(agr_obj, Mlx5DcResources):
        return True
    return False


def is_root():
    return os.geteuid() == 0


def post_rq_state_bad_flow(test_obj):
    """
    Check post_recive on rq while qp is in invalid state.
    - Change qp's state to IBV_QPS_RESET
    - Verify post receive on qp fails
    :param test_obj: An instance of RDMATestCase
    :return: None.
    """
    qp_attr = QPAttr(qp_state=e.IBV_QPS_RESET, cur_qp_state=e.IBV_QPS_RTS)
    test_obj.server.qps[0].modify(qp_attr, e.IBV_QP_STATE)
    recv_wr = get_recv_wr(test_obj.server)
    with test_obj.assertRaises(PyverbsRDMAError) as ex:
        post_recv(test_obj.server, recv_wr, qp_idx=0)
    test_obj.assertEqual(ex.exception.error_code, errno.EINVAL)


def post_sq_state_bad_flow(test_obj):
    """
    Check post_send on sq while qp is in invalid state.
    - Change qp's state to IBV_QPS_RESET
    - Verify post send on qp fails
    :param test_obj: An instance of RDMATestCase
    :return: None.
    """
    qp_idx = 0
    qp_attr = QPAttr(qp_state=e.IBV_QPS_RESET, cur_qp_state=e.IBV_QPS_RTS)
    test_obj.client.qps[qp_idx].modify(qp_attr, e.IBV_QP_STATE)
    ah = get_global_ah(test_obj.client, test_obj.gid_index, test_obj.ib_port)
    _, sg = get_send_elements(test_obj.client, False)
    with test_obj.assertRaises(PyverbsRDMAError) as ex:
        send(test_obj.client, sg, e.IBV_WR_SEND, new_send=True,
             qp_idx=qp_idx, ah=ah)
    test_obj.assertEqual(ex.exception.error_code, errno.EINVAL)


def full_rq_bad_flow(test_obj):
    """
    Check post_recive while qp's rq is full.
    - Find qp's rq length.
    - Fill the qp with work requests until overflow.
    :param test_obj: An instance of RDMATestCase
    :return: None.
    """
    qp_attr, _ = test_obj.server.qps[0].query(e.IBV_QP_CAP)
    max_recv_wr = qp_attr.cap.max_recv_wr
    with test_obj.assertRaises(PyverbsRDMAError) as ex:
        for _ in range (max_recv_wr + 1):
            s_recv_wr = get_recv_wr(test_obj.server)
            post_recv(test_obj.server, s_recv_wr, qp_idx=0)
    test_obj.assertEqual(ex.exception.error_code, errno.ENOMEM)


def create_rq_with_larger_sgl_bad_flow(test_obj):
    """
    Check post_receive on qp while wr sgl is bigger than
    max sge allowed for the qp
    - Find max sge allowed for the qp
    - Create wr with sgl bigger than the max
    - Verify post receive on qp fails
    :param test_obj: An instance of RDMATestCase
    :return: None.
    """
    qp_idx = 0
    server_mr = test_obj.server.mr
    server_mr_buf = server_mr.buf
    qp_attr, _ = test_obj.server.qps[qp_idx].query(e.IBV_QP_CAP)
    max_recv_sge = qp_attr.cap.max_recv_sge
    length = test_obj.server.msg_size // (max_recv_sge + 1)
    sgl = []
    offset = 0
    for _ in range(max_recv_sge + 1):
        sgl.append(SGE(server_mr_buf + offset, length, server_mr.lkey))
        offset = offset + length
    s_recv_wr = RecvWR(sg=sgl, num_sge=max_recv_sge + 1)
    with test_obj.assertRaises(PyverbsRDMAError) as ex:
        post_recv(test_obj.server, s_recv_wr, qp_idx=qp_idx)
    test_obj.assertEqual(ex.exception.error_code, errno.EINVAL)


def high_rate_send(agr_obj, packet, rate_limit, timeout=2):
    """
    Sends packet at high rate for 'timeout' seconds.
    :param agr_obj: Aggregation object which contains all resources necessary
    :param packet: Packet to send
    :param rate_limit: Minimal rate limit in MBps
    :param timeout: Seconds to send the packets
    """
    send_sg = SGE(agr_obj.mr.buf, len(packet), agr_obj.mr.lkey)
    agr_obj.mr.write(packet, len(packet))
    send_wr = SendWR(num_sge=1, sg=[send_sg])
    poll = poll_cq_ex if isinstance(agr_obj.cq, CQEX) else poll_cq
    iterations = 0
    start_send_t = time.perf_counter()
    while (time.perf_counter() - start_send_t) < timeout:
        agr_obj.qp.post_send(send_wr)
        poll(agr_obj.cq)
        iterations += 1
    # Calculate the rate
    rate = agr_obj.msg_size * iterations / timeout / 1000000
    assert rate > rate_limit, 'Traffic rate is smaller than minimal rate for the test'


def get_pkey_from_kernel(device, port=1, index=0):
    path = f'/sys/class/infiniband/{device}/ports/{port}/pkeys/{index}'
    output = subprocess.check_output(['cat', path], universal_newlines=True)
    pkey_hex = output.strip()
    pkey_decimal = int(pkey_hex, 16)
    return pkey_decimal
