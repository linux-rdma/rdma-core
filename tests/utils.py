# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file
"""
Provide some useful helper function for pyverbs' tests.
"""
from itertools import combinations as com
import errno
import unittest
import random
import socket
import os

from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from pyverbs.addr import AHAttr, AH, GlobalRoute
from tests.base import XRCResources, DCT_KEY
from pyverbs.wr import SGE, SendWR, RecvWR
from pyverbs.qp import QPCap, QPInitAttr, QPInitAttrEx
from tests.mlx5_base import Mlx5DcResources
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.mr import MW, MWBindInfo
from pyverbs.cq import PollCqAttr
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
        cflags = random_qp_create_flags(qpt, attr_ex)
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


def create_custom_mr(agr_obj, additional_access_flags=0, size=None):
    """
    Creates a memory region using the aggregation object's PD.
    If size is None, the agr_obj's message size is used to set the MR's size.
    The access flags are local write and the additional_access_flags.
    :param agr_obj: The aggregation object that creates the MR
    :param additional_access_flags: Addition access flags to set in the MR
    :param size: MR's length. If None, agr_obj.msg_size is used.
    """
    mr_length = size if size else agr_obj.msg_size
    try:
        return MR(agr_obj.pd, mr_length,
                  e.IBV_ACCESS_LOCAL_WRITE | additional_access_flags)
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
    mr = agr_obj.mr
    qp_type = agr_obj.sqp_lst[0].qp_type if isinstance(agr_obj, XRCResources) \
                else agr_obj.qp.qp_type
    offset = GRH_SIZE if qp_type == e.IBV_QPT_UD else 0
    msg = (agr_obj.msg_size + offset) * ('s' if is_server else 'c')
    mr.write(msg, agr_obj.msg_size + offset)
    sge = SGE(mr.buf + offset, agr_obj.msg_size, mr.lkey)
    send_wr = SendWR(opcode=opcode, num_sge=1, sg=[sge])
    if opcode in [e.IBV_WR_RDMA_WRITE, e.IBV_WR_RDMA_READ]:
        send_wr.set_wr_rdma(int(agr_obj.rkey), int(agr_obj.remote_addr))
    return send_wr, sge

def get_recv_wr(agr_obj):
    """
    Creates a single SGE Recv WR for agr_obj's QP type.
    :param agr_obj: Aggregation object which contains all resources necessary
    :return: recv wr
    """
    qp_type = agr_obj.rqp_lst[0].qp_type if isinstance(agr_obj, XRCResources) \
                else agr_obj.qp.qp_type
    mr = agr_obj.mr
    length = agr_obj.msg_size + GRH_SIZE if qp_type == e.IBV_QPT_UD \
             else agr_obj.msg_size
    recv_sge = SGE(mr.buf, length, mr.lkey)
    return RecvWR(sg=[recv_sge], num_sge=1)


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
    gid = ctx.query_gid(port_num, gid_index)
    gr = GlobalRoute(dgid=gid, sgid_index=gid_index)
    return gr


def xrc_post_send(agr_obj, qp_num, send_object, gid_index, port, send_op=None):
    agr_obj.qps = agr_obj.sqp_lst
    if send_op:
        post_send_ex(agr_obj, send_object, gid_index, port, send_op)
    else:
        post_send(agr_obj, send_object, gid_index, port)


def post_send_ex(agr_obj, send_object, gid_index, port, send_op=None, qp_idx=0):
    qp = agr_obj.qps[qp_idx]
    qp_type = qp.qp_type
    qp.wr_start()
    qp.wr_id = 0x123
    qp.wr_flags = e.IBV_SEND_SIGNALED
    if send_op == e.IBV_QP_EX_WITH_SEND:
        qp.wr_send()
    elif send_op == e.IBV_QP_EX_WITH_RDMA_WRITE:
        qp.wr_rdma_write(agr_obj.rkey, agr_obj.raddr)
    elif send_op == e.IBV_QP_EX_WITH_SEND_WITH_IMM:
        qp.wr_send_imm(IMM_DATA)
    elif send_op == e.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM:
        qp.wr_rdma_write_imm(agr_obj.rkey, agr_obj.raddr, IMM_DATA)
    elif send_op == e.IBV_QP_EX_WITH_RDMA_READ:
        qp.wr_rdma_read(agr_obj.rkey, agr_obj.raddr)
    elif send_op == e.IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP:
        # We're checking the returned value (remote's content), so cmp/swp
        # values are of no importance.
        qp.wr_atomic_cmp_swp(agr_obj.rkey, agr_obj.raddr, 42, 43)
    elif send_op == e.IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD:
        qp.wr_atomic_fetch_add(agr_obj.rkey, agr_obj.raddr, 1)
    elif send_op == e.IBV_QP_EX_WITH_BIND_MW:
        bind_info = MWBindInfo(agr_obj.mr, agr_obj.mr.buf, agr_obj.mr.rkey,
                               e.IBV_ACCESS_REMOTE_WRITE)
        mw = MW(agr_obj.pd, mw_type=e.IBV_MW_TYPE_2)
        # A new rkey is needed to be set into bind_info, modify rkey
        qp.wr_bind_mw(mw, agr_obj.mr.rkey + 12, bind_info)
        qp.wr_send()
    if qp_type == e.IBV_QPT_UD:
        ah = get_global_ah(agr_obj, gid_index, port)
        qp.wr_set_ud_addr(ah, agr_obj.rqps_num[qp_idx], agr_obj.UD_QKEY)
    if qp_type == e.IBV_QPT_XRC_SEND:
        qp.wr_set_xrc_srqn(agr_obj.remote_srqn)
    if isinstance(agr_obj, Mlx5DcResources):
        ah = get_global_ah(agr_obj, gid_index, port)
        qp.wr_set_dc_addr(ah, agr_obj.remote_dct_num, DCT_KEY)
    qp.wr_set_sge(send_object)
    qp.wr_complete()


def post_send(agr_obj, send_wr, gid_index, port, qp_idx=0):
    """
    Post a single send WR to the QP. Post_send's second parameter (send bad wr)
    is ignored for simplicity. For UD traffic an address vector is added as
    well.
    :param agr_obj: aggregation object which contains all resources necessary
    :param send_wr: Send work request to post send
    :param gid_index: Local gid index
    :param port: IB port number
    :param qp_idx: QP index to use
    :return: None
    """
    qp_type = agr_obj.qp.qp_type
    if qp_type == e.IBV_QPT_UD:
        ah = get_global_ah(agr_obj, gid_index, port)
        send_wr.set_wr_ud(ah, agr_obj.rqps_num[qp_idx], agr_obj.UD_QKEY)
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
        receive_queue.post_recv(recv_wr, None)


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
    wcs = []
    channel = cq.comp_channel
    while count > 0:
        if channel:
            channel.get_cq_event(cq)
            cq.req_notify()
        nc, tmp_wcs = cq.poll(count)
        for wc in tmp_wcs:
            if wc.status != e.IBV_WC_SUCCESS:
                raise PyverbsRDMAError('Completion status is {s}'.
                                       format(s=wc_status_to_str(wc.status)),
                                       wc.status)
            if data:
                if wc.wc_flags & e.IBV_WC_WITH_IMM == 0:
                    raise PyverbsRDMAError('Completion without immediate')
                assert socket.ntohl(wc.imm_data) == data
        count -= nc
        wcs.extend(tmp_wcs)
    return wcs


def poll_cq_ex(cqex, count=1, data=None):
    """
    Poll <count> completions from the extended CQ.
    :param cq: CQEX to poll from
    :param count: How many completions to poll
    :param data: In case of a work request with immediate, the immediate data
                 to be compared after poll
    :return: None
    """
    try:
        poll_attr = PollCqAttr()
        ret = cqex.start_poll(poll_attr)
        while ret == 2: # ENOENT
            ret = cqex.start_poll(poll_attr)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to poll CQ')
        count -= 1
        if cqex.status != e.IBV_WC_SUCCESS:
            raise PyverbsRDMAErrno('Completion status is {s}'.
                                   format(s=cqex.status))
        if data:
            assert data == socket.ntohl(cqex.read_imm_data())
        # Now poll the rest of the packets
        while count > 0:
            ret = cqex.poll_next()
            while ret == 2:
                ret = cqex.poll_next()
            if ret != 0:
                raise PyverbsRDMAErrno('Failed to poll CQ')
            if cqex.status != e.IBV_WC_SUCCESS:
                raise PyverbsRDMAErrno('Completion status is {s}'.
                                       format(s=cqex.status))
            if data:
                assert data == socket.ntohl(cqex.read_imm_data())
            count -= 1
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


def send(agr_obj, send_object, gid_index, port, send_op=None, new_send=False, qp_idx=0):
    if new_send:
        return post_send_ex(agr_obj, send_object, gid_index, port, send_op, qp_idx)
    return post_send(agr_obj, send_object, gid_index, port, qp_idx)


def traffic(client, server, iters, gid_idx, port, is_cq_ex=False, send_op=None,
            new_send=False):
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
    :return:
    """
    poll = poll_cq_ex if is_cq_ex else poll_cq
    if send_op == e.IBV_QP_EX_WITH_SEND_WITH_IMM or \
       send_op == e.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM:
        imm_data = IMM_DATA
    else:
        imm_data = None
    s_recv_wr = get_recv_wr(server)
    c_recv_wr = get_recv_wr(client)
    for qp_idx in range(server.qp_count):
        # prepare the receive queue with RecvWR
        post_recv(client, c_recv_wr, qp_idx=qp_idx)
        post_recv(server, s_recv_wr, qp_idx=qp_idx)
    read_offset = GRH_SIZE if client.qp.qp_type == e.IBV_QPT_UD else 0
    for _ in range(iters):
        for qp_idx in range(server.qp_count):
            c_send_wr, c_sg = get_send_elements(client, False)
            if client.use_mr_prefetch:
                flags = e._IBV_ADVISE_MR_FLAG_FLUSH
                if client.use_mr_prefetch == 'async':
                    flags = 0
                prefetch_mrs(client, [c_sg], advice=client.prefetch_advice,
                             flags=flags)
            c_send_object = c_sg if send_op else c_send_wr
            send(client, c_send_object, gid_idx, port, send_op, new_send,
                 qp_idx)
            poll(client.cq)
            poll(server.cq, data=imm_data)
            post_recv(server, s_recv_wr, qp_idx=qp_idx)
            msg_received = server.mr.read(server.msg_size, read_offset)
            validate(msg_received, True, server.msg_size)
            s_send_wr, s_sg = get_send_elements(server, True)
            if server.use_mr_prefetch:
                flags = e._IBV_ADVISE_MR_FLAG_FLUSH
                if server.use_mr_prefetch == 'async':
                    flags = 0
                prefetch_mrs(server, [s_sg], advice=server.prefetch_advice,
                             flags=flags)
            s_send_object = s_sg if send_op else s_send_wr
            send(server, s_send_object, gid_idx, port, send_op, new_send,
                 qp_idx)
            poll(server.cq)
            poll(client.cq, data=imm_data)
            post_recv(client, c_recv_wr, qp_idx=qp_idx)
            msg_received = client.mr.read(client.msg_size, read_offset)
            validate(msg_received, False, client.msg_size)


def rdma_traffic(client, server, iters, gid_idx, port, new_send=False,
                 send_op=None):
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
    :return:
    """
    # Using the new post send API, we need the SGE, not the SendWR
    send_element_idx = 1 if new_send else 0
    same_side_check =  send_op in [e.IBV_QP_EX_WITH_RDMA_READ,
                                   e.IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP,
                                   e.IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD,
                                   e.IBV_WR_RDMA_READ]
    for _ in range(iters):
        c_send_wr = get_send_elements(client, False, send_op)[send_element_idx]
        send(client, c_send_wr, gid_idx, port, send_op, new_send)
        poll_cq(client.cq)
        if same_side_check:
            msg_received = client.mr.read(client.msg_size, 0)
        else:
            msg_received = server.mr.read(server.msg_size, 0)
        validate(msg_received, False if same_side_check else True,
                 server.msg_size)
        s_send_wr = get_send_elements(server, True, send_op)[send_element_idx]
        if same_side_check:
            client.mr.write('c' * client.msg_size, client.msg_size)
        send(server, s_send_wr, gid_idx, port, send_op, new_send)
        poll_cq(server.cq)
        if same_side_check:
            msg_received = server.mr.read(client.msg_size, 0)
        else:
            msg_received = client.mr.read(server.msg_size, 0)
        validate(msg_received, True if same_side_check else False,
                 client.msg_size)
        if same_side_check:
            server.mr.write('s' * server.msg_size, server.msg_size)


def xrc_traffic(client, server, is_cq_ex=False, send_op=None):
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
            c_send_wr = get_send_elements(client, False)[send_element_idx]
            if send_op is None:
                c_send_wr.set_qp_type_xrc(client.remote_srqn)
            xrc_post_send(client, i, c_send_wr, 0, 0, send_op)
            poll(client.cq)
            poll(server.cq)
            msg_received = server.mr.read(server.msg_size, 0)
            validate(msg_received, True, server.msg_size)
            s_send_wr = get_send_elements(server, True)[send_element_idx]
            if send_op is None:
                s_send_wr.set_qp_type_xrc(server.remote_srqn)
            xrc_post_send(server, i, s_send_wr, 0, 0, send_op)
            poll(server.cq)
            poll(client.cq)
            msg_received = client.mr.read(client.msg_size, 0)
            validate(msg_received, False, client.msg_size)


# Decorators
def requires_odp(qp_type, required_odp_caps):
    def outer(func):
        def inner(instance):
            odp_supported(instance.ctx, qp_type, required_odp_caps)
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
    Check device ODP capabilities, support only send/recv so far.
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
        raise unittest.SkipTest('ODP is not supported - ODP recv/send is not supported')


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


def requires_huge_pages():
    def outer(func):
        def inner(instance):
            huge_pages_supported()
            return func(instance)
        return inner
    return outer


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


def is_root():
    return os.geteuid() == 0
