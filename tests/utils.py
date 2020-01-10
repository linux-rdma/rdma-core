# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file
"""
Provide some useful helper function for pyverbs' tests.
"""
from itertools import combinations as com
from string import ascii_lowercase as al
import unittest
import random
import os

from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from pyverbs.addr import AHAttr, AH, GlobalRoute
from pyverbs.wr import SGE, SendWR, RecvWR
from pyverbs.qp import QPCap, QPInitAttrEx
from tests.base import XRCResources
from pyverbs.cq import PollCqAttr
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
GRH_SIZE = 40


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
    if mask & e.IBV_QP_INIT_ATTR_MAX_TSO_HEADER:
        # TSO increases send WQE size, let's be on the safe side
        qia.cap.max_send_sge = 2
    return qia


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

# Traffic helpers

def get_send_wr(agr_obj, is_server):
    """
    Creates a single SGE Send WR for agr_obj's QP type. The content of the
    message is either 's' for server side or 'c' for client side.
    :param agr_obj: Aggregation object which contains all resources necessary
    :param is_server: Indicates whether this is server or client side
    :return: send wr
    """
    qp_type = agr_obj.sqp_lst[0].qp_type if isinstance(agr_obj, XRCResources) \
                else agr_obj.qp.qp_type
    mr = agr_obj.mr
    offset = GRH_SIZE if qp_type == e.IBV_QPT_UD else 0
    send_sge = SGE(mr.buf + offset, agr_obj.msg_size, mr.lkey)
    msg = (agr_obj.msg_size + offset) * ('s' if is_server else 'c')
    mr.write(msg, agr_obj.msg_size + offset)
    return SendWR(num_sge=1, sg=[send_sge])


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


def post_send(agr_obj, send_wr, gid_index, port):
    """
    Post a single send WR to the QP. Post_send's second parameter (send bad wr)
    is ignored for simplicity. For UD traffic an address vector is added as
    well.
    :param agr_obj: aggregation object which contains all resources necessary
    :param send_wr: Send work request to post send
    :param gid_index: Local gid index
    :param port: IB port number
    :return: None
    """
    qp_type = agr_obj.qp.qp_type
    if qp_type == e.IBV_QPT_UD:
        gr = GlobalRoute(dgid=agr_obj.ctx.query_gid(port, gid_index),
                         sgid_index=gid_index)
        ah_attr = AHAttr(port_num=port, is_global=1, gr=gr,
                         dlid=agr_obj.port_attr.lid)
        ah = AH(agr_obj.pd, attr=ah_attr)
        send_wr.set_wr_ud(ah, agr_obj.rqpn, agr_obj.UD_QKEY)
    agr_obj.qp.post_send(send_wr, None)


def post_recv(qp, recv_wr, num_wqes=1):
    """
    Call the QP's post_recv() method <num_wqes> times. Post_recv's second
    parameter (recv bad wr) is ignored for simplicity.
    :param qp: QP which posts receive work request
    :param recv_wr: Receive work request to post
    :param num_wqes: Number of WQEs to post
    :return: None
    """
    for _ in range(num_wqes):
        qp.post_recv(recv_wr, None)


def poll_cq(cq, count=1):
    """
    Poll <count> completions from the CQ.
    Note: This function calls the blocking poll() method of the CQ
    until <count> completions were received. Alternatively, gets a
    single CQ event when events are used.
    :param cq: CQ to poll from
    :param count: How many completions to poll
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
                                       format(s=wc_status_to_str(wc.status)))
        count -= nc
        wcs.extend(tmp_wcs)
    return wcs


def poll_cq_ex(cqex, count=1):
    """
    Poll <count> completions from the extended CQ.
    :param cq: CQEX to poll from
    :param count: How many completions to poll
    :return: None
    """
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
        count -= 1
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


def traffic(client, server, iters, gid_idx, port, is_cq_ex=False):
    """
    Runs basic traffic between two sides
    :param client: client side, clients base class is BaseTraffic
    :param server: server side, servers base class is BaseTraffic
    :param iters: number of traffic iterations
    :param gid_idx: local gid index
    :param port: IB port
    :param is_cq_ex: If True, use poll_cq_ex() rather than poll_cq()
    :return:
    """
    poll = poll_cq_ex if is_cq_ex else poll_cq
    s_recv_wr = get_recv_wr(server)
    c_recv_wr = get_recv_wr(client)
    post_recv(client.qp, c_recv_wr, client.num_msgs)
    post_recv(server.qp, s_recv_wr, server.num_msgs)
    read_offset = GRH_SIZE if client.qp.qp_type == e.IBV_QPT_UD else 0
    for _ in range(iters):
        c_send_wr = get_send_wr(client, False)
        post_send(client, c_send_wr, gid_idx, port)
        poll(client.cq)
        poll(server.cq)
        post_recv(client.qp, c_recv_wr)
        msg_received = server.mr.read(server.msg_size, read_offset)
        validate(msg_received, True, server.msg_size)
        s_send_wr = get_send_wr(server, True)
        post_send(server, s_send_wr, gid_idx, port)
        poll(server.cq)
        poll(client.cq)
        post_recv(server.qp, s_recv_wr)
        msg_received = client.mr.read(client.msg_size, read_offset)
        validate(msg_received, False, client.msg_size)


def xrc_traffic(client, server, is_cq_ex=False):
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
    :return: None
    """
    poll = poll_cq_ex if is_cq_ex else poll_cq
    client_srqn = client.srq.get_srq_num()
    server_srqn = server.srq.get_srq_num()
    s_recv_wr = get_recv_wr(server)
    c_recv_wr = get_recv_wr(client)
    post_recv(client.srq, c_recv_wr, client.qp_count*client.num_msgs)
    post_recv(server.srq, s_recv_wr, server.qp_count*server.num_msgs)
    for _ in range(client.num_msgs):
        for i in range(server.qp_count):
            c_send_wr = get_send_wr(client, False)
            c_send_wr.set_qp_type_xrc(server_srqn)
            client.sqp_lst[i].post_send(c_send_wr)
            poll(client.cq)
            poll(server.cq)
            msg_received = server.mr.read(server.msg_size, 0)
            validate(msg_received, True, server.msg_size)
            s_send_wr = get_send_wr(server, True)
            s_send_wr.set_qp_type_xrc(client_srqn)
            server.sqp_lst[i].post_send(s_send_wr)
            poll(server.cq)
            poll(client.cq)
            msg_received = client.mr.read(client.msg_size, 0)
            validate(msg_received, False, client.msg_size)


# Decorators
def requires_odp(qp_type):
    def outer(func):
        def inner(instance):
            odp_supported(instance.ctx, qp_type)
            return func(instance)
        return inner
    return outer


def odp_supported(ctx, qp_type):
    """
    Check device ODP capabilities, support only send/recv so far.
    :param ctx: Device Context
    :param qp_type: QP type ('rc', 'ud' or 'uc')
    :return: None
    """
    odp_caps = ctx.query_device_ex().odp_caps
    if odp_caps.general_caps == 0:
        raise unittest.SkipTest('ODP is not supported - No ODP caps')
    qp_odp_caps = getattr(odp_caps, '{}_odp_caps'.format(qp_type))
    has_odp_send = qp_odp_caps & e.IBV_ODP_SUPPORT_SEND
    has_odp_recv = qp_odp_caps & e.IBV_ODP_SUPPORT_SRQ_RECV if qp_type == 'xrc'\
                else qp_odp_caps & e.IBV_ODP_SUPPORT_RECV
    if has_odp_send == 0:
        raise unittest.SkipTest('ODP is not supported - ODP send not supported')
    if has_odp_recv == 0:
        raise unittest.SkipTest('ODP is not supported - ODP recv not supported')


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
