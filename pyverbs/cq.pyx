# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.
import weakref

from pyverbs.pyverbs_error import PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
cimport pyverbs.libibverbs_enums as e
from pyverbs.device cimport Context
from pyverbs.srq cimport SRQ
from pyverbs.qp cimport QP

cdef class CompChannel(PyverbsCM):
    """
    A completion channel is a file descriptor used to deliver completion
    notifications to a userspace process. When a completion event is generated
    for a CQ, the event is delivered via the completion channel attached to the
    CQ.
    """
    def __init__(self, Context context not None):
        """
        Initializes a completion channel object on the given device.
        :param context: The device's context to use
        :return: A CompChannel object on success
        """
        super().__init__()
        self.cc = v.ibv_create_comp_channel(context.context)
        if self.cc == NULL:
            raise PyverbsRDMAErrno('Failed to create a completion channel')
        self.context = context
        context.add_ref(self)
        self.cqs = weakref.WeakSet()
        self.logger.debug('Created a Completion Channel')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing completion channel')
        close_weakrefs([self.cqs])
        if self.cc != NULL:
            rc = v.ibv_destroy_comp_channel(self.cc)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to destroy a completion channel')
            self.cc = NULL

    def get_cq_event(self, CQ expected_cq):
        """
        Waits for the next completion event in the completion event channel
        :param expected_cq: The CQ that is expected to get the event
        :return: None
        """
        cdef v.ibv_cq *cq
        cdef void *ctx

        rc = v.ibv_get_cq_event(self.cc, &cq, &ctx)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to get CQ event')
        if cq != expected_cq.cq:
            raise PyverbsRDMAErrno('Received event on an unexpected CQ')
        expected_cq.num_events += 1

    cdef add_ref(self, obj):
        if isinstance(obj, CQ) or isinstance(obj, CQEX):
            self.cqs.add(obj)


cdef class CQ(PyverbsCM):
    """
    A Completion Queue is the notification mechanism for work request
    completions. A CQ can have 0 or more associated QPs.
    """
    def __init__(self, Context context not None, cqe, cq_context=None,
                 CompChannel channel=None, comp_vector=0):
        """
        Initializes a CQ object with the given parameters.
        :param context: The device's context on which to open the CQ
        :param cqe: CQ's capacity
        :param cq_context: User context's pointer
        :param channel: If set, will be used to return completion events
        :param comp_vector: Will be used for signaling completion events.
                            Must be larger than 0 and smaller than the
                            context's num_comp_vectors
        :return: The newly created CQ
        """
        super().__init__()
        if channel is not None:
            self.cq = v.ibv_create_cq(context.context, cqe, <void*>cq_context,
                                      channel.cc, comp_vector)
            channel.add_ref(self)
            self.channel = channel
        else:
            self.cq = v.ibv_create_cq(context.context, cqe, <void*>cq_context,
                                      NULL, comp_vector)
            self.channel = None
        if self.cq == NULL:
            raise PyverbsRDMAErrno('Failed to create a CQ')
        self.context = context
        context.add_ref(self)
        self.qps = weakref.WeakSet()
        self.srqs = weakref.WeakSet()
        self.num_events = 0
        self.logger.debug('Created a CQ')

    cdef add_ref(self, obj):
        if isinstance(obj, QP):
            self.qps.add(obj)
        elif isinstance(obj, SRQ):
            self.srqs.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing CQ')
        close_weakrefs([self.qps, self.srqs])
        if self.num_events:
            self.ack_events(self.num_events)
        if self.cq != NULL:
            rc = v.ibv_destroy_cq(self.cq)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to close CQ')
            self.cq = NULL
            self.context = None
            self.channel = None

    def poll(self, num_entries=1):
        """
        Polls the CQ for completions.
        :param num_entries: number of completions to pull
        :return: (npolled, wcs): The number of polled completions and an array
                 of the polled completions
        """
        cdef v.ibv_wc wc
        wcs = []
        npolled = 0

        while npolled < num_entries:
            rc = v.ibv_poll_cq(self.cq, 1, &wc)
            if rc < 0:
                raise PyverbsRDMAErrno('Failed to poll CQ')
            if rc == 0:
                break;
            npolled += 1
            wcs.append(WC(wr_id=wc.wr_id, status=wc.status, opcode=wc.opcode,
                          vendor_err=wc.vendor_err, byte_len=wc.byte_len,
                          qp_num=wc.qp_num, src_qp=wc.src_qp,
                          imm_data=wc.imm_data, wc_flags=wc.wc_flags,
                          pkey_index=wc.pkey_index, slid=wc.slid, sl=wc.sl,
                          dlid_path_bits=wc.dlid_path_bits))
        return npolled, wcs

    def req_notify(self, solicited_only = False):
        """
        Request completion notification on the completion queue.
        :param solicited_only: If non-zero, notifications will be created only
                               for incoming send / RDMA write WRs with
                               immediate data that have the solicited bit set in
                               their send flags.
        :return: None
        """
        rc = v.ibv_req_notify_cq(self.cq, solicited_only)
        if rc != 0:
            raise PyverbsRDMAErrno('Request notify CQ returned {rc}'.
                                   format(rc=rc))

    def ack_events(self, num_events):
        """
        Get and acknowledge CQ events
        :param num_events: Number of events to acknowledge
        :return: None
        """
        v.ibv_ack_cq_events(self.cq, num_events)
        self.num_events -= num_events

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return 'CQ\n' +\
               print_format.format('Handle', self.cq.handle) +\
               print_format.format('CQEs', self.cq.cqe)

    @property
    def comp_channel(self):
        return self.channel


cdef class CqInitAttrEx(PyverbsObject):
    def __init__(self, cqe = 100, CompChannel channel = None, comp_vector = 0,
                 wc_flags = 0, comp_mask = 0, flags = 0):
        """
        Initializes a CqInitAttrEx object with the given parameters.
        :param cqe: CQ's capacity
        :param channel: If set, will be used to return completion events
        :param comp_vector: Will be used for signaling completion events.
                            Must be larger than 0 and smaller than the
                            context's num_comp_vectors
        :param wc_flags: The wc_flags that should be returned in ibv_poll_cq_ex.
                         Or'ed bit of enum ibv_wc_flags_ex.
        :param comp_mask: compatibility mask (extended verb)
        :param flags: create cq attr flags - one or more flags from
                      ibv_create_cq_attr_flags enum
        :return:
        """
        super().__init__()
        self.attr.cqe = cqe
        self.attr.cq_context = NULL
        self.attr.channel = NULL if channel is None else channel.cc
        self.attr.comp_vector = comp_vector
        self.attr.wc_flags = wc_flags
        self.attr.comp_mask = comp_mask
        self.attr.flags = flags
        self.channel = channel

    @property
    def cqe(self):
        return self.attr.cqe
    @cqe.setter
    def cqe(self, val):
        self.attr.cqe = val

    # Setter-only properties require the older syntax
    property cq_context:
        def __set__(self, val):
            self.attr.cq_context = <void*>val

    @property
    def comp_channel(self):
        return self.channel
    @comp_channel.setter
    def comp_channel(self, CompChannel val):
        self.channel = val
        self.attr.channel = val.cc

    @property
    def comp_vector(self):
        return self.attr.comp_vector
    @comp_vector.setter
    def comp_vector(self, val):
        self.attr.comp_vector = val

    @property
    def wc_flags(self):
        return self.attr.wc_flags
    @wc_flags.setter
    def wc_flags(self, val):
        self.attr.wc_flags = val

    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val

    @property
    def flags(self):
        return self.attr.flags
    @flags.setter
    def flags(self, val):
        self.attr.flags = val

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return print_format.format('Number of CQEs', self.cqe) +\
            print_format.format('WC flags', create_wc_flags_to_str(self.wc_flags)) +\
            print_format.format('comp mask', self.comp_mask) +\
            print_format.format('flags', self.flags)


cdef class CQEX(PyverbsCM):
    def __init__(self, Context context not None, CqInitAttrEx init_attr):
        """
        Initializes a CQEX object on the given device's context with the given
        attributes.
        :param context: The device's context on which to open the CQ
        :param init_attr: Initial attributes that describe the CQ
        :return: The newly created CQEX on success
        """
        super().__init__()
        self.qps = weakref.WeakSet()
        self.srqs = weakref.WeakSet()
        if self.cq != NULL:
            # Leave CQ initialization to the provider
            return
        if init_attr is None:
            init_attr = CqInitAttrEx()
        self.cq = v.ibv_create_cq_ex(context.context, &init_attr.attr)
        if init_attr.comp_channel:
            init_attr.comp_channel.add_ref(self)
        if self.cq == NULL:
            raise PyverbsRDMAErrno('Failed to create extended CQ')
        self.ibv_cq = v.ibv_cq_ex_to_cq(self.cq)
        self.context = context
        context.add_ref(self)

    cdef add_ref(self, obj):
        if isinstance(obj, QP):
            self.qps.add(obj)
        elif isinstance(obj, SRQ):
            self.srqs.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing CQEx')
        close_weakrefs([self.srqs, self.qps])
        if self.cq != NULL:
            rc = v.ibv_destroy_cq(<v.ibv_cq*>self.cq)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to destroy CQEX')
            self.cq = NULL
            self.context = None

    def start_poll(self, PollCqAttr attr):
        """
        Start polling a batch of work completions.
        :param attr: For easy future extensions
        :return: 0 on success, ENOENT when no completions are available
        """
        if attr is None:
            attr = PollCqAttr()
        return v.ibv_start_poll(self.cq, &attr.attr)

    def poll_next(self):
        """
        Get the next work completion.
        :return: 0 on success, ENOENT when no completions are available
        """
        return v.ibv_next_poll(self.cq)

    def end_poll(self):
        """
        Indicates the end of polling batch of work completions
        :return: None
        """
        return v.ibv_end_poll(self.cq)

    def read_opcode(self):
        return v.ibv_wc_read_opcode(self.cq)
    def read_vendor_err(self):
        return v.ibv_wc_read_vendor_err(self.cq)
    def read_byte_len(self):
        return v.ibv_wc_read_byte_len(self.cq)
    def read_imm_data(self):
        return v.ibv_wc_read_imm_data(self.cq)
    def read_qp_num(self):
        return v.ibv_wc_read_qp_num(self.cq)
    def read_src_qp(self):
        return v.ibv_wc_read_src_qp(self.cq)
    def read_wc_flags(self):
        return v.ibv_wc_read_wc_flags(self.cq)
    def read_slid(self):
        return v.ibv_wc_read_slid(self.cq)
    def read_sl(self):
        return v.ibv_wc_read_sl(self.cq)
    def read_dlid_path_bits(self):
        return v.ibv_wc_read_dlid_path_bits(self.cq)
    def read_timestamp(self):
        return v.ibv_wc_read_completion_ts(self.cq)
    def read_cvlan(self):
        return v.ibv_wc_read_cvlan(self.cq)
    def read_flow_tag(self):
        return v.ibv_wc_read_flow_tag(self.cq)
    def read_tm_info(self):
        info = WcTmInfo()
        v.ibv_wc_read_tm_info(self.cq, &info.info)
        return info
    def read_completion_wallclock_ns(self):
        return v.ibv_wc_read_completion_wallclock_ns(self.cq)

    @property
    def status(self):
        return self.cq.status
    @status.setter
    def status(self, val):
        self.cq.status = val

    @property
    def wr_id(self):
        return self.cq.wr_id
    @wr_id.setter
    def wr_id(self, val):
        self.cq.wr_id = val

    def __str__(self):
        print_format = '{:<22}: {:<20}\n'
        return 'Extended CQ:\n' +\
               print_format.format('Handle', self.cq.handle) +\
               print_format.format('CQEs', self.cq.cqe)


cdef class WC(PyverbsObject):
    def __init__(self, wr_id=0, status=0, opcode=0, vendor_err=0, byte_len=0,
                 qp_num=0, src_qp=0, imm_data=0, wc_flags=0, pkey_index=0,
                 slid=0, sl=0, dlid_path_bits=0):
        super().__init__()
        self.wc.wr_id = wr_id
        self.wc.status = status
        self.wc.opcode = opcode
        self.wc.vendor_err = vendor_err
        self.wc.byte_len = byte_len
        self.wc.qp_num = qp_num
        self.wc.src_qp = src_qp
        self.wc.wc_flags = wc_flags
        self.wc.pkey_index = pkey_index
        self.wc.slid = slid
        self.wc.imm_data = imm_data
        self.wc.sl = sl
        self.wc.dlid_path_bits = dlid_path_bits

    @property
    def wr_id(self):
        return self.wc.wr_id
    @wr_id.setter
    def wr_id(self, val):
        self.wc.wr_id = val

    @property
    def status(self):
        return self.wc.status
    @status.setter
    def status(self, val):
        self.wc.status = val

    @property
    def opcode(self):
        return self.wc.opcode
    @opcode.setter
    def opcode(self, val):
        self.wc.opcode = val

    @property
    def vendor_err(self):
        return self.wc.vendor_err
    @vendor_err.setter
    def vendor_err(self, val):
        self.wc.vendor_err = val

    @property
    def byte_len(self):
        return self.wc.byte_len
    @byte_len.setter
    def byte_len(self, val):
        self.wc.byte_len = val

    @property
    def qp_num(self):
        return self.wc.qp_num
    @qp_num.setter
    def qp_num(self, val):
        self.wc.qp_num = val

    @property
    def src_qp(self):
        return self.wc.src_qp
    @src_qp.setter
    def src_qp(self, val):
        self.wc.src_qp = val

    @property
    def wc_flags(self):
        return self.wc.wc_flags
    @wc_flags.setter
    def wc_flags(self, val):
        self.wc.wc_flags = val

    @property
    def pkey_index(self):
        return self.wc.pkey_index
    @pkey_index.setter
    def pkey_index(self, val):
        self.wc.pkey_index = val

    @property
    def slid(self):
        return self.wc.slid
    @slid.setter
    def slid(self, val):
        self.wc.slid = val

    @property
    def sl(self):
        return self.wc.sl
    @sl.setter
    def sl(self, val):
        self.wc.sl = val

    @property
    def imm_data(self):
        return self.wc.imm_data
    @imm_data.setter
    def imm_data(self, val):
        self.wc.imm_data = val

    @property
    def dlid_path_bits(self):
        return self.wc.dlid_path_bits
    @dlid_path_bits.setter
    def dlid_path_bits(self, val):
        self.wc.dlid_path_bits = val

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return print_format.format('WR ID', self.wr_id) +\
            print_format.format('status', cqe_status_to_str(self.status)) +\
            print_format.format('opcode', cqe_opcode_to_str(self.opcode)) +\
            print_format.format('vendor error', self.vendor_err) +\
            print_format.format('byte length', self.byte_len) +\
            print_format.format('QP num', self.qp_num) +\
            print_format.format('source QP', self.src_qp) +\
            print_format.format('WC flags', cqe_flags_to_str(self.wc_flags)) +\
            print_format.format('pkey index', self.pkey_index) +\
            print_format.format('slid', self.slid) +\
            print_format.format('sl', self.sl) +\
            print_format.format('imm_data', self.imm_data) +\
            print_format.format('dlid path bits', self.dlid_path_bits)


cdef class PollCqAttr(PyverbsObject):
    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val


cdef class WcTmInfo(PyverbsObject):
    @property
    def tag(self):
        return self.info.tag
    @tag.setter
    def tag(self, val):
        self.info.tag = val

    @property
    def priv(self):
        return self.info.priv
    @priv.setter
    def priv(self, val):
        self.info.priv = val


def cqe_status_to_str(status):
    try:
        return {e.IBV_WC_SUCCESS: "success",
                e.IBV_WC_LOC_LEN_ERR: "local length error",
                e.IBV_WC_LOC_QP_OP_ERR: "local QP op error",
                e.IBV_WC_LOC_EEC_OP_ERR: "local EEC op error",
                e.IBV_WC_LOC_PROT_ERR: "local protection error",
                e.IBV_WC_WR_FLUSH_ERR: "WR flush error",
                e.IBV_WC_MW_BIND_ERR: "memory window bind error",
                e.IBV_WC_BAD_RESP_ERR: "bad response error",
                e.IBV_WC_LOC_ACCESS_ERR: "local access error",
                e.IBV_WC_REM_INV_REQ_ERR: "remote invalidate request error",
                e.IBV_WC_REM_ACCESS_ERR: "remote access error",
                e.IBV_WC_REM_OP_ERR: "remote op error",
                e.IBV_WC_RETRY_EXC_ERR: "retry exceeded error",
                e.IBV_WC_RNR_RETRY_EXC_ERR: "RNR retry exceeded",
                e.IBV_WC_LOC_RDD_VIOL_ERR: "local RDD violation error",
                e.IBV_WC_REM_INV_RD_REQ_ERR: "remote invalidate RD request error",
                e.IBV_WC_REM_ABORT_ERR: "remote abort error",
                e.IBV_WC_INV_EECN_ERR: "invalidate EECN error",
                e.IBV_WC_INV_EEC_STATE_ERR: "invalidate EEC state error",
                e.IBV_WC_FATAL_ERR: "WC fatal error",
                e.IBV_WC_RESP_TIMEOUT_ERR: "response timeout error",
                e.IBV_WC_GENERAL_ERR: "general error"}[status]
    except KeyError:
        return "Unknown CQE status"

def cqe_opcode_to_str(opcode):
    try:
        return {0x0: "Send", 0x1:"RDMA write", 0x2: "RDMA read",
                0x3: "Compare and swap", 0x4: "Fetch and add",
                0x5: "Bind Memory window", 0x6: "Local invalidate",
                0x7: "TSO", 0x80: "Receive",
                0x81: "Receive RDMA with immediate",
                0x82: "Tag matching - add", 0x83: "Tag matching - delete",
                0x84: "Tag matching - sync", 0x85: "Tag matching - receive",
                0x86: "Tag matching - no tag"}[opcode]
    except KeyError:
        return "Unknown CQE opcode {op}".format(op=opcode)

def flags_to_str(flags, dictionary):
    flags_str = ""
    for f in dictionary:
        if flags & f:
            flags_str += dictionary[f]
            flags_str += " "
    return flags_str


def cqe_flags_to_str(flags):
    cqe_flags = {1: "GRH", 2: "With immediate", 4: "IP csum OK",
                 8: "With invalidate", 16: "TM sync request", 32: "TM match",
                 64: "TM data valid"}
    return flags_to_str(flags, cqe_flags)

def create_wc_flags_to_str(flags):
    cqe_flags = {e.IBV_WC_EX_WITH_BYTE_LEN: 'IBV_WC_EX_WITH_BYTE_LEN',
                 e.IBV_WC_EX_WITH_IMM: 'IBV_WC_EX_WITH_IMM',
                 e.IBV_WC_EX_WITH_QP_NUM: 'IBV_WC_EX_WITH_QP_NUM',
                 e.IBV_WC_EX_WITH_SRC_QP: 'IBV_WC_EX_WITH_SRC_QP',
                 e.IBV_WC_EX_WITH_SLID: 'IBV_WC_EX_WITH_SLID',
                 e.IBV_WC_EX_WITH_SL: 'IBV_WC_EX_WITH_SL',
                 e.IBV_WC_EX_WITH_DLID_PATH_BITS: 'IBV_WC_EX_WITH_DLID_PATH_BITS',
                 e.IBV_WC_EX_WITH_COMPLETION_TIMESTAMP: 'IBV_WC_EX_WITH_COMPLETION_TIMESTAMP',
                 e.IBV_WC_EX_WITH_CVLAN: 'IBV_WC_EX_WITH_CVLAN',
                 e.IBV_WC_EX_WITH_FLOW_TAG: 'IBV_WC_EX_WITH_FLOW_TAG',
                 e.IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK: 'IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK'}
    return flags_to_str(flags, cqe_flags)
