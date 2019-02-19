# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.
from pyverbs.base import PyverbsRDMAErrno
cimport pyverbs.libibverbs_enums as e
from pyverbs.device cimport Context

cdef class CompChannel(PyverbsCM):
    """
    A completion channel is a file descriptor used to deliver completion
    notifications to a userspace process. When a completion event is generated
    for a CQ, the event is delivered via the completion channel attached to the
    CQ.
    """
    def __cinit__(self, Context context not None):
        """
        Initializes a completion channel object on the given device.
        :param context: The device's context to use
        :return: A CompChannel object on success
        """
        self.cc = v.ibv_create_comp_channel(context.context)
        if self.cc == NULL:
            raise PyverbsRDMAErrno('Failed to create a completion channel')
        self.context = context
        context.add_ref(self)
        self.logger.debug('Created a Completion Channel')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing completion channel')
        if self.cc != NULL:
            rc = v.ibv_destroy_comp_channel(self.cc)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to destroy a completion channel')
            self.cc = NULL

    def get_cq_event(self, CQ expected_cq):
        """
        Waits for the next completion event in the completion event channel
        :param expected_cq: The CQ that got the event
        :return: None
        """
        cdef v.ibv_cq *cq
        cdef void *ctx

        rc = v.ibv_get_cq_event(self.cc, &cq, &ctx)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to get CQ event')
        if cq != expected_cq.cq:
            raise PyverbsRDMAErrno('Received event on an unexpected CQ')


cdef class CQ(PyverbsCM):
    """
    A Completion Queue is the notification mechanism for work request
    completions. A CQ can have 0 or more associated QPs.
    """
    def __cinit__(self, Context context not None, cqe, cq_context,
                  CompChannel channel, comp_vector):
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
        self.cq = v.ibv_create_cq(context.context, cqe, <void*>cq_context,
                                  NULL, comp_vector)
        if self.cq == NULL:
            raise PyverbsRDMAErrno('Failed to create a CQ')
        self.context = context
        context.add_ref(self)
        self.logger.debug('Created a CQ')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing CQ')
        if self.cq != NULL:
            rc = v.ibv_destroy_cq(self.cq)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to close CQ')
            self.cq = NULL
            self.context = None

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

    @property
    def _cq(self):
        return <object>self.cq

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return 'CQ\n' +\
               print_format.format('Handle', self.cq.handle) +\
               print_format.format('CQEs', self.cq.cqe)


cdef class WC(PyverbsObject):
    def __cinit__(self, wr_id=0, status=0, opcode=0, vendor_err=0, byte_len=0,
                  qp_num=0, src_qp=0, imm_data=0, wc_flags=0, pkey_index=0,
                  slid=0, sl=0, dlid_path_bits=0):
        self.wr_id = wr_id
        self.status = status
        self.opcode = opcode
        self.vendor_err = vendor_err
        self.byte_len = byte_len
        self.qp_num = qp_num
        self.src_qp = src_qp
        self.wc_flags = wc_flags
        self.pkey_index = pkey_index
        self.slid = slid
        self.sl = sl
        self.dlid_path_bits = dlid_path_bits

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
            print_format.format('dlid path bits', self.dlid_path_bits)


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

def cqe_flags_to_str(flags):
    cqe_flags = {1: "GRH", 2: "With immediate", 4: "IP csum OK",
                 8: "With invalidate", 16: "TM sync request", 32: "TM match",
                 64: "TM data valid"}
    flags_str = ""
    for f in cqe_flags:
        if flags & f:
            flags_str += cqe_flags[f]
            flags_str += " "
    return flags_str
