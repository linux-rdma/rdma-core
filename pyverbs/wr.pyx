# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies Inc. All rights reserved. See COPYING file

from pyverbs.pyverbs_error import PyverbsUserError, PyverbsError
from pyverbs.base import PyverbsRDMAErrno
cimport pyverbs.libibverbs_enums as e
from pyverbs.addr cimport AH
from libc.stdlib cimport free, malloc
from libc.string cimport memcpy


cdef class SGE(PyverbsCM):
    """
    Represents ibv_sge struct. It has a read function to allow users to keep
    track of data. Write function is not provided as a scatter-gather element
    can be using a MR or a DMMR. In case direct (device's) memory is used,
    write can't be done using memcpy that relies on CPU-specific optimizations.
    A SGE has no way to tell which memory it is using.
    """
    def __init__(self, addr, length, lkey):
        """
        Initializes a SGE object.
        :param addr: The address to be used for read/write
        :param length: Available buffer size
        :param lkey: Local key of the used MR/DMMR
        :return: A SGE object
        """
        super().__init__()
        self.sge = <v.ibv_sge*>malloc(sizeof(v.ibv_sge))
        if self.sge == NULL:
            raise PyverbsError('Failed to allocate an SGE')
        self.sge.addr = addr
        self.sge.length = length
        self.sge.lkey = lkey

    def __dealloc(self):
        self.close()

    cpdef close(self):
        free(self.sge)

    cpdef read(self, length, offset):
        """
        Reads <length> bytes of data starting at <offset> bytes from the
        SGE's address.
        :param length: How many bytes to read
        :param offset: Offset from the SGE's address in bytes
        :return: The data written at the SGE's address + offset
        """
        cdef char *sg_data
        cdef int off = offset
        sg_data = <char*>(self.sge.addr + off)
        return sg_data[:length]

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return print_format.format('Address', hex(self.sge.addr)) +\
               print_format.format('Length', self.sge.length) +\
               print_format.format('Key', hex(self.sge.lkey))

    @property
    def addr(self):
        return self.sge.addr
    @addr.setter
    def addr(self, val):
        self.sge.addr = val

    @property
    def length(self):
        return self.sge.length
    @length.setter
    def length(self, val):
        self.sge.length = val

    @property
    def lkey(self):
        return self.sge.lkey
    @lkey.setter
    def lkey(self, val):
        self.sge.lkey = val


cdef class RecvWR(PyverbsCM):
    def __init__(self, wr_id=0, num_sge=0, sg=None,
                 RecvWR next_wr=None):
        """
        Initializes a RecvWR object.
        :param wr_id: A user-defined WR ID
        :param num_sge: Size of the scatter-gather array
        :param sg: A scatter-gather array
        :param: next_wr: The next WR in the list
        :return: A RecvWR object
        """
        super().__init__()
        cdef v.ibv_sge *dst
        if num_sge < 1 or sg is None:
            raise PyverbsUserError('A WR needs at least one SGE')
        self.recv_wr.sg_list = <v.ibv_sge*>malloc(num_sge * sizeof(v.ibv_sge))
        if self.recv_wr.sg_list == NULL:
            raise PyverbsRDMAErrno('Failed to malloc SG buffer')
        dst = self.recv_wr.sg_list
        copy_sg_array(dst, sg, num_sge)
        self.recv_wr.num_sge = num_sge
        self.recv_wr.wr_id = wr_id
        if next_wr is not None:
            self.recv_wr.next = &next_wr.recv_wr

    def __dealloc(self):
        self.close()

    cpdef close(self):
        free(self.recv_wr.sg_list)

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return print_format.format('WR ID', self.recv_wr.wr_id) +\
               print_format.format('Num SGE', self.recv_wr.num_sge)

    @property
    def next_wr(self):
        if self.recv_wr.next == NULL:
            return None
        val = RecvWR()
        val.recv_wr = self.recv_wr.next[0]
        return val
    @next_wr.setter
    def next_wr(self, RecvWR val not None):
        self.recv_wr.next = &val.recv_wr

    @property
    def wr_id(self):
        return self.recv_wr.wr_id
    @wr_id.setter
    def wr_id(self, val):
        self.recv_wr.wr_id = val

    @property
    def num_sge(self):
        return self.recv_wr.num_sge
    @num_sge.setter
    def num_sge(self, val):
        self.recv_wr.num_sge = val


cdef class SendWR(PyverbsCM):
    def __init__(self, wr_id=0, opcode=e.IBV_WR_SEND, num_sge=0, sg = None,
                 send_flags=e.IBV_SEND_SIGNALED, SendWR next_wr = None):
        """
        Initialize a SendWR object with user-provided or default values.
        :param wr_id: A user-defined WR ID
        :param opcode: The WR's opcode
        :param num_sge: Number of scatter-gather elements in the WR
        :param send_flags: Send flags as define in ibv_send_flags enum
        :param sg: A SGE element, head of the scatter-gather list
        :return: An initialized SendWR object
        """
        cdef v.ibv_sge *dst

        super().__init__()
        if num_sge < 1 or sg is None:
            raise PyverbsUserError('A WR needs at least one SGE')
        self.send_wr.sg_list = <v.ibv_sge*>malloc(num_sge * sizeof(v.ibv_sge))
        if self.send_wr.sg_list == NULL:
            raise PyverbsRDMAErrno('Failed to malloc SG buffer')
        dst = self.send_wr.sg_list
        copy_sg_array(dst, sg, num_sge)
        self.send_wr.num_sge = num_sge
        self.send_wr.wr_id = wr_id
        if next_wr is not None:
            self.send_wr.next = &next_wr.send_wr
        self.send_wr.opcode = opcode
        self.send_wr.send_flags = send_flags

    def __dealloc(self):
        self.close()

    cpdef close(self):
        free(self.send_wr.sg_list)

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return print_format.format('WR ID', self.send_wr.wr_id) +\
               print_format.format('Num SGE', self.send_wr.num_sge) +\
               print_format.format('Opcode', self.send_wr.opcode) +\
               print_format.format('Send flags',
                                   send_flags_to_str(self.send_wr.send_flags))

    @property
    def next_wr(self):
        if self.send_wr.next == NULL:
            return None
        val = SendWR()
        val.send_wr = self.send_wr.next[0]
        return val
    @next_wr.setter
    def next_wr(self, SendWR val not None):
        self.send_wr.next = &val.send_wr

    @property
    def wr_id(self):
        return self.send_wr.wr_id
    @wr_id.setter
    def wr_id(self, val):
        self.send_wr.wr_id = val

    @property
    def num_sge(self):
        return self.send_wr.num_sge
    @num_sge.setter
    def num_sge(self, val):
        self.send_wr.num_sge = val

    @property
    def opcode(self):
        return self.send_wr.opcode
    @opcode.setter
    def opcode(self, val):
        self.send_wr.opcode = val

    @property
    def send_flags(self):
        return self.send_wr.send_flags
    @send_flags.setter
    def send_flags(self, val):
        self.send_wr.send_flags = val

    property sg_list:
        def __set__(self, SGE val not None):
            self.send_wr.sg_list = val.sge

    def set_wr_ud(self, AH ah not None, rqpn, rqkey):
        """
        Set the members of the ud struct in the send_wr's wr union.
        :param ah: An address handle object
        :param rqpn: The remote QP number
        :param rqkey: The remote QKey, authorizing access to the destination QP
        :return: None
        """
        self.send_wr.wr.ud.ah = ah.ah
        self.send_wr.wr.ud.remote_qpn = rqpn
        self.send_wr.wr.ud.remote_qkey = rqkey

    def set_wr_rdma(self, rkey, addr):
        """
        Set the members of the rdma struct in the send_wr's wr union, used for
        RDMA extended transport header creation.
        :param rkey: Key to access the specified memory address.
        :param addr: Start address of the buffer
        :return: None
        """
        self.send_wr.wr.rdma.remote_addr = addr
        self.send_wr.wr.rdma.rkey = rkey

    def set_wr_atomic(self, rkey, addr, compare_add, swap=0):
        """
        Set the members of the atomic struct in the send_wr's wr union, used
        for the atomic extended transport header.
        :param rkey: Key to access the specified memory address.
        :param addr: Start address of the buffer
        :param compare_add: The data operand used in the compare portion of the
                            compare and swap operation
        :param swap: The data operand used in atomic operations:
                     - In compare and swap this field is swapped into the
                       addressed buffer
                     - In fetch and add this field is added to the contents of
                       the addressed buffer
        :return: None
        """
        self.send_wr.wr.atomic.remote_addr = addr
        self.send_wr.wr.atomic.rkey = rkey
        self.send_wr.wr.atomic.compare_add = compare_add
        self.send_wr.wr.atomic.swap = swap

    def set_qp_type_xrc(self, remote_srqn):
        """
        Set the members of the xrc struct in the send_wr's qp_type union, used
        for the XRC extended transport header.
        :param remote_srqn: The XRC SRQ number to be used by the responder fot
                            this packet
        :return: None
        """
        self.send_wr.qp_type.xrc.remote_srqn = remote_srqn

def send_flags_to_str(flags):
    send_flags = {e.IBV_SEND_FENCE: 'IBV_SEND_FENCE',
                  e.IBV_SEND_SIGNALED: 'IBV_SEND_SIGNALED',
                  e.IBV_SEND_SOLICITED: 'IBV_SEND_SOLICITED',
                  e.IBV_SEND_INLINE: 'IBV_SEND_INLINE',
                  e.IBV_SEND_IP_CSUM: 'IBV_SEND_IP_CSUM'}
    flags_str = ''
    for f in send_flags:
        if flags & f:
            flags_str += send_flags[f]
            flags_str += ' '
    return flags_str


cdef copy_sg_array(v.ibv_sge *dst, sg, num_sge):
    cdef v.ibv_sge *src
    for i in range(num_sge):
        src = (<SGE>sg[i]).sge
        memcpy(dst, src, sizeof(v.ibv_sge))
        dst += 1
