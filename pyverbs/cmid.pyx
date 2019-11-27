from pyverbs.pyverbs_error import PyverbsError
from pyverbs.device cimport PortAttr, Context
from pyverbs.qp cimport QPInitAttr, QPAttr
from pyverbs.base import PyverbsRDMAErrno
cimport pyverbs.libibverbs_enums as e
cimport pyverbs.librdmacm_enums as ce
cimport pyverbs.libibverbs as v
cimport pyverbs.librdmacm as cm
from pyverbs.pd cimport PD
from pyverbs.mr cimport MR
from pyverbs.cq cimport WC


cdef class ConnParam(PyverbsObject):

    def __init__(self, resources=1, depth=1, flow_control=0, retry=5,
                 rnr_retry=5, srq=0, qp_num=0):
        """
        Initialize a ConnParam object over an underlying rdma_conn_param
        C object which contains connection parameters. There are a few types of
        port spaces in RDMACM: RDMA_PS_TCP, RDMA_PS_UDP, RDMA_PS_IB and
        RDMA_PS_IPOIB. RDMA_PS_TCP resembles RC QP connection, which provides
        reliable, connection-oriented QP communication. This object applies only
        to RDMA_PS_TCP port space.
        :param resources: Max outstanding RDMA read and atomic ops that local
                          side will accept from the remote side.
        :param depth: Max outstanding RDMA read and atomic ops that local side
                      will have to the remote side.
        :param flow_control: Specifies if hardware flow control is available.
        :param retry: Max number of times that a send, RDMA or atomic op from
                      the remote peer should be retried.
        :param rnr_retry: The maximum number of times that a send operation from
                          the remote peer should be retried on a connection
                          after receiving a receiver not ready (RNR) error.
        :param srq: Specifies if the QP using shared receive queue, ignored if
                    the QP created by CMID.
        :param qp_num: Specifies the QP number, ignored if the QP created by
                       CMID.
        :return: ConnParam object
        """
        super().__init__()
        memset(&self.conn_param, 0, sizeof(cm.rdma_conn_param))
        self.conn_param.responder_resources = resources
        self.conn_param.initiator_depth = depth
        self.conn_param.flow_control = flow_control
        self.conn_param.retry_count = retry
        self.conn_param.rnr_retry_count = rnr_retry
        self.conn_param.srq = srq
        self.conn_param.qp_num = qp_num

    def __str__(self):
        print_format  = '{:<4}: {:<4}\n'
        return '{}: {}\n'.format('Connection parameters', "") +\
               print_format.format('responder resources', self.conn_param.responder_resources) +\
               print_format.format('initiator depth', self.conn_param.initiator_depth) +\
               print_format.format('flow control', self.conn_param.flow_control) +\
               print_format.format('retry count', self.conn_param.retry_count) +\
               print_format.format('rnr retry count', self.conn_param.rnr_retry_count) +\
               print_format.format('srq', self.conn_param.srq) +\
               print_format.format('qp number', self.conn_param.qp_num)


cdef class AddrInfo(PyverbsObject):
    def __init__(self, node=None, service=None, port_space=0, flags=0):
        """
        Initialize an AddrInfo object over an underlying rdma_addrinfo C object.
        :param node: Name, dotted-decimal IPv4 or IPv6 hex address to resolve.
        :param service: The service name or port number of the address.
        :param port_space: RDMA port space used (RDMA_PS_UDP or RDMA_PS_TCP).
        :param flags: Hint flags which control the operation.
        :return: An AddrInfo object which contains information needed to
        establish communication.
        """
        cdef char* srvc = NULL
        cdef char* address = NULL
        cdef cm.rdma_addrinfo hints
        cdef cm.rdma_addrinfo *hints_ptr = NULL

        super().__init__()
        if node is not None:
            node = node.encode('utf-8')
            address = <char*>node
        if service is not None:
            service = service.encode('utf-8')
            srvc = <char*>service
        if port_space != 0:
            hints_ptr = &hints
            memset(hints_ptr, 0, sizeof(cm.rdma_addrinfo))
            hints.ai_port_space = port_space
            hints.ai_flags = flags
        ret = cm.rdma_getaddrinfo(address, srvc, hints_ptr, &self.addr_info)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to get Address Info')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing AddrInfo')
        if self.addr_info != NULL:
            cm.rdma_freeaddrinfo(self.addr_info)
        self.addr_info = NULL


cdef class CMID(PyverbsCM):

    def __init__(self, object creator=None, QPInitAttr qp_init_attr=None,
                 PD pd=None):
        """
        Initialize a CMID object over an underlying rdma_cm_id C object.
        This is the main RDMA CM object which provides most of the rdmacm API.
        Currently only synchronous RDMA_PS_TCP communication supported.
        :param creator: For synchronous communication we need AddrInfo object in
                        order to establish connection. We allow creator to be
                        None for inner usage, see get_request method.
        :param pd: Optional parameter, a PD to be associated with this CMID.
        :param qp_init_attr: Optional initial QP attributes of CMID
                             associated QP.
        :return: CMID object for synchronous communication.
        """
        cdef v.ibv_qp_init_attr *init
        cdef v.ibv_pd *in_pd = NULL

        super().__init__()
        self.pd = None
        self.ctx = None
        if creator is None:
            return
        elif issubclass(type(creator), AddrInfo):
            init = NULL if qp_init_attr is None else &qp_init_attr.attr
            if pd is not None:
                in_pd = pd.pd
                self.pd = pd
            ret = cm.rdma_create_ep(&self.id, (<AddrInfo>creator).addr_info,
                                    in_pd, init)
            if ret != 0:
                raise PyverbsRDMAErrno('Failed to create CM ID')
            if not (<AddrInfo>creator).addr_info.ai_flags & ce.RAI_PASSIVE:
                self.ctx = Context(cmid=self)
                if self.pd is None:
                    self.pd = PD(self)
        else:
            raise PyverbsRDMAErrno('Cannot create CM ID from {obj}'
                                    .format(obj=type(creator)))

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing CMID')
        if self.id != NULL:
            cm.rdma_destroy_ep(self.id)
            if self.ctx:
                (<Context>self.ctx).context = NULL
            if self.pd:
                (<PD>self.pd).pd = NULL
            self.id = NULL

    def get_request(self):
        """
        Retrieves the next pending connection request event. The call may only
        be used on listening CMIDs operating synchronously. If the call is
        successful, a new CMID representing the connection request will be
        returned to the user. The new CMID will reference event information
        associated with the request until the user calls reject, accept, or
        close on the newly created identifier.
        :return: New CMID representing the connection request.
        """
        to_conn = CMID()
        ret = cm.rdma_get_request(self.id, &to_conn.id)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to get request, no connection established')
        self.ctx = Context(cmid=to_conn)
        self.pd = PD(to_conn)
        return to_conn

    def reg_msgs(self, size):
        """
        Registers a memory region for sending or receiving messages or for
        RDMA operations. The registered memory may then be posted to an CMID
        using post_send or post_recv methods.
        :param size: The total length of the memory to register
        :return: registered MR
        """
        return MR(self.pd, size, e.IBV_ACCESS_LOCAL_WRITE)

    def listen(self, backlog=0):
        """
        Listen for incoming connection requests or datagram service lookup.
        The listen is restricted to the locally bound source address.
        :param backlog: The backlog of incoming connection requests
        :return: None
        """
        ret = cm.rdma_listen(self.id, backlog)
        if ret != 0:
            raise PyverbsRDMAErrno('Listen Failed')

    def connect(self, ConnParam param=None):
        """
        Initiates an active connection request to a remote destination.
        :param param: Optional connection parameters
        :return: None
        """
        cdef cm.rdma_conn_param *conn = &param.conn_param if param else NULL
        ret = cm.rdma_connect(self.id, conn)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Connect')

    def disconnect(self):
        """
        Disconnects a connection and transitions any associated QP to error
        state.
        :return: None
        """
        ret = cm.rdma_disconnect(self.id)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Disconnect')

    def accept(self, ConnParam param=None):
        """
        Is called from the listening side to accept a connection or datagram
        service lookup request.
        :param param: Optional connection parameters
        :return: None
        """
        cdef cm.rdma_conn_param *conn = &param.conn_param if param else NULL
        ret = cm.rdma_accept(self.id, conn)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Accept Connection')

    def post_recv(self, MR mr not None):
        """
        Posts a recv_wr via QP associated with CMID.
        Context param of rdma_post_recv C function currently not supported.
        :param mr: A valid MR object.
        :return: None
        """
        ret = cm.rdma_post_recv(self.id, NULL, mr.buf, mr.mr.length, mr.mr)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Post Receive')

    def post_send(self, MR mr not None, flags=v.IBV_SEND_SIGNALED):
        """
        Posts a message via QP associated with CMID.
        Context param of rdma_post_send C function currently not supported.
        :param mr: A valid MR object which contains message to send.
        :param flags: flags for send work request.
        :return: None
        """
        ret = cm.rdma_post_send(self.id, NULL, mr.buf, mr.mr.length, mr.mr,
                                flags)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Post Send')

    def get_recv_comp(self):
        """
        Polls the receive CQ associated with CMID for a work completion.
        :return: The retrieved WC or None if there is no completions
        """
        cdef v.ibv_wc wc
        ret = cm.rdma_get_recv_comp(self.id, &wc)
        if ret < 0:
            raise PyverbsRDMAErrno('Failed to retrieve receive completion')
        elif ret == 0:
            return None
        return WC(wr_id=wc.wr_id, status=wc.status, opcode=wc.opcode,
                  vendor_err=wc.vendor_err, byte_len=wc.byte_len,
                  qp_num=wc.qp_num, src_qp=wc.src_qp,
                  imm_data=wc.imm_data, wc_flags=wc.wc_flags,
                  pkey_index=wc.pkey_index, slid=wc.slid, sl=wc.sl,
                  dlid_path_bits=wc.dlid_path_bits)

    def get_send_comp(self):
        """
        Polls the send CQ associated with CMID for a work completion.
        :return: The retrieved WC or None if there is no completions
        """
        cdef v.ibv_wc wc
        ret = cm.rdma_get_send_comp(self.id, &wc)
        if ret < 0:
            raise PyverbsRDMAErrno('Failed to retrieve send completion')
        elif ret == 0:
            return None
        return WC(wr_id=wc.wr_id, status=wc.status, opcode=wc.opcode,
                  vendor_err=wc.vendor_err, byte_len=wc.byte_len,
                  qp_num=wc.qp_num, src_qp=wc.src_qp,
                  imm_data=wc.imm_data, wc_flags=wc.wc_flags,
                  pkey_index=wc.pkey_index, slid=wc.slid, sl=wc.sl,
                  dlid_path_bits=wc.dlid_path_bits)
