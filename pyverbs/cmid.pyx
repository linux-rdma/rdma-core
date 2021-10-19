from libc.stdint cimport uintptr_t, uint8_t
from libc.string cimport memset
import weakref

from pyverbs.pyverbs_error import PyverbsUserError, PyverbsError
from pyverbs.qp cimport QPInitAttr, QPAttr, ECE
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
cimport pyverbs.libibverbs_enums as e
cimport pyverbs.librdmacm_enums as ce
from pyverbs.addr cimport AH, AHAttr
from pyverbs.device cimport Context
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

    @property
    def qpn(self):
        return self.conn_param.qp_num
    @qpn.setter
    def qpn(self, val):
        self.conn_param.qp_num = val

    @property
    def private_data(self):
        return <object>self.conn_param.private_data

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


cdef class JoinMCAttrEx(PyverbsObject):

    def __init__(self, AddrInfo addr not None, comp_mask=0, join_flags=0):
        """
        Initialize a JoinMCAttrEx object over an underlying
        rdma_cm_join_mc_attr_ex C object which contains the extended join
        multicast attributes.
        :param addr: Multicast address identifying the group to join.
        :param comp_mask: Bitwise OR between "rdma_cm_join_mc_attr_mask" enum.
        :param join_flags: Single flag from "rdma_cm_mc_join_flags" enum.
                           Indicates the type of the join requests.
        """
        super().__init__()
        self.join_mc_attr_ex.addr = addr.addr_info.ai_src_addr
        self.join_mc_attr_ex.comp_mask = comp_mask
        self.join_mc_attr_ex.join_flags = join_flags

    @property
    def join_flags(self):
        return self.join_mc_attr_ex.join_flags
    @join_flags.setter
    def join_flags(self, val):
        self.join_mc_attr_ex.join_flags = val

    @property
    def comp_mask(self):
        return self.join_mc_attr_ex.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.join_mc_attr_ex.comp_mask = val


cdef class UDParam(PyverbsObject):

    def __init__(self, CMEvent cm_event not None):
        """
        Initialize a UDParam object over an underlying rdma_ud_param
        C object which contains UD connection parameters.
        :param cm_event: The creator of UDParam. When the active side gets
                         connection establishment event, the event contains
                         UDParam for the passive CMID details.
        :return: UDParam object
        """
        super().__init__()
        memset(&self.ud_param, 0, sizeof(cm.rdma_ud_param))
        self.ud_param = (<CMEvent>cm_event).event.param.ud

    @property
    def qp_num(self):
        return self.ud_param.qp_num

    @property
    def qkey(self):
        return self.ud_param.qkey

    @property
    def ah_attr(self):
        ah_attr = AHAttr()
        ah_attr.init_from_ud_param(self)
        return ah_attr


cdef class AddrInfo(PyverbsObject):

    def __init__(self, src=None, dst=None, src_service=None, dst_service=None,
                 port_space=0, flags=0):
        """
        Initialize an AddrInfo object over an underlying rdma_addrinfo C object.
        :param src: Name, dotted-decimal IPv4 or IPv6 hex address to bind to.
        :param dst: Name, dotted-decimal IPv4 or IPv6 hex address to connect to.
        :param src_service: The service name or port number of the source
                            address.
        :param dst_service: The service name or port number of the destination
                            address.
        :param port_space: RDMA port space used (RDMA_PS_UDP or RDMA_PS_TCP).
        :param flags: Hint flags which control the operation.
        :return: An AddrInfo object which contains information needed to
        establish communication.
        """
        cdef char* src_srvc = NULL
        cdef char* dst_srvc = NULL
        cdef char* src_addr = NULL
        cdef char* dst_addr = NULL
        cdef cm.rdma_addrinfo hints
        cdef cm.rdma_addrinfo *hints_ptr = NULL
        cdef cm.rdma_addrinfo *res = NULL

        super().__init__()
        if src is not None:
            if isinstance(src, str):
                src = src.encode('utf-8')
            src_addr = <char*>src
        if dst is not None:
            if isinstance(dst, str):
                dst = dst.encode('utf-8')
            dst_addr = <char*>dst
        if src_service is not None:
            if isinstance(src_service, str):
                src_service = src_service.encode('utf-8')
            src_srvc = <char*>src_service
        if dst_service is not None:
            if isinstance(dst_service, str):
                dst_service = dst_service.encode('utf-8')
            dst_srvc = <char*>dst_service

        hints_ptr = &hints
        memset(hints_ptr, 0, sizeof(cm.rdma_addrinfo))
        hints.ai_port_space = port_space
        hints.ai_flags = flags
        if flags & ce.RAI_PASSIVE:
            ret = cm.rdma_getaddrinfo(src_addr, src_srvc, hints_ptr,
                                      &self.addr_info)
        else:
            if src:
                hints.ai_flags |= ce.RAI_PASSIVE
                ret = cm.rdma_getaddrinfo(src_addr, src_srvc, hints_ptr, &res)
                if ret != 0:
                    raise PyverbsRDMAErrno('Failed to get Address Info')
                hints.ai_src_addr = <cm.sockaddr*>res.ai_src_addr
                hints.ai_src_len = res.ai_src_len
                hints.ai_flags &= ~ce.RAI_PASSIVE
            ret = cm.rdma_getaddrinfo(dst_addr, dst_srvc, hints_ptr,
                                      &self.addr_info)
            if src:
                cm.rdma_freeaddrinfo(res)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to get Address Info')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.addr_info != NULL:
            self.logger.debug('Closing AddrInfo')
            cm.rdma_freeaddrinfo(self.addr_info)
        self.addr_info = NULL


cdef class CMEvent(PyverbsObject):

    def __init__(self, CMEventChannel channel):
        """
        Initialize a CMEvent object over an underlying rdma_cm_event C object
        :param channel: Event Channel on which this event has been received
        :return: CMEvent object
        """
        super().__init__()
        ret = cm.rdma_get_cm_event(channel.event_channel, &self.event)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to create CMEvent')
        self.logger.debug('Created a CMEvent')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.event != NULL:
            self.logger.debug('Closing CMEvent')
            self.ack_cm_event()
            self.event = NULL

    @property
    def event_type(self):
        return self.event.event

    def ack_cm_event(self):
        """
        Free a communication event. This call frees the event structure and any
        memory that it references.
        :return: None
        """
        ret = cm.rdma_ack_cm_event(self.event)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Acknowledge Event - {}'
                                   .format(self.event_str()))
        self.event = NULL

    def event_str(self):
        if self.event == NULL:
            return ''
        return (<bytes>cm.rdma_event_str(self.event_type)).decode()

    @property
    def private_data(self):
        return <object>self.event.param.conn.private_data


cdef class CMEventChannel(PyverbsObject):

    def __init__(self):
        """
        Initialize a CMEventChannel object over an underlying rdma_event_channel
        C object.
        :return: EventChannel object
        """
        super().__init__()
        self.event_channel = cm.rdma_create_event_channel()
        if self.event_channel == NULL:
            raise PyverbsRDMAErrno('Failed to create CMEventChannel')
        self.logger.debug('Created a CMEventChannel')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.event_channel != NULL:
            self.logger.debug('Closing CMEventChannel')
            cm.rdma_destroy_event_channel(self.event_channel)
            self.event_channel = NULL


cdef class CMID(PyverbsCM):

    def __init__(self, object creator=None, QPInitAttr qp_init_attr=None,
                 PD pd=None, port_space=ce.RDMA_PS_TCP, CMID listen_id=None):
        """
        Initialize a CMID object over an underlying rdma_cm_id C object.
        This is the main RDMA CM object which provides most of the rdmacm API.
        Currently only synchronous RDMA_PS_TCP communication supported.
        Notes: User-specific context, currently not supported.
        :param creator: For synchronous communication we need AddrInfo object in
                        order to establish connection. We allow creator to be
                        None for inner usage, see get_request method.
        :param qp_init_attr: Optional initial QP attributes of CMID
                             associated QP.
        :param pd: Optional parameter, a PD to be associated with this CMID.
        :param port_space: RDMA port space.
        :param listen_id: When passive side establishes a connection, it creates
                          a new CMID. listen_id is used to initialize the new
                          CMID.
        :return: CMID object for synchronous communication.
        """
        cdef v.ibv_qp_init_attr *init
        cdef v.ibv_pd *in_pd = NULL

        super().__init__()
        self.pd = None
        self.ctx = None
        self.event_channel = None
        self.mrs = weakref.WeakSet()
        if creator is None:
            return
        elif isinstance(creator, AddrInfo):
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
        elif isinstance(creator, CMEventChannel):
             self.event_channel = <CMEventChannel>creator
             ret = cm.rdma_create_id((<CMEventChannel>creator).event_channel,
                                     &self.id, NULL, port_space)
             if ret != 0:
                raise PyverbsRDMAErrno('Failed to create CM ID')
        elif isinstance(creator, CMEvent):
            if listen_id is None:
                raise PyverbsUserError('listen ID not provided')
            self.id = (<CMEvent>creator).event.id
            self.event_channel = listen_id.event_channel
            self.ctx = listen_id.ctx
            self.pd = listen_id.pd
        else:
            raise PyverbsRDMAErrno('Cannot create CM ID from {obj}'
                                    .format(obj=type(creator)))

    cdef add_ref(self, obj):
        if isinstance(obj, MR):
            self.mrs.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    @property
    def event_channel(self):
        return self.event_channel

    @property
    def context(self):
        return self.ctx

    @property
    def pd(self):
        return self.pd

    @property
    def qpn(self):
        if self.id.qp:
            return self.id.qp.qp_num
        return None

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.id != NULL:
            self.logger.debug('Closing CMID')
            if self.event_channel is None:
                cm.rdma_destroy_ep(self.id)
            else:
                if self.id.qp != NULL:
                    cm.rdma_destroy_qp(self.id)
                ret = cm.rdma_destroy_id(self.id)
                if ret != 0:
                    raise PyverbsRDMAErrno('Failed to close CMID')
            if self.ctx:
                (<Context>self.ctx).context = NULL
            if self.pd:
                (<PD>self.pd).pd = NULL
            close_weakrefs([self.mrs])
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

    def bind_addr(self, AddrInfo lai not None):
        """
        Associate a source address with a CMID. If binding to a specific local
        address, the CMID will also be bound to a local RDMA device.
        :param lai: Local address information
        :return: None
        """
        ret = cm.rdma_bind_addr(self.id, lai.addr_info.ai_src_addr)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Bind ID')
        # After bind address, cm_id contains ibv_context.
        # Now we can create Context object.
        if self.ctx is None:
            self.ctx = Context(cmid=self)
        if self.pd is None:
            self.pd = PD(self)

    def resolve_addr(self, AddrInfo rai not None, timeout_ms=2000):
        """
        Resolve destination and optional source addresses from IP addresses to
        an RDMA address. If successful, the specified rdma_cm_id will be bound
        to a local device.
        :param rai: Remote address information.
        :param timeout_ms: Time to wait for resolution to complete [msec]
        :return: None
        """
        ret = cm.rdma_resolve_addr(self.id, rai.addr_info.ai_src_addr,
                                   rai.addr_info.ai_dst_addr, timeout_ms)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Resolve Address')

    def join_multicast(self, AddrInfo addr=None, JoinMCAttrEx mc_attr=None,
                       context=0):
        """
        Joins a multicast group and attaches an associated QP to the group.
        :param addr: Multicast address identifying the group to join.
        :param mc_attr: JoinMCAttrEx object is requierd to use
                        rdma_join_multicast_ex. This object contains the join
                        flags and the AddrInfo to join.
        :param context: User-defined context associated with the join request.
        :return: None
        """
        cdef cm.rdma_cm_join_mc_attr_ex  *mc_join_attr = NULL
        if not addr and not mc_attr:
            raise PyverbsUserError('Join to multicast must have AddrInfo or JoinMCAttrEx arguments')
        if not mc_attr:
            ret = cm.rdma_join_multicast(self.id, addr.addr_info.ai_src_addr,
                                         <void*><uintptr_t>context)
        else:
            ret = cm.rdma_join_multicast_ex(self.id, &mc_attr.join_mc_attr_ex,
                                            <void*><uintptr_t>context)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Join multicast')

    def leave_multicast(self, AddrInfo addr not None):
        """
        Leaves a multicast group and detaches an associated QP from the group.
        :param addr: AddrInfo object, represent the multicast address that
                     identifies the group to leave.
        :return: None
        """
        ret = cm.rdma_leave_multicast(self.id, addr.addr_info.ai_src_addr)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to leave multicast')

    def resolve_route(self, timeout_ms=2000):
        """
        Resolve an RDMA route to the destination address in order to establish
        a connection. The destination must already have been resolved by calling
        resolve_addr. Thus this function is called on the client side after
        resolve_addr but before calling connect.
        :param timeout_ms: Time to wait for resolution to complete
        :return: None
        """
        ret = cm.rdma_resolve_route(self.id, timeout_ms)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Resolve Route')
        # After resolve route, cm_id contains ibv_context.
        # Now we can create Context object.
        if self.ctx is None:
            self.ctx = Context(cmid=self)
        if self.pd is None:
            self.pd = PD(self)

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

    def establish(self):
        """
        Complete an active connection request.
        If a QP has not been created on the CMID, this method should be
        called by the active side to complete the connection, after getting
        connect response event. This will trigger a connection established
        event on the passive side.
        This method should not be used on a CMID on which a QP has been
        created.
        """
        ret = cm.rdma_establish(self.id)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Complete an active connection request')

    def set_local_ece(self, ECE ece):
        """
        Set local ECE paraemters to be used for REQ/REP communication.
        :param ece: ECE object with the requested configuration
        :return: None
        """
        rc = cm.rdma_set_local_ece(self.id, &ece.ece)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to set local ECE')

    def get_remote_ece(self):
        """
        Get ECE parameters as were received from the communication peer.
        :return: ECE object with the ece configuration
        """
        ece = ECE()
        rc = cm.rdma_get_remote_ece(self.id, &ece.ece)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to get remote ECE')
        return ece

    def create_qp(self, QPInitAttr qp_init not None):
        """
        Create a QP, which is associated with CMID.
        If CMID and qp_init don't hold any CQs, new CQs will be created and
        associated with CMID.
        If only qp_init provides CQs, they will not be associated with CMID.
        If both provide CQs they have to be using the same CQs.
        :param qp_init: QP init attributes
        """
        ret = cm.rdma_create_qp(self.id, (<PD>self.pd).pd, &qp_init.attr)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Create QP')

    def query_qp(self, attr_mask):
        """
        Query QP using ibv_query_qp.
        :param attr_mask: Which attributes to query (use <enum name> enum)
        :return: A (QPAttr, QPInitAttr) tuple, containing the relevant QP info
        """
        attr = QPAttr()
        init_attr = QPInitAttr()
        rc = v.ibv_query_qp(self.id.qp, &attr.attr, attr_mask, &init_attr.attr)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to query QP')
        return attr, init_attr

    def init_qp_attr(self, qp_state):
        """
        Initialize a QPAttr object used for state transitions of an external
        QP (a QP which was not created using CMID).
        When connecting external QPs using CMIDs both sides must call this
        method before QP state transition to RTR/RTS in order to obtain
        relevant QP attributes from CMID.
        :param qp_state: The QP's destination state
        :return: A (QPAttr, attr_mask) tuple, where attr_mask defines which
                 attributes of QPAttr are valid
        """
        cdef int attr_mask
        qp_attr = QPAttr()
        qp_attr.qp_state = qp_state

        rc = cm.rdma_init_qp_attr(self.id, &qp_attr.attr, &attr_mask)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to get QP attributes')
        return qp_attr, attr_mask

    def reg_msgs(self, size):
        """
        Registers a memory region for sending or receiving messages or for
        RDMA operations. The registered memory may then be posted to an CMID
        using post_send or post_recv methods.
        :param size: The total length of the memory to register
        :return: registered MR
        """
        return MR(self, size, e.IBV_ACCESS_LOCAL_WRITE)

    def reg_read(self, size=0):
        """
        Registers a memory region for sending or receiving messages or for
        remote read operations.
        :param size: The total length of the memory to register
        :return: registered MR
        """
        return MR(self, size, e.IBV_ACCESS_REMOTE_READ)

    def reg_write(self, size=0):
        """
        Registers a memory region for sending or receiving messages or for
        remote write operations.
        :param size: The total length of the memory to register
        :return: registered MR
        """
        return MR(self, size, e.IBV_ACCESS_REMOTE_WRITE)

    def post_recv(self, MR mr not None, length=None):
        """
        Posts a recv_wr via QP associated with CMID.
        Context param of rdma_post_recv C function currently not supported.
        :param mr: A valid MR object.
        :param length: length of buffer to recv (default: mr length).
        :return: None
        """
        if not length:
            length = mr.mr.length
        ret = cm.rdma_post_recv(self.id, NULL, mr.buf, length, mr.mr)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Post Receive')

    def post_send(self, MR mr not None, flags=v.IBV_SEND_SIGNALED, length=None):
        """
        Posts a message via QP associated with CMID.
        Context param of rdma_post_send C function currently not supported.
        :param mr: A valid MR object which contains message to send.
        :param flags: flags for send work request.
        :param length: length of buffer to send (default: mr length).
        :return: None
        """
        if not length:
            length = mr.mr.length
        ret = cm.rdma_post_send(self.id, NULL, mr.buf, length, mr.mr,
                                flags)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Post Send')

    def post_read(self, MR mr not None, length, remote_addr, rkey,
                  flags=0):
        """
        Post read WR using the CMIDs internal QP.
        :param mr: A valid MR object.
        :param length: length of buffer to send.
        :param remote_addr: The remote MR address.
        :param rkey: The remote MR rkey.
        :param flags: flags for send work request.
        :return: None
        """
        ret = cm.rdma_post_read(self.id, NULL, mr.buf, length, mr.mr,
                                flags, remote_addr, rkey)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Post Read')

    def post_write(self, MR mr not None, length, remote_addr, rkey,
                   flags=0):
        """
        Post write WR using the CMIDs internal QP.
        :param mr: A valid MR object.
        :param length: length of buffer to send.
        :param remote_addr: The remote MR address.
        :param rkey: The remote MR rkey.
        :param flags: flags for send work request.
        :return: None
        """
        ret = cm.rdma_post_write(self.id, NULL, mr.buf, length, mr.mr,
                                 flags, remote_addr, rkey)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Post Write')

    def post_ud_send(self, MR mr not None, AH ah not None, rqpn=0,
                     flags=v.IBV_SEND_SIGNALED, length=None):
        """
        Posts a message via UD QP associated with CMID to another UD QP.
        :param mr: A valid MR object which contains message to send.
        :param ah: The destination AH.
        :param rqpn: The remote QP number.
        :param flags: flags for send work request.
        :param length: length of buffer to send.
        :return: None
        """
        if not length:
            length = mr.mr.length
        ret = cm.rdma_post_ud_send(self.id, NULL, mr.buf, length, mr.mr,
                                   flags, ah.ah, rqpn)
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

    def set_option(self, level, optname, optval, optlen):
        """
        Set communication options for a CMID.
        :param level: The protocol level of the option to set.
        :param optname: The name of the option to set.
        :param optval: The option data.
        :param optlen: The size of the data.
        """
        if optname != ce.RDMA_OPTION_ID_ACK_TIMEOUT:
            raise PyverbsUserError('Currently only RDMA_OPTION_ID_ACK_TIMEOUT is supported in Pyverbs.')
        cdef uint8_t value = optval
        ret = cm.rdma_set_option(self.id, level, optname, <void*>&value, optlen)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to set option')

    def reject(self, private_data=None, private_data_len=0):
        """
        Reject a connection or datagram service lookup request.
        :param private_data: Optional private data to send with the reject message.
        :param private_data_len: Size (in bytes) of the private data being sent.
        """
        ret = cm.rdma_reject(self.id, <const void*>private_data, private_data_len)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to Reject Connection')
