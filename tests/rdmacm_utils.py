# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file
"""
Provide some useful helper function for pyverbs rdmacm' tests.
"""
import sys
from tests.utils import validate, poll_cq, get_send_elements, get_recv_wr
from tests.base_rdmacm import AsyncCMResources, SyncCMResources
from pyverbs.cmid import CMEvent, AddrInfo, JoinMCAttrEx
from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
import pyverbs.cm_enums as ce
from pyverbs.addr import AH
import pyverbs.enums as e
import abc
import errno

GRH_SIZE = 40
MULTICAST_QPN = 0xffffff
REJECT_MSG = 'connection rejected'


class CMConnection(abc.ABC):
    """
    RDMA CM base abstract connection class. The class contains the rdmacm
    resources and other methods to easily establish a connection and run
    traffic using the rdmacm resources. Each type of connection or traffic
    should inherit from this class and implement the necessary methods such as
    connection establishment and traffic.
    """
    def __init__(self, syncer=None, notifier=None):
        """
        Initializes a connection object.
        :param syncer: Barrier object to sync between all the test processes.
        :param notifier: Queue object to pass objects between the connection
                         sides.
        """
        self.syncer = syncer
        self.notifier = notifier
        self.cm_res = None

    def rdmacm_traffic(self, server=None, multicast=False):
        """
        Run rdmacm traffic. This method runs the compatible traffic flow
        depending on the CMResources. If self.with_ext_qp is set the traffic
        will go through the external QP.
        :param server: Run as server.
        :param multicast: Run multicast traffic.
        """
        server = server if server is not None else self.cm_res.passive
        if self.cm_res.with_ext_qp:
            if server:
                self._ext_qp_server_traffic()
            else:
                self._ext_qp_client_traffic()
        else:
            if server:
                self._cmid_server_traffic(multicast)
            else:
                self._cmid_client_traffic(multicast)

    def remote_traffic(self, passive, remote_op='write'):
        """
        Run rdmacm remote traffic. This method runs RDMA remote traffic from
        the active to the passive.
        :param passive: If True, run as server.
        :param remote_op: 'write'/'read', The type of the RDMA remote operation.
        """
        msg_size = self.cm_res.msg_size
        if passive:
            self.cm_res.mr.write((msg_size) * 's', msg_size)
            mr_details = (self.cm_res.mr.rkey, self.cm_res.mr.buf)
            self.notifier.put(mr_details)
            self.syncer.wait()
            self.syncer.wait()
            if remote_op == 'write':
                msg_received = self.cm_res.mr.read(msg_size, 0)
                validate(msg_received, True, msg_size)
        else:
            self.cm_res.mr.write((msg_size) * 'c', msg_size)
            self.syncer.wait()
            rkey, remote_addr = self.notifier.get()
            cmid = self.cm_res.cmid
            post_func = cmid.post_write if remote_op == 'write' else \
                cmid.post_read
            for _ in range(self.cm_res.num_msgs):
                post_func(self.cm_res.mr, msg_size, remote_addr, rkey,
                          flags=e.IBV_SEND_SIGNALED)
                cmid.get_send_comp()
            self.syncer.wait()
            if remote_op == 'read':
                msg_received = self.cm_res.mr.read(msg_size, 0)
                validate(msg_received, False, msg_size)

    def _ext_qp_server_traffic(self):
        """
        RDMACM server side traffic function which sends and receives a message,
        and then validates the received message. This traffic method uses the CM
        external QP and CQ for send, recv and get_completion.
        :return: None
        """
        recv_wr = get_recv_wr(self.cm_res)
        self.cm_res.qp.post_recv(recv_wr)
        self.syncer.wait()
        for _ in range(self.cm_res.num_msgs):
            poll_cq(self.cm_res.cq)
            self.cm_res.qp.post_recv(recv_wr)
            msg_received = self.cm_res.mr.read(self.cm_res.msg_size, 0)
            validate(msg_received, self.cm_res.passive, self.cm_res.msg_size)
            send_wr = get_send_elements(self.cm_res, self.cm_res.passive)[0]
            self.cm_res.qp.post_send(send_wr)
            poll_cq(self.cm_res.cq)

    def _ext_qp_client_traffic(self):
        """
        RDMACM client side traffic function which sends and receives a message,
        and then validates the received message. This traffic method uses the CM
        external QP and CQ for send, recv and get_completion.
        :return: None
        """
        recv_wr = get_recv_wr(self.cm_res)
        self.syncer.wait()
        for _ in range(self.cm_res.num_msgs):
            send_wr = get_send_elements(self.cm_res, self.cm_res.passive)[0]
            self.cm_res.qp.post_send(send_wr)
            poll_cq(self.cm_res.cq)
            self.cm_res.qp.post_recv(recv_wr)
            poll_cq(self.cm_res.cq)
            msg_received = self.cm_res.mr.read(self.cm_res.msg_size, 0)
            validate(msg_received, self.cm_res.passive, self.cm_res.msg_size)

    def _cmid_server_traffic(self, multicast=False):
        """
        RDMACM server side traffic function which sends and receives a message,
        and then validates the received message. This traffic method uses the
        RDMACM API for send, recv and get_completion.
        :return: None
        """
        grh_offset = GRH_SIZE if self.cm_res.qp_type == e.IBV_QPT_UD else 0
        send_msg = (self.cm_res.msg_size + grh_offset) * 's'
        cmid = self.cm_res.child_id if not multicast else self.cm_res.cmid
        for _ in range(self.cm_res.num_msgs):
            cmid.post_recv(self.cm_res.mr)
            self.syncer.wait()
            self.syncer.wait()
            wc = cmid.get_recv_comp()
            msg_received = self.cm_res.mr.read(self.cm_res.msg_size, grh_offset)
            validate(msg_received, True, self.cm_res.msg_size)
            if self.cm_res.port_space == ce.RDMA_PS_TCP:
                self.cm_res.mr.write(send_msg, self.cm_res.msg_size)
                cmid.post_send(self.cm_res.mr)
            else:
                if multicast:
                    ah = AH(cmid.pd, attr=self.cm_res.ud_params.ah_attr)
                    rqpn = MULTICAST_QPN
                else:
                    ah = AH(cmid.pd, wc=wc, port_num=1, grh=self.cm_res.mr.buf)
                    rqpn = self.cm_res.remote_qpn
                self.cm_res.mr.write(send_msg, self.cm_res.msg_size + GRH_SIZE)
                cmid.post_ud_send(self.cm_res.mr, ah, rqpn=rqpn,
                                  length=self.cm_res.msg_size)
            cmid.get_send_comp()
            self.syncer.wait()

    def _cmid_client_traffic(self, multicast=False):
        """
        RDMACM client side traffic function which sends and receives a message,
        and then validates the received message. This traffic method uses the
        RDMACM API for send, recv and get_completion.
        :return: None
        """
        grh_offset = GRH_SIZE if self.cm_res.qp_type == e.IBV_QPT_UD else 0
        send_msg = (self.cm_res.msg_size + grh_offset) * 'c'
        cmid = self.cm_res.cmid
        for _ in range(self.cm_res.num_msgs):
            self.cm_res.mr.write(send_msg, self.cm_res.msg_size + grh_offset)
            self.syncer.wait()
            if self.cm_res.port_space == ce.RDMA_PS_TCP:
                cmid.post_send(self.cm_res.mr)
            else:
                ah = AH(cmid.pd, attr=self.cm_res.ud_params.ah_attr)
                rqpn = MULTICAST_QPN if multicast else self.cm_res.ud_params.qp_num
                cmid.post_ud_send(self.cm_res.mr, ah, rqpn=rqpn,
                                  length=self.cm_res.msg_size)
            cmid.get_send_comp()
            cmid.post_recv(self.cm_res.mr)
            self.syncer.wait()
            self.syncer.wait()
            cmid.get_recv_comp()
            msg_received = self.cm_res.mr.read(self.cm_res.msg_size, grh_offset)
            validate(msg_received, False, self.cm_res.msg_size)

    def event_handler(self, expected_event=None):
        """
        Handle and execute corresponding API for RDMACM events of asynchronous
        communication.
        :param expected_event: The user expected event.
        :return: None
        """
        cm_event = CMEvent(self.cm_res.cmid.event_channel)
        if cm_event.event_type == ce.RDMA_CM_EVENT_CONNECT_REQUEST:
            self.cm_res.create_child_id(cm_event)
        elif cm_event.event_type in [ce.RDMA_CM_EVENT_ESTABLISHED,
                                     ce.RDMA_CM_EVENT_MULTICAST_JOIN]:
            self.cm_res.set_ud_params(cm_event)
        if expected_event and expected_event != cm_event.event_type:
            raise PyverbsError('Expected this event: {}, got this event: {}'.
                                format(expected_event, cm_event.event_str()))
        if expected_event == ce.RDMA_CM_EVENT_REJECTED:
            assert cm_event.private_data == REJECT_MSG, \
                f'CM event data ({cm_event.private_data}) is different than the expected ({REJECT_MSG})'
        cm_event.ack_cm_event()

    @abc.abstractmethod
    def establish_connection(self):
        pass

    @abc.abstractmethod
    def disconnect(self):
        pass


class CMAsyncConnection(CMConnection):
    """
    Implement RDMACM connection management for asynchronous CMIDs. It includes
    connection establishment, disconnection and other methods such as traffic.
    """
    def __init__(self, ip_addr, syncer=None, notifier=None, passive=False,
                 num_conns=1, qp_timeout=-1, reject_conn=False, **kwargs):
        """
        Init the CMConnection and then init the AsyncCMResources.
        :param ip_addr: IP address to use.
        :param syncer: Barrier object to sync between all the test processes.
        :param notifier: Queue object to pass objects between the connection
                         sides.
        :param passive: Indicate if it's a passive side.
        :param num_conns: Number of connections.
        :param qp_timeout: Value of the QP timeout.
        :param reject_conn: True if the server will reject the connection.
        :param kwargs: Arguments used to initialize the CM resources. For more
                       info please check CMResources.
        """
        super(CMAsyncConnection, self).__init__(syncer=syncer, notifier=notifier)
        self.num_conns = num_conns
        self.create_cm_res(ip_addr, passive=passive, **kwargs)
        self.qp_timeout = qp_timeout
        self.reject_conn = reject_conn

    def create_cm_res(self, ip_addr, passive, **kwargs):
        self.cm_res = AsyncCMResources(addr=ip_addr, passive=passive, **kwargs)
        if passive:
            self.cm_res.create_cmid()
        else:
            for i in range(self.num_conns):
                self.cm_res.create_cmid(i)

    def join_to_multicast(self, mc_addr=None, src_addr=None, extended=False):
        """
        Join the CMID to multicast group.
        :param mc_addr: The multicast IP address.
        :param src_addr: The CMIDs source address.
        :param extended: Use the join_multicast_ex API.
        """
        self.cm_res.cmid.bind_addr(self.cm_res.ai)
        resolve_addr_info = AddrInfo(src=src_addr, dst=mc_addr)
        self.cm_res.cmid.resolve_addr(resolve_addr_info)
        self.event_handler(expected_event=ce.RDMA_CM_EVENT_ADDR_RESOLVED)
        self.cm_res.create_qp()
        mc_addr_info = AddrInfo(src=mc_addr)
        if not extended:
            self.cm_res.cmid.join_multicast(addr=mc_addr_info)
        else:
            flags = ce.RDMA_MC_JOIN_FLAG_FULLMEMBER
            comp_mask = ce.RDMA_CM_JOIN_MC_ATTR_ADDRESS | \
                        ce.RDMA_CM_JOIN_MC_ATTR_JOIN_FLAGS
            mcattr = JoinMCAttrEx(addr=mc_addr_info, comp_mask=comp_mask,
                                  join_flags=flags)
            self.cm_res.cmid.join_multicast(mc_attr=mcattr)
        self.event_handler(expected_event=ce.RDMA_CM_EVENT_MULTICAST_JOIN)
        self.cm_res.create_mr()

    def leave_multicast(self, mc_addr=None):
        """
        Leave multicast group.
        :param mc_addr: The multicast IP address.
        """
        mc_addr_info = AddrInfo(src=mc_addr)
        self.cm_res.cmid.leave_multicast(mc_addr_info)

    def establish_connection(self):
        """
        Establish RDMACM connection between two Async CMIDs.
        """
        if self.cm_res.passive:
            self.cm_res.cmid.bind_addr(self.cm_res.ai)
            self.cm_res.cmid.listen()
        for conn_idx in range(self.num_conns):
            if self.cm_res.passive:
                self.syncer.wait()
                self.event_handler(expected_event=ce.RDMA_CM_EVENT_CONNECT_REQUEST)
                self.cm_res.create_qp(conn_idx=conn_idx)
                if self.qp_timeout >= 0:
                    self.set_qp_timeout(self.cm_res.child_ids[conn_idx], self.qp_timeout)
                if self.cm_res.with_ext_qp:
                    self.set_cmids_qp_ece(self.cm_res.passive)
                    self.cm_res.modify_ext_qp_to_rts(conn_idx=conn_idx)
                    self.set_cmid_ece(self.cm_res.passive)
                child_id = self.cm_res.child_ids[conn_idx]
                if self.reject_conn:
                    child_id.reject(REJECT_MSG, sys.getsizeof(REJECT_MSG))
                    return
                child_id.accept(self.cm_res.create_conn_param(conn_idx=conn_idx))
                if self.qp_timeout >= 0:
                    attr, _ = child_id.query_qp(e.IBV_QP_TIMEOUT)
                    assert self.qp_timeout == attr.timeout
                if self.cm_res.port_space == ce.RDMA_PS_TCP:
                    self.event_handler(expected_event=ce.RDMA_CM_EVENT_ESTABLISHED)
            else:
                cmid = self.cm_res.cmids[conn_idx]
                cmid.resolve_addr(self.cm_res.ai)
                self.event_handler(expected_event=ce.RDMA_CM_EVENT_ADDR_RESOLVED)
                self.syncer.wait()
                cmid.resolve_route()
                self.event_handler(expected_event=ce.RDMA_CM_EVENT_ROUTE_RESOLVED)
                self.cm_res.create_qp(conn_idx=conn_idx)
                if self.qp_timeout >= 0:
                    self.set_qp_timeout(self.cm_res.cmid, self.qp_timeout)
                if self.cm_res.with_ext_qp:
                    self.set_cmid_ece(self.cm_res.passive)
                cmid.connect(self.cm_res.create_conn_param(conn_idx=conn_idx))
                if self.cm_res.with_ext_qp:
                    self.event_handler(expected_event=\
                        ce.RDMA_CM_EVENT_CONNECT_RESPONSE)
                    self.set_cmids_qp_ece(self.cm_res.passive)
                    self.cm_res.modify_ext_qp_to_rts(conn_idx=conn_idx)
                    cmid.establish()
                else:
                    if self.reject_conn:
                        self.event_handler(expected_event=ce.RDMA_CM_EVENT_REJECTED)
                        return
                    self.event_handler(expected_event=ce.RDMA_CM_EVENT_ESTABLISHED)
                if self.qp_timeout >= 0:
                    attr, _ = self.cm_res.cmid.query_qp(e.IBV_QP_TIMEOUT)
                    assert self.qp_timeout == attr.timeout
        self.cm_res.create_mr()
        self.sync_qp_numbers()

    def set_qp_timeout(self, cm_id, ack_timeout):
        cm_id.set_option(ce.RDMA_OPTION_ID, ce.RDMA_OPTION_ID_ACK_TIMEOUT, ack_timeout, 1)

    def sync_qp_numbers(self):
        """
        Sync the QP numbers of the connections sides.
        """
        if self.cm_res.passive:
            self.syncer.wait()
            self.notifier.put(self.cm_res.my_qp_number())
            self.syncer.wait()
            self.cm_res.remote_qpn = self.notifier.get()
        else:
            self.syncer.wait()
            self.cm_res.remote_qpn = self.notifier.get()
            self.notifier.put(self.cm_res.my_qp_number())
            self.syncer.wait()

    def disconnect(self):
        """
        Disconnect the connection.
        """
        if self.cm_res.port_space == ce.RDMA_PS_TCP:
            if self.cm_res.passive:
                for child_id in self.cm_res.child_ids.values():
                    child_id.disconnect()
            else:
                self.event_handler(expected_event=ce.RDMA_CM_EVENT_DISCONNECTED)
                for cmid in self.cm_res.cmids.values():
                    cmid.disconnect()

    def set_cmid_ece(self, passive):
        """
        Set the local CMIDs ECE. The ECE is taken from the CMIDs QP ECE.
        :param passive: Indicates if this CMID is participate as passive in
                        this connection.
        """
        cmid = self.cm_res.child_id if passive else self.cm_res.cmid
        try:
            ece = self.cm_res.qp.query_ece()
            cmid.set_local_ece(ece)
        except PyverbsRDMAError as ex:
            if ex.error_code != errno.EOPNOTSUPP:
                raise ex

    def set_cmids_qp_ece(self, passive):
        """
        Set the CMIDs QP ECE.
        :param passive: Indicates if this CMID is participate as passive in
                        this connection.
        """
        cmid = self.cm_res.child_id if passive else self.cm_res.cmid
        try:
            ece = cmid.get_remote_ece()
            self.cm_res.qp.set_ece(ece)
        except PyverbsRDMAError as ex:
            if ex.error_code != errno.EOPNOTSUPP:
                raise ex

class CMSyncConnection(CMConnection):
    """
    Implement RDMACM connection management for synchronous CMIDs. It includes
    connection establishment, disconnection and other methods such as traffic.
    """
    def __init__(self, ip_addr, syncer=None, notifier=None, passive=False, **kwargs):
        """
        Init the CMConnection and then init the SyncCMResources.
        :param ip_addr: IP address to use.
        :param syncer: Barrier object to sync between all the test processes.
        :param notifier: Queue object to pass objects between the connection
                         sides.
        :param passive: Indicate if it's a passive side.
        :param kwargs: Arguments used to initialize the CM resources. For more
                       info please check CMResources.
        """
        super(CMSyncConnection, self).__init__(syncer=syncer, notifier=notifier)
        self.create_cm_res(ip_addr, passive=passive, **kwargs)

    def create_cm_res(self, ip_addr, passive, **kwargs):
        self.cm_res = SyncCMResources(addr=ip_addr, passive=passive, **kwargs)
        self.cm_res.create_cmid()

    def establish_connection(self):
        """
        Establish RDMACM connection between two Sync CMIDs.
        """
        if self.cm_res.passive:
            self.cm_res.cmid.listen()
            self.syncer.wait()
            self.cm_res.create_child_id()
            self.cm_res.child_id.accept()
            self.cm_res.create_mr()
        else:
            self.syncer.wait()
            self.cm_res.cmid.connect()
            self.cm_res.create_mr()

    def disconnect(self):
        """
        Disconnect the connection.
        """
        if self.cm_res.port_space == ce.RDMA_PS_TCP:
            if self.cm_res.passive:
                self.cm_res.child_id.disconnect()
            else:
                self.cm_res.cmid.disconnect()
