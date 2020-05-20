# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file
"""
Provide some useful helper function for pyverbs rdmacm' tests.
"""
from tests.utils import validate, poll_cq, get_send_element, get_recv_wr
from tests.base_rdmacm import AsyncCMResources, SyncCMResources
from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from tests.utils import validate
from pyverbs.cmid import CMEvent
import pyverbs.cm_enums as ce
import abc
import unittest
import errno
import os


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

    def rdmacm_traffic(self):
        """
        Run rdmacm traffic. This method runs the compatible traffic flow
        depending on the CMResources. If self.with_ext_qp is set the traffic
        will go through the external QP.
        """
        if self.cm_res.with_ext_qp:
            if self.cm_res.passive:
                self._ext_qp_server_traffic()
            else:
                self._ext_qp_client_traffic()
        else:
            if self.cm_res.passive:
                self._cmid_server_traffic()
            else:
                self._cmid_client_traffic()

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
            send_wr = get_send_element(self.cm_res, self.cm_res.passive)[0]
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
            send_wr = get_send_element(self.cm_res, self.cm_res.passive)[0]
            self.cm_res.qp.post_send(send_wr)
            poll_cq(self.cm_res.cq)
            self.cm_res.qp.post_recv(recv_wr)
            poll_cq(self.cm_res.cq)
            msg_received = self.cm_res.mr.read(self.cm_res.msg_size, 0)
            validate(msg_received, self.cm_res.passive, self.cm_res.msg_size)

    def _cmid_server_traffic(self):
        """
        RDMACM server side traffic function which sends and receives a message,
        and then validates the received message. This traffic method uses the
        RDMACM API for send, recv and get_completion.
        :return: None
        """
        send_msg = (self.cm_res.msg_size) * 's'
        cmid = self.cm_res.child_id
        grh_offset = 0
        for _ in range(self.cm_res.num_msgs):
            cmid.post_recv(self.cm_res.mr)
            self.syncer.wait()
            self.syncer.wait()
            wc = cmid.get_recv_comp()
            msg_received = self.cm_res.mr.read(self.cm_res.msg_size,
                                               grh_offset)
            validate(msg_received, self.cm_res.passive, self.cm_res.msg_size)
            self.cm_res.mr.write(send_msg, self.cm_res.msg_size)
            cmid.post_send(self.cm_res.mr)
            cmid.get_send_comp()
            self.syncer.wait()

    def _cmid_client_traffic(self):
        """
        RDMACM client side traffic function which sends and receives a message,
        and then validates the received message. This traffic method uses the
        RDMACM API for send, recv and get_completion.
        :return: None
        """
        send_msg = (self.cm_res.msg_size) * 'c'
        cmid = self.cm_res.cmid
        grh_offset = 0
        for _ in range(self.cm_res.num_msgs):
            self.cm_res.mr.write(send_msg, self.cm_res.msg_size + grh_offset)
            self.syncer.wait()
            cmid.post_send(self.cm_res.mr)
            cmid.get_send_comp()
            self.syncer.wait()
            cmid.post_recv(self.cm_res.mr)
            self.syncer.wait()
            cmid.get_recv_comp()
            msg_received = self.cm_res.mr.read(self.cm_res.msg_size,
                                               grh_offset)
            validate(msg_received, self.cm_res.passive, self.cm_res.msg_size)

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
        if expected_event and expected_event != cm_event.event_type:
            raise PyverbsError('Expected this event: {}, got this event: {}'.
                                format(expected_event, cm_event.event_str()))
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
    def __init__(self, ip_addr, syncer=None, notifier=None, passive=False, **kwargs):
        """
        Init the CMConnection and then init the AsyncCMResources.
        :param ip_addr: IP address to use.
        :param syncer: Barrier object to sync between all the test processes.
        :param notifier: Queue object to pass objects between the connection
                         sides.
        :param passive: Indicate if it's a passive side.
        :param kwargs: Arguments used to initialize the CM resources. For more
                       info please check CMResources.
        """
        super(CMAsyncConnection, self).__init__(syncer=syncer, notifier=notifier)
        self.cm_res = AsyncCMResources(addr=ip_addr, passive=passive, **kwargs)

    def establish_connection(self):
        """
        Establish RMDACM connection between two Async CMIDs.
        """
        if self.cm_res.passive:
            self.cm_res.cmid.bind_addr(self.cm_res.ai)
            self.cm_res.cmid.listen()
            self.syncer.wait()
            self.event_handler(expected_event=ce.RDMA_CM_EVENT_CONNECT_REQUEST)
            self.cm_res.create_qp()
            if self.cm_res.with_ext_qp:
                self.set_cmids_qp_ece(True)
            self.cm_res.child_id.accept(self.cm_res.create_conn_param())
            if self.cm_res.with_ext_qp:
                self.cm_res.modify_ext_qp_to_rts()
            self.event_handler(expected_event=ce.RDMA_CM_EVENT_ESTABLISHED)
        else:
            self.cm_res.cmid.resolve_addr(self.cm_res.ai)
            self.event_handler(expected_event=ce.RDMA_CM_EVENT_ADDR_RESOLVED)
            self.syncer.wait()
            self.cm_res.cmid.resolve_route()
            self.event_handler(expected_event=ce.RDMA_CM_EVENT_ROUTE_RESOLVED)
            self.cm_res.create_qp()
            if self.cm_res.with_ext_qp:
                self.set_cmids_qp_ece(False)
            self.cm_res.cmid.connect(self.cm_res.create_conn_param())
            if self.cm_res.with_ext_qp:
                self.event_handler(expected_event=\
                    ce.RDMA_CM_EVENT_CONNECT_RESPONSE)
                self.cm_res.modify_ext_qp_to_rts()
                self.cm_res.cmid.establish()
            else:
                self.event_handler(expected_event=ce.RDMA_CM_EVENT_ESTABLISHED)
        self.cm_res.create_mr()
        self.sync_qp_numbers()

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
        if self.cm_res.passive:
            self.cm_res.child_id.disconnect()
        else:
            self.event_handler(expected_event=ce.RDMA_CM_EVENT_DISCONNECTED)
            self.cm_res.cmid.disconnect()

    def set_cmids_qp_ece(self, passive):
        """
        Set the QP ECE.
        :param passive: Indicates if this CMID is participate as passive in
                        this connection.
        """
        try:
            if passive:
                ece = self.cm_res.child_id.get_remote_ece()
                self.cm_res.qp.set_ece(ece)
            else:
                ece = self.cm_res.qp.query_ece()
                self.cm_res.cmid.set_local_ece(ece)
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
        self.cm_res = SyncCMResources(addr=ip_addr, passive=passive, **kwargs)

    def establish_connection(self):
        """
        Establish RMDACM connection between two Sync CMIDs.
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
        if self.cm_res.passive:
            self.cm_res.child_id.disconnect()
        else:
            self.cm_res.cmid.disconnect()
