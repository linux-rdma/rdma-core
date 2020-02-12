# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file
"""
Provide some useful helper function for pyverbs rdmacm' tests.
"""
from pyverbs.pyverbs_error import PyverbsError
from tests.base import CMResources
from tests.utils import validate
from pyverbs.cmid import CMEvent
import pyverbs.cm_enums as ce
import os

events_dict = {ce.RDMA_CM_EVENT_ADDR_ERROR: 'Resolve Address Error',
               ce.RDMA_CM_EVENT_ROUTE_ERROR: 'Resolve Route Error',
               ce.RDMA_CM_EVENT_CONNECT_ERROR: 'Connection Error',
               ce.RDMA_CM_EVENT_UNREACHABLE: 'Node is Unreachable',
               ce.RDMA_CM_EVENT_REJECTED: 'Connection Rejected',
               ce.RDMA_CM_EVENT_DEVICE_REMOVAL: 'Device Removal',
               ce.RDMA_CM_EVENT_MULTICAST_JOIN: 'Multicast Join',
               ce.RDMA_CM_EVENT_MULTICAST_ERROR: 'Multicast Error',
               ce.RDMA_CM_EVENT_ADDR_CHANGE: 'Address Change',
               ce.RDMA_CM_EVENT_TIMEWAIT_EXIT: 'Time wait Exit'}


def server_traffic(agr_obj, syncer):
    """
    RDMACM passive side traffic function which uses RDMACM's QP, this function
    sends and receives a message, and then validate the received message, this
    operation executed <agr_obj.num_msgs> times.
    :param agr_obj: Aggregation object which contains all necessary resources
    :param syncer: multiprocessing.Barrier object for processes synchronization
    :return: None
    """
    send_msg = agr_obj.msg_size * 's'
    cmid = agr_obj.child_id
    for _ in range(agr_obj.num_msgs):
        cmid.post_recv(agr_obj.mr)
        syncer.wait()
        syncer.wait()
        cmid.get_recv_comp()
        msg_received = agr_obj.mr.read(agr_obj.msg_size, 0)
        validate(msg_received, agr_obj.is_server, agr_obj.msg_size)
        agr_obj.mr.write(send_msg, agr_obj.msg_size)
        cmid.post_send(agr_obj.mr)
        cmid.get_send_comp()
        syncer.wait()


def client_traffic(agr_obj, syncer):
    """
    RDMACM active side traffic function which uses RDMACM's QP, this function
    sends and receives a message, and then validate the received message, this
    operation executed <agr_obj.num_msgs> times.
    :param agr_obj: Aggregation object which contains all necessary resources
    :param syncer: multiprocessing.Barrier object for processes synchronization
    :return: None
    """
    send_msg = agr_obj.msg_size * 'c'
    cmid = agr_obj.cmid
    for _ in range(agr_obj.num_msgs):
        agr_obj.mr.write(send_msg, agr_obj.msg_size)
        syncer.wait()
        cmid.post_send(agr_obj.mr)
        cmid.get_send_comp()
        syncer.wait()
        cmid.post_recv(agr_obj.mr)
        syncer.wait()
        cmid.get_recv_comp()
        msg_received = agr_obj.mr.read(agr_obj.msg_size, 0)
        validate(msg_received, agr_obj.is_server, agr_obj.msg_size)


def event_handler(agr_obj):
    """
    Handle and execute corresponding API for RDMACM events of asynchronous
    communication
    :param agr_obj: Aggregation object which contains all necessary resources
    :return: None
    """
    cm_event = CMEvent(agr_obj.cmid.event_channel)
    if cm_event.event_type == ce.RDMA_CM_EVENT_ADDR_RESOLVED:
        agr_obj.cmid.resolve_route()
    elif cm_event.event_type == ce.RDMA_CM_EVENT_ROUTE_RESOLVED:
        agr_obj.create_qp()
        agr_obj.cmid.connect(agr_obj.create_conn_param())
    elif cm_event.event_type == ce.RDMA_CM_EVENT_CONNECT_REQUEST:
        agr_obj.create_child_id(cm_event)
        agr_obj.create_qp()
        agr_obj.child_id.accept(agr_obj.create_conn_param())
    elif cm_event.event_type == ce.RDMA_CM_EVENT_ESTABLISHED:
        agr_obj.connected = True
    elif cm_event.event_type == ce.RDMA_CM_EVENT_CONNECT_RESPONSE:
        agr_obj.connected = True
        agr_obj.cmid.establish()
    elif cm_event.event_type == ce.RDMA_CM_EVENT_DISCONNECTED:
        if agr_obj.is_server:
            agr_obj.child_id.disconnect()
            agr_obj.connected = False
        else:
            agr_obj.cmid.disconnect()
            agr_obj.connected = False
    else:
        if cm_event.event_type in events_dict:
            raise PyverbsError('Unexpected event - {}'.format(
                               events_dict[cm_event.event_type]))
        else:
            raise PyverbsError('The event {} is not supported'.format(
                               cm_event.event_type))
    cm_event.ack_cm_event()


def sync_traffic(addr, syncer, notifier, is_server):
    """
    RDMACM synchronous data and control path which first establish a connection
    using RDMACM's synchronous API and then execute RDMACM synchronous traffic.
    :param addr: Address to connect to and to bind to
    :param syncer: multiprocessing.Barrier object for processes synchronization
    :param notifier: Notify parent process about any exceptions or success
    :param is_server: A flag which indicates if this is a server or client
    :return: None
    """
    try:
        if is_server:
            server = CMResources(src=addr)
            server.cmid.listen()
            syncer.wait()
            server.create_child_id()
            server.child_id.accept()
            server.create_mr()
            server_traffic(server, syncer)
            server.child_id.disconnect()
        else:
            client = CMResources(dst=addr)
            syncer.wait()
            client.cmid.connect()
            client.create_mr()
            client_traffic(client, syncer)
            client.cmid.disconnect()
    except Exception as ex:
        side = 'passive' if is_server else 'active'
        notifier.put('Caught exception in {side} side process: pid {pid}\n'
                     .format(side=side, pid=os.getpid()) +
                     'Exception message: {ex}'.format(ex=str(ex)))
    else:
        notifier.put(None)


def async_traffic(addr, syncer, notifier, is_server):
    """
    RDMACM asynchronous data and control path function that first establishes a
    connection using RDMACM events API and then executes RDMACM asynchronous
    traffic.
    :param addr: Address to connect to and to bind to
    :param syncer: multiprocessing.Barrier object for processes synchronization
    :param notifier: Notify parent process about any exceptions or success
    :param is_server: A flag which indicates if this is a server or not
    :return: None
    """
    try:
        if is_server:
            server = CMResources(src=addr, is_async=True)
            listen_id = server.cmid
            listen_id.bind_addr(server.ai)
            listen_id.listen()
            syncer.wait()
            while not server.connected:
                event_handler(server)
            server.create_mr()
            server_traffic(server, syncer)
            server.child_id.disconnect()
        else:
            client = CMResources(src=addr, dst=addr, is_async=True)
            id = client.cmid
            id.resolve_addr(client.ai)
            syncer.wait()
            while not client.connected:
                event_handler(client)
            client.create_mr()
            client_traffic(client, syncer)
            event_handler(client)
    except Exception as ex:
        side = 'passive' if is_server else 'active'
        notifier.put('Caught exception in {side} side process: pid {pid}\n'
                     .format(side=side, pid=os.getpid()) +
                     'Exception message: {ex}'.format(ex=str(ex)))
    else:
        notifier.put(None)
