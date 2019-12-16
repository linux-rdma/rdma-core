# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file
"""
Provide some useful helper function for pyverbs rdmacm' tests.
"""
from tests.base import CMResources
from tests.utils import validate
import os


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
