# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file
"""
Provide some useful helper function for pyverbs rdmacm' tests.
"""
from tests.base import CMResources
from tests.utils import validate
import os


def active_side(dst_addr, syncer, notifier):
    """
    RDMACM active side (client) which establish and uses rdamcm synchronous
    connection.
    :param dst_addr: Destination address to connect
    :param syncer: multiprocessing.Barrier object for processes synchronization
    :param notifier: Notify parent process about any exceptions or success
    :return: None
    """
    try:
        client = CMResources(dst=dst_addr)
        syncer.wait()
        client.pre_run()
        connected_id = client.cmid
        client.create_mr(connected_id)
        send_msg = 'c' * client.msg_size
        for _ in range(client.num_msgs):
            client.mr.write(send_msg, client.msg_size)
            syncer.wait()
            connected_id.post_send(client.mr)
            connected_id.get_send_comp()
            syncer.wait()
            connected_id.post_recv(client.mr)
            syncer.wait()
            connected_id.get_recv_comp()
            msg_received = client.mr.read(client.msg_size, 0)
            validate(msg_received, False, client.msg_size)
        connected_id.disconnect()
    except Exception as ex:
        notifier.put('Caught exception in active side process: pid {}\n'
                     .format(os.getpid()) +
                     'Exception message: {}'.format(str(ex)))
    else:
        notifier.put(None)


def passive_side(src_addr, syncer, notifier):
    """
    RDMACM passive side (server) which establish and uses rdamcm synchronous
    connection.
    :param src_addr: Local address to bind to
    :param syncer: multiprocessing.Barrier object for processes synchronization
    :param notifier: Notify parent process about any exceptions or success
    :return: None
    """
    try:
        server = CMResources(src=src_addr)
        server.pre_run()
        syncer.wait()
        connected_id = server.cmid.get_request()
        connected_id.accept()
        server.create_mr(connected_id)
        send_msg = 's' * server.msg_size
        for _ in range(server.num_msgs):
            connected_id.post_recv(server.mr)
            syncer.wait()
            syncer.wait()
            connected_id.get_recv_comp()
            msg_received = server.mr.read(server.msg_size, 0)
            validate(msg_received, True, server.msg_size)
            server.mr.write(send_msg, server.msg_size)
            connected_id.post_send(server.mr)
            connected_id.get_send_comp()
            syncer.wait()
        connected_id.disconnect()
    except Exception as ex:
        notifier.put('Caught exception in passive side process: pid {}\n'
                     .format(os.getpid()) +
                     'Exception message: {}'.format(str(ex)))
    else:
        notifier.put(None)