# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file
"""
Provide some useful helper function for pyverbs rdmacm' tests.
"""
from tests.base import CMResources
from tests.utils import validate


def active_side(dst_addr, pipe):
    """
    RDMACM active side (client) which establish and uses rdamcm synchronous
    connection.
    :param dst_addr: Destination address to connect
    :param pipe: multiprocessing.Pipe object for processes synchronization
    :return: None
    """
    client = CMResources(dst=dst_addr)
    pipe.recv()
    client.pre_run()
    connected_id = client.cmid
    client.create_mr(connected_id)
    send_msg = 'c' * client.msg_size
    for _ in range(client.num_msgs):
        client.mr.write(send_msg, client.msg_size)
        pipe.recv()
        connected_id.post_send(client.mr)
        connected_id.get_send_comp()
        pipe.send('')
        connected_id.post_recv(client.mr)
        pipe.recv()
        connected_id.get_recv_comp()
        msg_received = client.mr.read(client.msg_size, 0)
        validate(msg_received, False, client.msg_size)
    connected_id.disconnect()


def passive_side(src_addr, pipe):
    """
    RDMACM passive side (server) which establish and uses rdamcm synchronous
    connection.
    :param src_addr: Local address to bind to
    :param pipe: multiprocessing.Pipe object for processes synchronization
    :return: None
    """
    server = CMResources(src=src_addr)
    server.pre_run()
    pipe.send('')
    connected_id = server.cmid.get_request()
    connected_id.accept()
    server.create_mr(connected_id)
    send_msg = 's' * server.msg_size
    for _ in range(server.num_msgs):
        connected_id.post_recv(server.mr)
        pipe.send('')
        pipe.recv()
        connected_id.get_recv_comp()
        msg_received = server.mr.read(server.msg_size, 0)
        validate(msg_received, True, server.msg_size)
        server.mr.write(send_msg, server.msg_size)
        connected_id.post_send(server.mr)
        connected_id.get_send_comp()
        pipe.send('')
    connected_id.disconnect()
