# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file
"""
Test module for pyverbs' mlx5_vfio module.
"""

from threading import Thread
import unittest
import select
import errno

from pyverbs.providers.mlx5.mlx5_vfio import Mlx5VfioAttr, Mlx5VfioContext
from tests.mlx5_base import Mlx5DevxRcResources, Mlx5DevxTrafficBase
from pyverbs.pyverbs_error import PyverbsRDMAError


class Mlx5VfioResources(Mlx5DevxRcResources):
    def __init__(self, ib_port, pci_name, gid_index=None, ctx=None):
        self.pci_name = pci_name
        self.ctx = ctx
        super().__init__(None, ib_port, gid_index)

    def create_context(self):
        """
        Opens an mlx5 VFIO context.
        Since only one context is allowed to be opened on a VFIO, the user must
        pass that context for the remaining resources, which in that case, the
        same context would be used.
        :return: None
        """
        if self.ctx:
            return
        try:
            vfio_attr = Mlx5VfioAttr(pci_name=self.pci_name)
            vfio_attr.pci_name = self.pci_name
            self.ctx = Mlx5VfioContext(attr=vfio_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest(f'Mlx5 VFIO is not supported ({ex})')
            raise ex

    def query_gid(self):
        """
        Currently Mlx5VfioResources does not support Eth port type.
        Query GID would just be skipped.
        """
        pass


class Mlx5VfioTrafficTest(Mlx5DevxTrafficBase):
    """
    Test various functionality of an mlx5-vfio device.
    """
    def setUp(self):
        """
        Verifies that the user has passed a PCI device name to work with.
        """
        self.pci_dev = self.config['pci_dev']
        if not self.pci_dev:
            raise unittest.SkipTest('PCI device must be passed by the user')

    def create_players(self):
        self.server = Mlx5VfioResources(ib_port=self.ib_port, pci_name=self.pci_dev)
        self.client = Mlx5VfioResources(ib_port=self.ib_port, pci_name=self.pci_dev,
                                        ctx=self.server.ctx)

    def vfio_processs_events(self):
        """
        Processes mlx5 vfio device events.
        This method should run from application thread to maintain the events.
        """
        # Server and client use the same context
        events_fd = self.server.ctx.get_events_fd()
        with select.epoll() as epoll_events:
            epoll_events.register(events_fd, select.EPOLLIN)
            while self.proc_events:
                for fd, event in epoll_events.poll(timeout=0.1):
                    if fd == events_fd:
                        if not (event & select.EPOLLIN):
                            self.event_ex.append(PyverbsRDMAError(f'Unexpected vfio event: {event}'))
                        self.server.ctx.process_events()

    def test_mlx5vfio_rc_qp_send_imm_traffic(self):
        """
        Opens one mlx5 vfio context, creates two DevX RC QPs on it, and modifies
        them to RTS state.
        Then does SEND_IMM traffic.
        """
        self.create_players()
        if self.server.is_eth():
            raise unittest.SkipTest(f'{self.__class__.__name__} is currently supported over IB only')
        self.event_ex = []
        self.proc_events = True
        proc_events = Thread(target=self.vfio_processs_events)
        proc_events.start()
        # Move the DevX QPs ro RTS state
        self.pre_run()
        try:
            # Send traffic
            self.send_imm_traffic()
        finally:
            # Stop listening to events
            self.proc_events = False
            proc_events.join()
            if self.event_ex:
                raise PyverbsRDMAError(f'Received unexpected vfio events: {self.event_ex}')
