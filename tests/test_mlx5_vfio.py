# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file
"""
Test module for pyverbs' mlx5_vfio module.
"""

from threading import Thread
import unittest
import logging
import struct
import select
import errno
import time
import math
import os

from tests.mlx5_base import Mlx5DevxRcResources, Mlx5DevxTrafficBase, PortState, \
    PortStatus, PORT_STATE_TIMEOUT
from pyverbs.providers.mlx5.mlx5dv import Mlx5DevxMsiVector, Mlx5DevxEq, Mlx5UAR
from pyverbs.providers.mlx5.mlx5_vfio import Mlx5VfioAttr, Mlx5VfioContext
from pyverbs.pyverbs_error import PyverbsRDMAError
import pyverbs.providers.mlx5.mlx5_enums as dve
from pyverbs.base import PyverbsRDMAErrno
import pyverbs.mem_alloc as mem
import pyverbs.dma_util as dma


class Mlx5VfioResources(Mlx5DevxRcResources):
    def __init__(self, ib_port, pci_name, gid_index=None, ctx=None, activate_port_state=False):
        self.pci_name = pci_name
        self.ctx = ctx
        super().__init__(None, ib_port, gid_index, activate_port_state=activate_port_state)

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


class Mlx5VfioEqResources(Mlx5VfioResources):
    def __init__(self, ib_port, pci_name, gid_index=None, ctx=None):
        self.cons_index = 0
        super().__init__(ib_port, pci_name, gid_index, ctx)
        self.logger = logging.getLogger(self.__class__.__name__)

    def create_uar(self):
        super().create_uar()
        self.uar['eq'] = Mlx5UAR(self.ctx, dve._MLX5DV_UAR_ALLOC_TYPE_NC)
        if not self.uar['eq'].page_id:
            raise PyverbsRDMAError('Failed to allocate UAR')

    def get_eqe(self, cc):
        from tests.mlx5_prm_structs import SwEqe

        ci = self.cons_index + cc
        entry = ci & (self.nent - 1)
        eqe_bytes = mem.read64(self.eq.vaddr + entry * len(SwEqe()))
        eqe_bytes = eqe_bytes.to_bytes(length=8, byteorder='little')
        eqe = SwEqe(eqe_bytes)
        if (eqe.owner & 1) ^ (not(not(ci & self.nent))):
            eqe = None
        elif eqe:
            dma.udma_from_dev_barrier()

        return eqe

    def update_ci(self, cc, arm=0):
        addr = self.doorbell
        if arm:
            addr += 8  # Adding 2 bytes according to PRM
        self.cons_index += cc
        val = (self.cons_index & 0xffffff) | (self.eqn << 24)
        val_be = struct.unpack("<I", struct.pack(">I", val))[0]
        dma.mmio_write32_as_be(addr, val_be)
        dma.udma_to_dev_barrier()

    def init_dveq_buff(self):
        from tests.mlx5_prm_structs import SwEqe

        for i in range(self.nent):
            eqe_bytes = mem.read64(self.eq.vaddr + i * len(SwEqe()))
            eqe_bytes = eqe_bytes.to_bytes(length=8, byteorder='little')
            eqe = SwEqe(eqe_bytes)
            eqe.owner = 0x1
        self.update_ci(0)

    def update_cc(self, cc):
        if cc >= self.num_spare_eqe:
            self.update_ci(cc)
            cc = 0
        return cc

    def create_eq(self):
        from tests.mlx5_prm_structs import CreateEqIn, SwEqc, CreateEqOut,\
            EventType

        # Using num_spare_eqe to guarantee that we update
        # the ci before we polled all the entries in the EQ
        self.num_spare_eqe = 0x80
        self.nent = 0x80 + self.num_spare_eqe
        self.msi_vector = Mlx5DevxMsiVector(self.ctx)
        vector = self.msi_vector.vector
        log_eq_size = math.ceil(math.log2(self.nent))
        mask = 1 << EventType.PORT_STATE_CHANGE
        cmd_in = CreateEqIn(sw_eqc=SwEqc(uar_page=self.uar['eq'].page_id,
                                         log_eq_size=log_eq_size, intr=vector),
                            event_bitmask_63_0=mask)
        self.eq = Mlx5DevxEq(self.ctx, cmd_in, len(CreateEqOut()))
        self.eqn = CreateEqOut(self.eq.out_view).eqn
        self.doorbell = self.uar['eq'].base_addr + 0x40
        self.init_dveq_buff()
        self.update_ci(0, 1)

    def query_eqn(self):
        pass

    def process_async_events(self, fd):
        from tests.mlx5_prm_structs import EventType

        cc = 0
        ret = os.read(fd, 8)
        if not ret:
            raise PyverbsRDMAErrno('Failed to read FD')
        eqe = self.get_eqe(cc)
        while eqe:
            if eqe.event_type == EventType.PORT_STATE_CHANGE:
                self.logger.debug('Caught port state change event')
                return eqe.event_type
            elif eqe.event_type == EventType.CQ_ERROR:
                raise PyverbsRDMAError('Event type Error')
            cc = self.update_cc(cc + 1)
            eqe = self.get_eqe(cc)
        self.update_ci(cc, 1)


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
        self.server = Mlx5VfioResources(ib_port=self.ib_port, pci_name=self.pci_dev,
                                        activate_port_state=True)
        self.client = Mlx5VfioResources(ib_port=self.ib_port, pci_name=self.pci_dev,
                                        ctx=self.server.ctx)

    def create_async_players(self):
        self.server = Mlx5VfioEqResources(ib_port=self.ib_port, pci_name=self.pci_dev)
        self.client = Mlx5VfioResources(ib_port=self.ib_port, pci_name=self.pci_dev,
                                        ctx=self.server.ctx)

    def vfio_process_events(self):
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

    def vfio_process_async_events(self):
        """
        Processes mlx5 vfio device async events.
        This method should run from application thread to maintain the events.
        """
        from tests.mlx5_prm_structs import EventType

        # Server and client use the same context
        events_fd = self.server.msi_vector.fd
        with select.epoll() as epoll_events:
            epoll_events.register(events_fd, select.EPOLLIN)
            while self.proc_events:
                for fd, event in epoll_events.poll(timeout=0.1):
                    if fd == events_fd:
                        if not (event & select.EPOLLIN):
                            self.event_ex.append(PyverbsRDMAError(f'Unexpected vfio event: {event}'))
                        if self.server.process_async_events(events_fd) == EventType.PORT_STATE_CHANGE:
                            self.caught_event = True

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
        proc_events = Thread(target=self.vfio_process_events)
        proc_events.start()
        # Move the DevX QPs to RTS state
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

    def test_mlx5vfio_async_event(self):
        """
        Opens one mlx5 vfio context, creates DevX EQ on it.
        Then activates the port and catches the port state change event.
        """
        self.create_async_players()
        if self.server.is_eth():
            raise unittest.SkipTest(f'{self.__class__.__name__} is currently supported over IB only')
        self.event_ex = []
        self.proc_events = True
        self.caught_event = False
        proc_events = Thread(target=self.vfio_process_events)
        proc_async_events = Thread(target=self.vfio_process_async_events)
        proc_events.start()
        proc_async_events.start()
        # Move the DevX QPs to RTS state
        self.pre_run()
        try:
            # Change port state
            self.server.change_port_state_with_registers(PortStatus.MLX5_PORT_UP)
            admin_status, oper_status = self.server.query_port_state_with_registers()
            start_state_t = time.perf_counter()
            while admin_status != PortStatus.MLX5_PORT_UP or oper_status != PortStatus.MLX5_PORT_UP:
                if time.perf_counter() - start_state_t >= PORT_STATE_TIMEOUT:
                    raise PyverbsRDMAError('Could not change the port state to UP')
                admin_status, oper_status = self.server.query_port_state_with_registers()
            start_state_t = time.perf_counter()
            while self.server.query_port_state_with_mads(self.ib_port) < PortState.ACTIVE:
                if time.perf_counter() - start_state_t >= PORT_STATE_TIMEOUT:
                    raise PyverbsRDMAError('Could not change the port state to ACTIVE')
                time.sleep(1)
        finally:
            # Stop listening to events
            self.proc_events = False
            proc_events.join()
            proc_async_events.join()
            if self.event_ex:
                raise PyverbsRDMAError(f'Received unexpected vfio events: {self.event_ex}')
            if not self.caught_event:
                raise PyverbsRDMAError('Failed to catch an async event')
