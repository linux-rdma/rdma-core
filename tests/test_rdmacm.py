# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

from tests.rdmacm_utils import sync_traffic, async_traffic
from pyverbs.pyverbs_error import PyverbsError
from tests.base import RDMATestCase
import multiprocessing as mp
import pyverbs.device as d
import subprocess
import unittest
import json

NUM_OF_PROCESSES = 2


class CMTestCase(RDMATestCase):
    def setUp(self):
        if self.dev_name is not None:
            net_name = self.get_net_name(self.dev_name)
            try:
                self.ip_addr = self.get_ip_address(net_name)
            except KeyError:
                raise unittest.SkipTest('Device {} doesn\'t have net interface'
                                        .format(self.dev_name))
        else:
            dev_list = d.get_device_list()
            for dev in dev_list:
                net_name = self.get_net_name(dev.name.decode())
                try:
                    self.ip_addr = self.get_ip_address(net_name)
                except IndexError:
                    continue
                else:
                    self.dev_name = dev.name.decode()
                    break
            if self.dev_name is None:
                raise unittest.SkipTest('No devices with net interface')
        super().setUp()

    @staticmethod
    def get_net_name(dev):
        out = subprocess.check_output(['ls', '/sys/class/infiniband/{}/device/net/'
                                      .format(dev)])
        return out.decode().split('\n')[0]

    @staticmethod
    def get_ip_address(ifname):
        out = subprocess.check_output(['ip', '-j', 'addr', 'show', ifname])
        loaded_json = json.loads(out.decode())
        interface = loaded_json[0]['addr_info'][0]['local']
        if 'fe80::' in interface:
            interface = interface + '%' + ifname
        return interface

    @staticmethod
    def two_nodes_rdmacm_traffic(ip_addr, traffic_func):
        ctx = mp.get_context('fork')
        syncer = ctx.Barrier(NUM_OF_PROCESSES, timeout=5)
        notifier = ctx.Queue()
        passive = ctx.Process(target=traffic_func, args=[ip_addr, syncer,
                                                         notifier, True])
        active = ctx.Process(target=traffic_func, args=[ip_addr, syncer,
                                                        notifier, False])
        passive.start()
        active.start()
        while notifier.empty():
            pass

        for _ in range(NUM_OF_PROCESSES):
            res = notifier.get()
            if res is not None:
                passive.terminate()
                active.terminate()
                raise PyverbsError(res)

        passive.join()
        active.join()

    def test_rdmacm_sync_traffic(self):
        self.two_nodes_rdmacm_traffic(self.ip_addr, sync_traffic)

    def test_rdmacm_async_traffic(self):
        self.two_nodes_rdmacm_traffic(self.ip_addr, async_traffic)
