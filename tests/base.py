# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc . All rights reserved. See COPYING file

import unittest
import random

from pyverbs.device import Context
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.pd import PD


class PyverbsAPITestCase(unittest.TestCase):
    def setUp(self):
        """
        Opens the devices and queries them
        """
        lst = d.get_device_list()
        self.devices = []
        for dev in lst:
            c = d.Context(name=dev.name.decode())
            attr = c.query_device()
            attr_ex = c.query_device_ex()
            self.devices.append((c, attr, attr_ex))

    def tearDown(self):
        for tup in self.devices:
            tup[0].close()


class RDMATestCase(unittest.TestCase):
    """
    A base class for test cases which provides the option for user parameters.
    These can be provided by manually adding the test case to the runner:
    suite = unittest.TestSuite()
    ... # Regular auto-detection of test cases, no parameters used.
    # Now follows your manual addition of test cases e.g:
    suite.addTest(RDMATestCase.parametrize(<TestCaseName>, dev_name='..',
                                           ib_port=1, gid_index=3,
                                           pkey_index=42))
    """
    ZERO_GID = '0000:0000:0000:0000'

    def __init__(self, methodName='runTest', dev_name=None, ib_port=None,
                 gid_index=None, pkey_index=None):
        super(RDMATestCase, self).__init__(methodName)
        self.dev_name = dev_name
        self.ib_port = ib_port
        self.gid_index = gid_index
        self.pkey_index = pkey_index

    @staticmethod
    def parametrize(testcase_klass, dev_name=None, ib_port=None, gid_index=None,
                    pkey_index=None):
        """
        Create a test suite containing all the tests from the given subclass
        with the given dev_name, port, gid index and pkey_index.
        """
        loader = unittest.TestLoader()
        names = loader.getTestCaseNames(testcase_klass)
        suite = unittest.TestSuite()
        for n in names:
            suite.addTest(testcase_klass(n, dev_name=dev_name, ib_port=ib_port,
                                         gid_index=gid_index,
                                         pkey_index=pkey_index))
        return suite

    def setUp(self):
        """
        Verify that the test case has dev_name, ib_port, gid_index and pkey index.
        If not provided by the user, a random valid combination will be used.
        """
        if self.pkey_index is None:
            # To avoid iterating the entire pkeys table, if a pkey index wasn't
            # provided, use index 0 which is always valid
            self.pkey_index = 0

        self.args = []
        if self.dev_name is not None:
            ctx = d.Context(name=self.dev_name)
            if self.ib_port is not None:
                if self.gid_index is not None:
                    # We have all we need, return
                    return
                else:
                    # Add avaiable GIDs of the given dev_name + port
                    self._add_gids_per_port(ctx, self.dev_name, self.ib_port)
            else:
                # Add available GIDs for each port of the given dev_name
                self._add_gids_per_device(ctx, self.dev_name)
        else:
            # Iterate available devices, add available GIDs for each of
            # their ports
            lst = d.get_device_list()
            for dev in lst:
                dev_name = dev.name.decode()
                ctx = d.Context(name=dev_name)
                self._add_gids_per_device(ctx, dev_name)

        if not self.args:
            raise unittest.SkipTest('No port is up, can\'t run traffic')
        # Choose one combination and use it
        args = random.choice(self.args)
        self.dev_name = args[0]
        self.ib_port = args[1]
        self.gid_index = args[2]

    def _add_gids_per_port(self, ctx, dev, port):
        # Don't add ports which are not active
        if ctx.query_port(port).state != e.IBV_PORT_ACTIVE:
            return
        idx = 0
        while True:
            gid = ctx.query_gid(port, idx)
            if gid.gid[-19:] == self.ZERO_GID:
                # No point iterating on
                break
            else:
                self.args.append([dev, port, idx])
                idx += 1

    def _add_gids_per_device(self, ctx, dev):
        port_count = ctx.query_device().phys_port_cnt
        for port in range(port_count):
            self._add_gids_per_port(ctx, dev, port+1)


class BaseResources(object):
    """
    BaseResources class is a base aggregator object which contains basic
    resources like Context and PD. It opens a context over the given device
    and port and allocates a PD.
    """
    def __init__(self, dev_name, ib_port, gid_index):
        """
        Initializes a BaseResources object.
        :param dev_name: Device name to be used (default: 'ibp0s8f0')
        :param ib_port: IB port of the device to use (default: 1)
        :param gid_index: Which GID index to use (default: 0)
        """
        self.ctx = Context(name=dev_name)
        self.gid_index = gid_index
        self.pd = PD(self.ctx)
        self.ib_port = ib_port
