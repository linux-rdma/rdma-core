# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.  See COPYING file

import unittest
import random

from pyverbs.base import PyverbsRDMAErrno
import pyverbs.device as d
from pyverbs.pd import PD


class pd_test(unittest.TestCase):
    """
    Test various functionalities of the PD class.
    """
    def test_alloc_pd(self):
        """
        Test ibv_alloc_pd()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx):
                    pass

    def test_dealloc_pd(self):
        """
        Test ibv_dealloc_pd()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    pd.close()

    def test_multiple_pd_creation(self):
        """
        Test multiple creations and destructions of a PD object
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                for i in range(random.randint(1, 200)):
                    with PD(ctx) as pd:
                        pd.close()

    def test_create_pd_none_ctx(self):
        """
        Verify that PD can't be created with a None context
        """
        try:
            pd = PD(None)
        except TypeError as te:
            assert 'expected pyverbs.device.Context' in te.args[0]
            assert 'got NoneType' in te.args[0]
        else:
            raise PyverbsRDMAErrno('Created a PD with None context')

    def test_destroy_pd_twice(self):
        """
        Test bad flow cases in destruction of a PD object
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    # Pyverbs supports multiple destruction of objects, we are
                    # not expecting an exception here.
                    pd.close()
                    pd.close()
