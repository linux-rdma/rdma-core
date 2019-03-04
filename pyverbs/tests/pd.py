# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.  See COPYING file
"""
Test module for pyverbs' pd module.
"""
import unittest
import random

from pyverbs.base import PyverbsRDMAErrno
import pyverbs.device as d
from pyverbs.pd import PD


class PDTest(unittest.TestCase):
    """
    Test various functionalities of the PD class.
    """
    @staticmethod
    def test_alloc_pd():
        """
        Test ibv_alloc_pd()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx):
                    pass

    @staticmethod
    def test_dealloc_pd():
        """
        Test ibv_dealloc_pd()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    pd.close()

    @staticmethod
    def test_multiple_pd_creation():
        """
        Test multiple creations and destructions of a PD object
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                for i in range(random.randint(1, 200)):
                    with PD(ctx) as pd:
                        pd.close()

    @staticmethod
    def test_create_pd_none_ctx():
        """
        Verify that PD can't be created with a None context
        """
        try:
            PD(None)
        except TypeError as te:
            assert 'expected pyverbs.device.Context' in te.args[0]
            assert 'got NoneType' in te.args[0]
        else:
            raise PyverbsRDMAErrno('Created a PD with None context')

    @staticmethod
    def test_destroy_pd_twice():
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
