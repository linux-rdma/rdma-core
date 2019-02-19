# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.  See COPYING file
"""
Test module for pyverbs' cq module.
"""
import unittest
import random

from pyverbs.pyverbs_error import PyverbsError
from pyverbs.cq import CompChannel, CQ
import pyverbs.device as d
import pyverbs.enums as e


class CQTest(unittest.TestCase):
    """
    Test various functionalities of the CQ class.
    """

    @staticmethod
    def test_create_cq():
        """
        Test ibv_create_cq()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                cqes = get_num_cqes(ctx)
                comp_vector = random.randint(0, ctx.num_comp_vectors - 1)
                if random.choice([True, False]):
                    with CompChannel(ctx) as cc:
                        with CQ(ctx, cqes, None, cc, comp_vector):
                            pass
                else:
                    with CQ(ctx, cqes, None, None, comp_vector):
                        pass

    @staticmethod
    def test_create_cq_bad_flow():
        """
        Test ibv_create_cq() with a wrong comp_vector / cqe number
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                cqes = get_num_cqes(ctx)
                comp_vector = random.randint(ctx.num_comp_vectors, 100)
                try:
                    if random.choice([True, False]):
                        with CompChannel(ctx) as cc:
                            with CQ(ctx, cqes, None, cc, comp_vector):
                                pass
                    else:
                        with CQ(ctx, cqes, None, None, comp_vector):
                            pass
                except PyverbsError as e:
                    assert 'Failed to create a CQ' in e.args[0]
                    assert 'Invalid argument' in e.args[0]
                else:
                    raise PyverbsError(
                        'Created a CQ with comp_vector={n} while device\'s num_comp_vectors={nc}'.
                        format(n=comp_vector, nc=ctx.num_comp_vectors))
                max_cqe = ctx.query_device().max_cqe
                cqes = random.randint(max_cqe + 1, max_cqe + 100)
                try:
                    if random.choice([True, False]):
                        with CompChannel(ctx) as cc:
                            with CQ(ctx, cqes, None, cc, 0):
                                pass
                    else:
                        with CQ(ctx, cqes, None, None, 0):
                            pass
                except PyverbsError as err:
                    assert 'Failed to create a CQ' in err.args[0]
                    assert 'Invalid argument' in err.args[0]
                else:
                    raise PyverbsError(
                        'Created a CQ with cqe={n} while device\'s max_cqe={nc}'.
                        format(n=cqes, nc=max_cqe))

    @staticmethod
    def test_destroy_cq():
        """
        Test ibv_destroy_cq()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                cqes = get_num_cqes(ctx)
                comp_vector = random.randint(0, ctx.num_comp_vectors - 1)
                if random.choice([True, False]):
                    with CompChannel(ctx) as cc:
                        cq = CQ(ctx, cqes, None, cc, comp_vector)
                else:
                    cq = CQ(ctx, cqes, None, None, comp_vector)
                cq.close()


class CCTest(unittest.TestCase):
    """
    Test various functionalities of the Completion Channel class.
    """

    @staticmethod
    def test_create_comp_channel():
        """
        Test ibv_create_comp_channel()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with CompChannel(ctx):
                    pass

    @staticmethod
    def test_destroy_comp_channel():
        """
        Test ibv_destroy_comp_channel()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                cc = CompChannel(ctx)
                cc.close()


def get_num_cqes(ctx):
    attr = ctx.query_device()
    max_cqe = attr.max_cqe
    return random.randint(0, max_cqe)
