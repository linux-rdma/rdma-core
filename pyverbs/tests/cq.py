# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.  See COPYING file
"""
Test module for pyverbs' cq module.
"""
import unittest
import random

from pyverbs.cq import CompChannel, CQ, CqInitAttrEx, CQEX
from pyverbs.pyverbs_error import PyverbsError
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


class CQEXTest(unittest.TestCase):
    """
    Test various functionalities of the CQEX class.
    """

    @staticmethod
    def test_create_cq_ex():
        """
        Test ibv_create_cq_ex()
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with CQEX(ctx, get_attrs_ex(ctx)):
                    pass

    @staticmethod
    def test_create_cq_ex_bad_flow():
        """
        Test ibv_create_cq_ex() with wrong comp_vector / number of cqes
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attrs_ex = get_attrs_ex(ctx)
                max_cqe = ctx.query_device().max_cqe
                attrs_ex.cqe = max_cqe + random.randint(1, 100)
                try:
                    CQEX(ctx, attrs_ex)
                except PyverbsError as e:
                    assert 'Failed to create extended CQ' in e.args[0]
                    assert ' Errno: 22' in e.args[0]
                else:
                    raise PyverbsError(
                        'Created a CQEX with {c} CQEs while device\'s max CQE={dc}'.
                        format(c=attrs_ex.cqe, dc=max_cqe))
                comp_channel = random.randint(ctx.num_comp_vectors, 100)
                attrs_ex.comp_vector = comp_channel
                attrs_ex.cqe = get_num_cqes(ctx)
                try:
                    CQEX(ctx, attrs_ex)
                except PyverbsError as e:
                    assert 'Failed to create extended CQ' in e.args[0]
                    assert ' Errno: 22' in e.args[0]
                else:
                    raise PyverbsError(
                        'Created a CQEX with comp_vector={c} while device\'s num_comp_vectors={dc}'.
                        format(c=comp_channel, dc=ctx.num_comp_vectors))

    @staticmethod
    def test_destroy_cq_ex():
        """
        Test ibv_destroy_cq() for extended CQs
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with CQEX(ctx, get_attrs_ex(ctx)) as cq:
                    cq.close()


def get_num_cqes(ctx):
    attr = ctx.query_device()
    max_cqe = attr.max_cqe
    return random.randint(0, max_cqe)


def get_attrs_ex(ctx):
    cqe = get_num_cqes(ctx)
    sample = random.sample(list(e.ibv_create_cq_wc_flags),
                           random.randint(0, 11))
    wc_flags = 0
    for flag in sample:
        wc_flags |= flag
    comp_mask = random.choice([0, e.IBV_CQ_INIT_ATTR_MASK_FLAGS])
    flags = 0
    if comp_mask is not 0:
        sample = random.sample(list(e.ibv_create_cq_attr_flags),
                               random.randint(0, 2))
        for flag in sample:
            flags |= flag
    return CqInitAttrEx(cqe=cqe, wc_flags=wc_flags, comp_mask=comp_mask,
                        flags=flags)
