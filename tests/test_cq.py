# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for pyverbs' cq module.
"""
import random

from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from pyverbs.cq import CompChannel, CQ, CqInitAttrEx, CQEX
from tests.base import PyverbsAPITestCase
import pyverbs.enums as e
import tests.utils as u
import unittest
import errno


class CQTest(PyverbsAPITestCase):
    """
    Test various functionalities of the CQ class.
    """
    def test_create_cq(self):
        """
        Test ibv_create_cq()
        """
        for ctx, attr, attr_ex in self.devices:
            for i in range(10):
                cqes = get_num_cqes(attr)
                comp_vector = int(ctx.num_comp_vectors * random.random())
                if random.choice([True, False]):
                    with CompChannel(ctx) as cc:
                        with CQ(ctx, cqes, None, cc, comp_vector):
                            pass
                else:
                    with CQ(ctx, cqes, None, None, comp_vector):
                        pass

    def test_create_cq_bad_flow(self):
        """
        Test ibv_create_cq() with a wrong comp_vector / cqe number
        """
        for ctx, attr, attr_ex in self.devices:
            for i in range(10):
                cc = CompChannel(ctx)
                cqes = 100
                comp_vector = ctx.num_comp_vectors + int(100 *
                                                         random.random())
                has_cc = random.choice([True, False])
                if not has_cc:
                    cc = None
                try:
                    with CQ(ctx, cqes, None, cc, comp_vector):
                        pass
                except PyverbsError as ex:
                    assert 'Failed to create a CQ' in ex.args[0]
                    assert 'Invalid argument' in ex.args[0]
                else:
                    raise PyverbsError(
                        'Created a CQ with comp_vector={n} while device\'s num_comp_vectors={nc}'.
                        format(n=comp_vector, nc=ctx.num_comp_vectors))
                max_cqe = ctx.query_device().max_cqe
                cqes = random.randint(max_cqe + 1, max_cqe + 100)
                try:
                    with CQ(ctx, cqes, None, cc, 0):
                        pass
                except PyverbsError as ex:
                    assert 'Failed to create a CQ' in ex.args[0]
                    assert 'Invalid argument' in ex.args[0]
                else:
                    raise PyverbsError(
                        'Created a CQ with cqe={n} while device\'s max_cqe={nc}'.
                        format(n=cqes, nc=max_cqe))

    def test_destroy_cq(self):
        """
        Test ibv_destroy_cq()
        """
        for ctx, attr, attr_ex in self.devices:
            for i in range(10):
                cqes = get_num_cqes(attr)
                comp_vector = int(ctx.num_comp_vectors * random.random())
                if random.choice([True, False]):
                    with CompChannel(ctx) as cc:
                        cq = CQ(ctx, cqes, None, cc, comp_vector)
                else:
                    cq = CQ(ctx, cqes, None, None, comp_vector)
                cq.close()


class CCTest(PyverbsAPITestCase):
    """
    Test various functionalities of the Completion Channel class.
    """
    def test_create_comp_channel(self):
        """
        Test ibv_create_comp_channel()
        """
        for ctx, attr, attr_ex in self.devices:
            with CompChannel(ctx):
                pass

    def test_destroy_comp_channel(self):
        """
        Test ibv_destroy_comp_channel()
        """
        for ctx, attr, attr_ex in self.devices:
            cc = CompChannel(ctx)
            cc.close()


class CQEXTest(PyverbsAPITestCase):
    """
    Test various functionalities of the CQEX class.
    """
    def test_create_cq_ex(self):
        """
        Test ibv_create_cq_ex()
        """
        for ctx, attr, attr_ex in self.devices:
            cqe = get_num_cqes(attr)
            cq_init_attrs_ex = CqInitAttrEx(cqe=cqe, wc_flags=0, comp_mask=0, flags=0)
            wc_flags = get_cq_flags_with_caps()
            if attr_ex.raw_packet_caps & e.IBV_RAW_PACKET_CAP_CVLAN_STRIPPING == 0:
                wc_flags.remove(e.IBV_WC_EX_WITH_CVLAN)
            for f in wc_flags:
                cq_init_attrs_ex.wc_flags = f
                with CQEX(ctx, cq_init_attrs_ex):
                    pass
            # For the wc_flags that have no capability bit, we're not raising
            # an exception for EOPNOTSUPPORT
            wc_flags = get_cq_flags_with_no_caps()
            for f in wc_flags:
                cq_init_attrs_ex.wc_flags = f
                try:
                    with CQEX(ctx, cq_init_attrs_ex):
                        pass
                except PyverbsError as ex:
                    assert 'Failed to create extended CQ' in ex.args[0]
                    assert ' Errno: 95' in ex.args[0]
            cq_init_attrs_ex.wc_flags = 0
            cq_init_attrs_ex.comp_mask = e.IBV_CQ_INIT_ATTR_MASK_FLAGS
            attr_flags = list(e.ibv_create_cq_attr_flags)
            for f in attr_flags:
                cq_init_attrs_ex.flags = f
                try:
                    with CQEX(ctx, cq_init_attrs_ex):
                        pass
                except PyverbsError as ex:
                    assert 'Failed to create extended CQ' in ex.args[0]
                    assert ' Errno: 95' in ex.args[0]

    def test_create_cq_ex_bad_flow(self):
        """
        Test ibv_create_cq_ex() with wrong comp_vector / number of cqes
        """
        for ctx, attr, attr_ex in self.devices:
            for i in range(10):
                cq_attrs_ex = CqInitAttrEx(cqe=0, wc_flags=0, comp_mask=0, flags=0)
                max_cqe = attr.max_cqe
                cq_attrs_ex.cqe = max_cqe + 1 + int(100 * random.random())
                try:
                    CQEX(ctx, cq_attrs_ex)
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Create extended CQ is not supported')
                    assert 'Failed to create extended CQ' in ex.args[0]
                    assert ' Errno: 22' in ex.args[0]
                else:
                    raise PyverbsError(
                        'Created a CQEX with {c} CQEs while device\'s max CQE={dc}'.
                        format(c=cq_attrs_ex.cqe, dc=max_cqe))
                comp_channel = random.randint(ctx.num_comp_vectors, 100)
                cq_attrs_ex.comp_vector = comp_channel
                cq_attrs_ex.cqe = get_num_cqes(attr)
                try:
                    CQEX(ctx, cq_attrs_ex)
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Create extended CQ is not supported')
                    assert 'Failed to create extended CQ' in ex.args[0]
                    assert ' Errno: 22' in ex.args[0]
                else:
                    raise PyverbsError(
                        'Created a CQEX with comp_vector={c} while device\'s num_comp_vectors={dc}'.
                        format(c=comp_channel, dc=ctx.num_comp_vectors))

    def test_destroy_cq_ex(self):
        """
        Test ibv_destroy_cq() for extended CQs
        """
        for ctx, attr, attr_ex in self.devices:
            cqe = get_num_cqes(attr)
            cq_init_attrs_ex = CqInitAttrEx(cqe=cqe, wc_flags=0, comp_mask=0, flags=0)
            wc_flags = get_cq_flags_with_caps()
            if attr_ex.raw_packet_caps & e.IBV_RAW_PACKET_CAP_CVLAN_STRIPPING == 0:
                wc_flags.remove(e.IBV_WC_EX_WITH_CVLAN)
            for f in wc_flags:
                cq_init_attrs_ex.wc_flags = f
                with CQEX(ctx, cq_init_attrs_ex) as cq:
                    cq.close()
            # For the wc_flags that have no capability bit, we're not raising
            # an exception for EOPNOTSUPPORT
            wc_flags = get_cq_flags_with_no_caps()
            for f in wc_flags:
                cq_init_attrs_ex.wc_flags = f
                try:
                    with CQEX(ctx, cq_init_attrs_ex) as cq:
                        cq.close()
                except PyverbsError as ex:
                    assert 'Failed to create extended CQ' in ex.args[0]
                    assert ' Errno: 95' in ex.args[0]
            cq_init_attrs_ex.wc_flags = 0
            cq_init_attrs_ex.comp_mask = e.IBV_CQ_INIT_ATTR_MASK_FLAGS
            attr_flags = list(e.ibv_create_cq_attr_flags)
            for f in attr_flags:
                cq_init_attrs_ex.flags = f
                try:
                    with CQEX(ctx, cq_init_attrs_ex) as cq:
                        cq.close()
                except PyverbsError as ex:
                    assert 'Failed to create extended CQ' in ex.args[0]
                    assert ' Errno: 95' in ex.args[0]

def get_num_cqes(attr):
    max_cqe = attr.max_cqe
    return int((max_cqe + 1) * random.random())


def get_cq_flags_with_no_caps():
    wc_flags = list(e.ibv_create_cq_wc_flags)
    wc_flags.remove(e.IBV_WC_EX_WITH_CVLAN)
    return wc_flags


def get_cq_flags_with_caps():
    return [e.IBV_WC_EX_WITH_CVLAN]
