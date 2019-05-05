# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for pyverbs' cq module.
"""
import random

from pyverbs.cq import CompChannel, CQ, CqInitAttrEx, CQEX
from pyverbs.pyverbs_error import PyverbsError
from pyverbs.tests.base import PyverbsTestCase
import pyverbs.tests.utils as u
import pyverbs.enums as e


class CQTest(PyverbsTestCase):
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
                    with CQ(ctx, cqes, None, cc, 0):
                        pass
                except PyverbsError as err:
                    assert 'Failed to create a CQ' in err.args[0]
                    assert 'Invalid argument' in err.args[0]
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


class CCTest(PyverbsTestCase):
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


class CQEXTest(PyverbsTestCase):
    """
    Test various functionalities of the CQEX class.
    """
    def test_create_cq_ex(self):
        """
        Test ibv_create_cq_ex()
        """
        for ctx, attr, attr_ex in self.devices:
            for i in range(10):
                with CQEX(ctx, get_attrs_ex(attr, attr_ex)):
                    pass

    def test_create_cq_ex_bad_flow(self):
        """
        Test ibv_create_cq_ex() with wrong comp_vector / number of cqes
        """
        for ctx, attr, attr_ex in self.devices:
            for i in range(10):
                cq_attrs_ex = get_attrs_ex(attr, attr_ex)
                max_cqe = attr.max_cqe
                cq_attrs_ex.cqe = max_cqe + 1 + int(100 * random.random())
                try:
                    CQEX(ctx, cq_attrs_ex)
                except PyverbsError as e:
                    assert 'Failed to create extended CQ' in e.args[0]
                    assert ' Errno: 22' in e.args[0]
                else:
                    raise PyverbsError(
                        'Created a CQEX with {c} CQEs while device\'s max CQE={dc}'.
                        format(c=cq_attrs_ex.cqe, dc=max_cqe))
                comp_channel = random.randint(ctx.num_comp_vectors, 100)
                cq_attrs_ex.comp_vector = comp_channel
                cq_attrs_ex.cqe = get_num_cqes(attr)
                try:
                    CQEX(ctx, cq_attrs_ex)
                except PyverbsError as e:
                    assert 'Failed to create extended CQ' in e.args[0]
                    assert ' Errno: 22' in e.args[0]
                else:
                    raise PyverbsError(
                        'Created a CQEX with comp_vector={c} while device\'s num_comp_vectors={dc}'.
                        format(c=comp_channel, dc=ctx.num_comp_vectors))

    def test_destroy_cq_ex(self):
        """
        Test ibv_destroy_cq() for extended CQs
        """
        for ctx, attr, attr_ex in self.devices:
            for i in range(10):
                with CQEX(ctx, get_attrs_ex(attr, attr_ex)) as cq:
                    cq.close()

def get_num_cqes(attr):
    max_cqe = attr.max_cqe
    return int((max_cqe + 1) * random.random())


def get_attrs_ex(attr, attr_ex):
    cqe = get_num_cqes(attr)
    wc_flags = list(e.ibv_create_cq_wc_flags)
    # Flow tag is not always supported, doesn't have a capability bit to check
    wc_flags.remove(e.IBV_WC_EX_WITH_FLOW_TAG)
    if attr_ex.tm_caps.max_ops == 0:
        wc_flags.remove(e.IBV_WC_EX_WITH_TM_INFO)
    if attr_ex.raw_packet_caps & e.IBV_RAW_PACKET_CAP_CVLAN_STRIPPING == 0:
        wc_flags.remove(e.IBV_WC_EX_WITH_CVLAN)
    sample = u.sample(wc_flags)
    wc_flags = 0
    for flag in sample:
        wc_flags |= flag
    comp_mask = random.choice([0, e.IBV_CQ_INIT_ATTR_MASK_FLAGS])
    flags = 0
    if comp_mask is not 0:
        attr_flags = list(e.ibv_create_cq_attr_flags)
        sample = u.sample(attr_flags)
        for flag in sample:
            flags |= flag
    return CqInitAttrEx(cqe=cqe, wc_flags=wc_flags, comp_mask=comp_mask,
                        flags=flags)
