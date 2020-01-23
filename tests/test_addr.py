# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file

import unittest
import errno

from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from pyverbs.addr import GlobalRoute, AHAttr, AH
from tests.base import PyverbsAPITestCase
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.pd import PD
from pyverbs.cq import WC


class AHTest(PyverbsAPITestCase):
    """
    Test various functionalities of the AH class.
    """
    def test_create_ah(self):
        """
        Test ibv_create_ah.
        """
        done = 0
        for ctx, attr, attr_ex in self.devices:
            pd = PD(ctx)
            for port_num in range(1, 1 + attr.phys_port_cnt):
                state = ctx.query_port(port_num).state
                if state != e.IBV_PORT_ACTIVE and state != e.IBV_PORT_INIT:
                    continue
                gr = get_global_route(ctx, port_num=port_num)
                ah_attr = AHAttr(gr=gr, is_global=1, port_num=port_num)
                try:
                    with AH(pd, attr=ah_attr):
                        done += 1
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Create AH is not supported')
                    raise ex
        if done == 0:
            raise unittest.SkipTest('No port is up, can\'t create AH')
    # TODO: Test ibv_create_ah_from_wc once we have traffic

    def test_create_ah_roce(self):
        """
        Verify that AH can't be created without GRH in RoCE
        """
        done = 0
        for ctx, attr, attr_ex in self.devices:
            pd = PD(ctx)
            for port_num in range(1, 1 + attr.phys_port_cnt):
                port_attr = ctx.query_port(port_num)
                if port_attr.state != e.IBV_PORT_ACTIVE and \
                   port_attr.state != e.IBV_PORT_INIT:
                    continue
                if port_attr.link_layer == e.IBV_LINK_LAYER_INFINIBAND:
                    raise unittest.SkipTest('Can\'t run RoCE tests on IB link layer')
                ah_attr = AHAttr(is_global=0, port_num=port_num)
                try:
                    ah = AH(pd, attr=ah_attr)
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Create AH is not supported')
                    assert 'Failed to create AH' in str(ex)
                    done +=1
                else:
                    raise PyverbsError('Created a non-global AH on RoCE')
        if done == 0:
            raise unittest.SkipTest('No port is up, can\'t create AH')

    def test_destroy_ah(self):
        """
        Test ibv_destroy_ah.
        """
        done = 0
        for ctx, attr, attr_ex in self.devices:
            pd = PD(ctx)
            for port_num in range(1, 1 + attr.phys_port_cnt):
                state = ctx.query_port(port_num).state
                if state != e.IBV_PORT_ACTIVE and state != e.IBV_PORT_INIT:
                    continue
                gr = get_global_route(ctx)
                ah_attr = AHAttr(gr=gr, is_global=1, port_num=port_num)
                try:
                    with AH(pd, attr=ah_attr) as ah:
                        ah.close()
                        done += 1
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Create AH is not supported')
                    raise ex
        if done == 0:
            raise unittest.SkipTest('No port is up, can\'t create AH')


def get_global_route(ctx, gid_index=0, port_num=1):
    """
    Queries the provided Context's gid <gid_index> and creates a GlobalRoute
    object with sgid_index <gid_index> and the queried GID as dgid.
    :param ctx: Context object to query
    :param gid_index: GID index to query and use. Default: 0, as it's always
                      valid
    :param port_num: Number of the port to query. Default: 1
    :return: GlobalRoute object
    """
    gid = ctx.query_gid(port_num, gid_index)
    gr = GlobalRoute(dgid=gid, sgid_index=gid_index)
    return gr
