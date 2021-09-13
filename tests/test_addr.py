# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.  See COPYING file

import unittest
import errno

from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from tests.base import PyverbsAPITestCase
from pyverbs.addr import AHAttr, AH
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.pd import PD
import tests.utils as u


class AHTest(PyverbsAPITestCase):
    """
    Test various functionalities of the AH class.
    """
    def verify_link_layer_ether(self, ctx):
        """
        Aux function to verify link layer
        """
        link_layer = ctx.query_port(self.ib_port).link_layer
        if link_layer != e.IBV_LINK_LAYER_ETHERNET:
            raise unittest.SkipTest(f'Link layer of port={self.ib_port} is {d.translate_link_layer(link_layer)} , skip RoCE test')

    def verify_state(self, ctx):
        """
        Aux function to verify port state
        """
        state = ctx.query_port(self.ib_port).state
        if state != e.IBV_PORT_ACTIVE and state != e.IBV_PORT_INIT:
            raise unittest.SkipTest(f'Port {self.ib_port} is not up, can not create AH')

    def test_create_ah(self):
        """
        Test ibv_create_ah.
        """
        self.verify_state(self.ctx)
        gr = u.get_global_route(self.ctx, port_num=self.ib_port)
        port_attrs = self.ctx.query_port(self.ib_port)
        dlid = port_attrs.lid if port_attrs.link_layer == e.IBV_LINK_LAYER_INFINIBAND else 0
        ah_attr = AHAttr(dlid=dlid, gr=gr, is_global=1, port_num=self.ib_port)
        pd = PD(self.ctx)
        try:
            AH(pd, attr=ah_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create AH is not supported')
            raise ex

    def test_create_ah_roce(self):
        """
        Verify that AH can't be created without GRH in RoCE
        """
        self.verify_link_layer_ether(self.ctx)
        self.verify_state(self.ctx)
        pd = PD(self.ctx)
        ah_attr = AHAttr(is_global=0, port_num=self.ib_port)
        try:
            AH(pd, attr=ah_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create AH is not supported')
            assert 'Failed to create AH' in str(ex)
        else:
            raise PyverbsError(f'Successfully created a non-global AH on RoCE port={self.ib_port}')

    def test_destroy_ah(self):
        """
        Test ibv_destroy_ah.
        """
        self.verify_state(self.ctx)
        gr = u.get_global_route(self.ctx, port_num=self.ib_port)
        port_attrs = self.ctx.query_port(self.ib_port)
        dlid = port_attrs.lid if port_attrs.link_layer == e.IBV_LINK_LAYER_INFINIBAND else 0
        ah_attr = AHAttr(dlid=dlid, gr=gr, is_global=1, port_num=self.ib_port)
        pd = PD(self.ctx)
        try:
            with AH(pd, attr=ah_attr) as ah:
                ah.close()
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create AH is not supported')
            raise ex
