# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.
"""
Test module for efa direct-verbs.
"""

import errno
from pyverbs.addr import AHAttr
from pyverbs.base import PyverbsRDMAError
from pyverbs.cq import CQ
import pyverbs.enums as e
from pyverbs.pd import PD
import pyverbs.providers.efa.efadv as efa
from tests.base import PyverbsAPITestCase
import tests.utils as u
import unittest


class EfaQueryDeviceTest(PyverbsAPITestCase):
    """
    Test various functionalities of the direct verbs class.
    """
    def test_efadv_query(self):
        """
        Verify that it's possible to read EFA direct-verbs.
        """
        for ctx, attr, attr_ex in self.devices:
            with efa.EfaContext(name=ctx.name) as efa_ctx:
                try:
                    efa_attrs = efa_ctx.query_efa_device()
                    if self.config['verbosity']:
                        print(f'\n{efa_attrs}')
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Not supported on non EFA devices')
                    raise ex


class EfaAHTest(PyverbsAPITestCase):
    """
    Test functionality of the EfaAH class
    """
    def test_efadv_query_ah(self):
        """
        Test efadv_query_ah()
        """
        for ctx, attr, attr_ex in self.devices:
            pd = PD(ctx)
            try:
                gr = u.get_global_route(ctx, port_num=1)
                ah_attr = AHAttr(gr=gr, is_global=1, port_num=1)
                ah = efa.EfaAH(pd, attr=ah_attr)
                query_ah_attr = ah.query_efa_ah()
                if self.config['verbosity']:
                    print(f'\n{query_ah_attr}')
            except PyverbsRDMAError as ex:
                if ex.error_code == errno.EOPNOTSUPP:
                    raise unittest.SkipTest('Not supported on non EFA devices')
                raise ex


class EfaQPTest(PyverbsAPITestCase):
    """
    Test SRD QP class
    """
    def test_efadv_create_driver_qp(self):
        """
        Test efadv_create_driver_qp()
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100) as cq:
                    qia = u.get_qp_init_attr(cq, attr)
                    qia.qp_type = e.IBV_QPT_DRIVER
                    try:
                        qp = efa.SRDQP(pd, qia)
                    except PyverbsRDMAError as ex:
                        if ex.error_code == errno.EOPNOTSUPP:
                            raise unittest.SkipTest("Create SRD QP is not supported")
                        raise ex
