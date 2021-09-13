# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.
"""
Test module for efa direct-verbs.
"""

import unittest
import random
import errno

import pyverbs.providers.efa.efa_enums as efa_e
from pyverbs.base import PyverbsRDMAError
import pyverbs.providers.efa.efadv as efa
from pyverbs.qp import QPInitAttrEx
from pyverbs.addr import AHAttr
from pyverbs.cq import CQ
import pyverbs.enums as e
from pyverbs.pd import PD

from tests.efa_base import EfaAPITestCase
import tests.utils as u



class EfaQueryDeviceTest(EfaAPITestCase):
    """
    Test various functionalities of the direct verbs class.
    """
    def test_efadv_query(self):
        """
        Verify that it's possible to read EFA direct-verbs.
        """
        with efa.EfaContext(name=self.ctx.name) as efa_ctx:
            try:
                efa_attrs = efa_ctx.query_efa_device()
                if self.config['verbosity']:
                    print(f'\n{efa_attrs}')
            except PyverbsRDMAError as ex:
                if ex.error_code == errno.EOPNOTSUPP:
                    raise unittest.SkipTest('Not supported on non EFA devices')
                raise ex


class EfaAHTest(EfaAPITestCase):
    """
    Test functionality of the EfaAH class
    """
    def test_efadv_query_ah(self):
        """
        Test efadv_query_ah()
        """
        pd = PD(self.ctx)
        try:
            gr = u.get_global_route(self.ctx, port_num=self.ib_port)
            ah_attr = AHAttr(gr=gr, is_global=1, port_num=self.ib_port)
            ah = efa.EfaAH(pd, attr=ah_attr)
            query_ah_attr = ah.query_efa_ah()
            if self.config['verbosity']:
                print(f'\n{query_ah_attr}')
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Not supported on non EFA devices')
            raise ex


class EfaQPTest(EfaAPITestCase):
    """
    Test SRD QP class
    """
    def test_efadv_create_driver_qp(self):
        """
        Test efadv_create_driver_qp()
        """
        with PD(self.ctx) as pd:
            with CQ(self.ctx, 100) as cq:
                qia = u.get_qp_init_attr(cq, self.attr)
                qia.qp_type = e.IBV_QPT_DRIVER
                try:
                    qp = efa.SRDQP(pd, qia)
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest("Create SRD QP is not supported")
                    raise ex


class EfaQPExTest(EfaAPITestCase):
    """
    Test SRD QPEx class
    """
    def test_efadv_create_qp_ex(self):
        """
        Test efadv_create_qp_ex()
        """
        with PD(self.ctx) as pd:
            with CQ(self.ctx, 100) as cq:
                qiaEx = get_qp_init_attr_ex(cq, pd, self.attr)
                efaqia = efa.EfaQPInitAttr()
                efaqia.driver_qp_type = efa_e.EFADV_QP_DRIVER_TYPE_SRD
                try:
                    qp = efa.SRDQPEx(self.ctx, qiaEx, efaqia)
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest("Create SRD QPEx is not supported")
                    raise ex


def get_random_send_op_flags():
    send_ops_flags = [e.IBV_QP_EX_WITH_SEND,
                      e.IBV_QP_EX_WITH_SEND_WITH_IMM,
                      e.IBV_QP_EX_WITH_RDMA_READ]
    selected = u.sample(send_ops_flags)
    selected_ops_flags = 0
    for s in selected:
        selected_ops_flags += s.value
    return selected_ops_flags

def get_qp_init_attr_ex(cq, pd, attr):
    qp_cap = u.random_qp_cap(attr)
    sig = random.randint(0, 1)
    mask = e.IBV_QP_INIT_ATTR_PD | e.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
    send_ops_flags = get_random_send_op_flags()
    qia = QPInitAttrEx(qp_type=e.IBV_QPT_DRIVER, cap=qp_cap, sq_sig_all=sig, comp_mask=mask,
                       create_flags=0, max_tso_header=0, send_ops_flags=send_ops_flags)
    qia.send_cq = cq
    qia.recv_cq = cq
    qia.pd = pd
    return qia
