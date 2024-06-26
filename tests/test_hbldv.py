# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2022-2024 HabanaLabs, Ltd.
# Copyright (C) 2023-2024, Intel Corporation.
# All Rights Reserved.

"""
Test module for hbl direct-verbs.
"""

import errno
import unittest
import struct
import ctypes

from pyverbs.providers.hbl.hbldv import (
    HblDVUserFIFOAttr, HblDVCQattr, HblDVQueryCQ, HblDVCQ, HblDVPortAttr, HblDVQP,
    HblDVQueryQP, HblDVEncap, HblDVEncapAttr, HblDVEncapOut, HblDVModifyQP
)

from pyverbs.base import PyverbsRDMAError
from pyverbs.pyverbs_error import PyverbsUserError
import pyverbs.providers.hbl.hbldv as hbl
import pyverbs.providers.hbl.hbl_enums as hbl_e
from pyverbs.cq import CQ
from pyverbs.pd import PD
import pyverbs.enums as e
from pyverbs.qp import QPInitAttr, QPAttr

from tests.hbl_base import HblAPITestCase


class HblUserFIFOTest(HblAPITestCase):
    """
    Test functionality of the Hbl user FIFO class
    """
    def test_hbldv_usr_fifo(self):
        """
        Test hbldv_usr_fifo()
        """
        try:
            attr = HblDVUserFIFOAttr()
            attr.port_num = self.ib_port
            usr_fifo = hbl.HblDVUserFIFO()
            usr_fifo.create_usr_fifo(self.ctx, attr)
            usr_fifo.destroy_usr_fifo()
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Not supported on non hbl devices')
            raise ex

class HblCQTest(HblAPITestCase):
    """
    Test functionality of the Hbl CQ class
    """
    def test_hbldv_create_cq(self):
        """
        Test hbldv_create_cq()
        """
        try:
            num_cqes = 512
            cq_attr = HblDVCQattr()
            cq_attr.port_num = self.ib_port
            cq_attr.cq_type = 0
            cq_obj = HblDVCQ()
            cq_obj.create_cq(self.ctx, num_cqes, cq_attr)
            cq_obj.destroy_cq()
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Not supported on non hbl devices')
            raise ex

    def test_hbldv_query_cq(self):
        """
        Test hbldv_query_cq()
        """
        try:
            num_cqes = 512
            cq_attr = HblDVCQattr()
            cq_attr.port_num = self.ib_port
            cq_attr.cq_type = 0
            cq_obj = HblDVCQ()
            cq_obj.create_cq(self.ctx, num_cqes, cq_attr)
            query_cq_obj = HblDVQueryCQ()
            cq_obj.query_cq(query_cq_obj)
            cq_obj.destroy_cq()
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Not supported on non hbl devices')
            raise ex

class HblQueryPortTest(HblAPITestCase):
    """
    Test functionality of the Hbl Query port class
    """
    def test_hbldv_query_port(self):
        """
        Test hbldv_query_port()
        """
        try:
            attr = HblDVPortAttr()
            port = hbl.HblQueryPort()
            port.query_port(self.ctx, self.ib_port, attr)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Not supported on non hbl devices')
            raise ex

class HblQPTest(HblAPITestCase):
    """
    Test functionality of the Hbl Query QP class
    """
    def test_hbldv_modify_qp(self):
        """
        Test hbldv_modify_qp()
        """
        try:
            pd_obj = PD(self.ctx)
            cq_obj = CQ(self.ctx, 512)
            qp_init_obj = QPInitAttr(e.IBV_QPT_RC, None, cq_obj, cq_obj)
            qp_obj = HblDVQP()
            qp_obj.create_qp(pd_obj, qp_init_obj)
            qp_attr_obj = QPAttr()
            qp_attr_obj.qp_state = e.IBV_QPS_INIT
            qp_attr_obj.port_num = self.ib_port
            qp_attr_obj.pkey_index = 0
            qp_modify_attr = HblDVModifyQP()
            qp_modify_attr.wq_type = 1
            qp_obj.modify_qp(qp_attr_obj,
                             e.IBV_QP_STATE | e.IBV_QP_PKEY_INDEX |
                             e.IBV_QP_PORT | e.IBV_QP_ACCESS_FLAGS, qp_modify_attr)
            qp_obj.destroy_qp()
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Not supported on non hbl devices')
            raise ex

    def test_hbldv_query_qp(self):
        """
        Test hbldv_query_qp()
        """
        try:
            cq_obj = CQ(self.ctx, 512)
            pd_obj = PD(self.ctx)
            qp_init_obj = QPInitAttr(e.IBV_QPT_RC, None, cq_obj, cq_obj)
            qp_obj = HblDVQP()
            qp_obj.create_qp(pd_obj, qp_init_obj)
            qp_attr_obj = QPAttr()
            qp_attr_obj.qp_state = e.IBV_QPS_INIT
            qp_attr_obj.port_num = self.ib_port
            qp_attr_obj.pkey_index = 0
            qp_modify_attr = HblDVModifyQP()
            qp_modify_attr.wq_type = 1
            qp_obj.modify_qp(qp_attr_obj, e.IBV_QP_STATE | e.IBV_QP_PKEY_INDEX | e.IBV_QP_PORT | e.IBV_QP_ACCESS_FLAGS, qp_modify_attr)
            query_qp_obj = HblDVQueryQP()
            qp_obj.query_qp(query_qp_obj)
            qp_obj.destroy_qp()
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Not supported on non hbl devices')
            raise ex

class HblCCCQTest(HblAPITestCase):
    """
    Test functionality of the Hbl CC CQ class
    """
    def test_hbldv_create_cq(self):
        """
        Test hbldv_create_cq() for CC
        """
        if not self.ctx.query_hbl_device().caps & hbl_e.HBLDV_DEVICE_ATTR_CAP_CC:
            raise unittest.SkipTest('Test not supported on this device')
        try:
            num_cqes = 512
            cq_attr = HblDVCQattr()
            cq_attr.port_num = self.ib_port
            cq_attr.cq_type = 1
            cq_obj = HblDVCQ()
            cq_obj.create_cq(self.ctx, num_cqes, cq_attr)
            cq_obj.destroy_cq()
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Not supported on non hbl devices')
            raise ex

    def test_hbldv_query_cq(self):
        """
        Test hbldv_query_cq() for CC
        """
        if not self.ctx.query_hbl_device().caps & hbl_e.HBLDV_DEVICE_ATTR_CAP_CC:
            raise unittest.SkipTest('Test not supported on this device')
        try:
            num_cqes = 512
            cq_attr = HblDVCQattr()
            cq_attr.port_num = self.ib_port
            cq_attr.cq_type = 1
            cq_obj = HblDVCQ()
            cq_obj.create_cq(self.ctx, num_cqes, cq_attr)
            query_cq_obj = HblDVQueryCQ()
            cq_obj.query_cq(query_cq_obj)
            cq_obj.destroy_cq()
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Not supported on non hbl devices')
            raise ex

class HblEncapTest(HblAPITestCase):
    """
    Test functionality of the Hbl Encap class
    """
    def test_hbldv_create_encap(self):
        """
        Test hbldv_create_encap()
        """
        try:
            encap_attr = HblDVEncapAttr()
            encap_attr.port_num = self.ib_port
            encap_attr.encap_type = 2
            encap_out = HblDVEncapOut()
            encap_obj = HblDVEncap()
            encap_attr.tnl_hdr_size = 32
            encap_obj.create_encap(self.ctx, encap_attr, encap_out)
            encap_obj.destroy_encap()
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Not supported on non hbl devices')
            raise ex
