# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 HiSilicon Limited. All rights reserved.

import unittest
import random
import errno

from pyverbs.providers.hns.hnsdv import HnsContext, HnsDVContextAttr, \
    HnsDVQPInitAttr, HnsQP
from tests.base import RCResources, RDMATestCase, PyverbsAPITestCase
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
from pyverbs.qp import QPCap, QPInitAttrEx
import pyverbs.providers.hns.hns_enums as dve
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.mr import MR


HUAWEI_VENDOR_ID = 0x19e5

def is_hns_dev(ctx):
    dev_attrs = ctx.query_device()
    return dev_attrs.vendor_id == HUAWEI_VENDOR_ID


def skip_if_not_hns_dev(ctx):
    if not is_hns_dev(ctx):
        raise unittest.SkipTest('Can not run the test over non HNS device')


class HnsPyverbsAPITestCase(PyverbsAPITestCase):
    def setUp(self):
        super().setUp()
        skip_if_not_hns_dev(self.ctx)


class HnsRDMATestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        skip_if_not_hns_dev(d.Context(name=self.dev_name))


class HnsDcaResources(RCResources):
    def create_context(self):
        hnsdv_attr = HnsDVContextAttr(flags=dve.HNSDV_CONTEXT_FLAGS_DCA)
        try:
            self.ctx = HnsContext(hnsdv_attr, name=self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open hns context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening hns context is not supported')

    def create_qp_cap(self):
        return QPCap(100, 0, 10, 0)

    def create_qp_init_attr(self):
        return QPInitAttrEx(cap=self.create_qp_cap(), pd=self.pd, scq=self.cq,
                            rcq=self.cq, srq=self.srq, qp_type=e.IBV_QPT_RC,
                            comp_mask=e.IBV_QP_INIT_ATTR_PD,
                            sq_sig_all=1)

    def create_qps(self):
        # Create the DCA QPs.
        qp_init_attr = self.create_qp_init_attr()
        try:
            for _ in range(self.qp_count):
                attr = HnsDVQPInitAttr(comp_mask=dve.HNSDV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS,
                                       create_flags=dve.HNSDV_QP_CREATE_ENABLE_DCA_MODE)
                qp = HnsQP(self.ctx, qp_init_attr, attr)
                self.qps.append(qp)
                self.qps_num.append(qp.qp_num)
                self.psns.append(random.getrandbits(24))
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest(f'Create DCA QP is not supported')
            raise ex

    def create_mr(self):
        access = e.IBV_ACCESS_REMOTE_WRITE | e.IBV_ACCESS_LOCAL_WRITE
        self.mr = MR(self.pd, self.msg_size, access)
