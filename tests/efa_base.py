# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020-2025 Amazon.com, Inc. or its affiliates. All rights reserved.

import unittest
import random
import errno

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.cq import CqInitAttrEx
from pyverbs.qp import QPAttr, QPCap, QPInitAttrEx
import pyverbs.providers.efa.efa_enums as efa_enums
import pyverbs.providers.efa.efadv as efa
import pyverbs.device as d
from pyverbs.libibverbs_enums import ibv_qp_init_attr_mask, ibv_qp_type, ibv_qp_create_send_ops_flags,\
                                     ibv_access_flags, IBV_WC_STANDARD_FLAGS

from tests.base import PyverbsAPITestCase
from tests.base import TrafficResources
from tests.base import RDMATestCase
import tests.utils


AMAZON_VENDOR_ID = 0x1d0f


def is_efa_dev(ctx):
    dev_attrs = ctx.query_device()
    return dev_attrs.vendor_id == AMAZON_VENDOR_ID


def skip_if_not_efa_dev(ctx):
    if not is_efa_dev(ctx):
        raise unittest.SkipTest('Can not run the test over non EFA device')


class EfaAPITestCase(PyverbsAPITestCase):
    def setUp(self):
        super().setUp()
        skip_if_not_efa_dev(self.ctx)


class EfaRDMATestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        skip_if_not_efa_dev(d.Context(name=self.dev_name))


class SRDResources(TrafficResources):
    SRD_QKEY = 0x11111111
    SRD_PKEY_INDEX = 0
    def __init__(self, dev_name, ib_port, gid_index, send_ops_flags,
                 qp_count=1, required_dev_cap=None, wc_flags=0, qp_flags=0):
        self.send_ops_flags = send_ops_flags
        self.qp_flags = qp_flags
        self.required_dev_cap = required_dev_cap
        self.efa_wc_flags = wc_flags
        super().__init__(dev_name, ib_port, gid_index, qp_count=qp_count)

    def create_context(self):
        super().create_context()
        if self.required_dev_cap:
            with efa.EfaContext(name=self.ctx.name) as efa_ctx:
                if not efa_ctx.query_efa_device().device_caps & self.required_dev_cap:
                    miss_caps = efa.dev_cap_to_str(self.required_dev_cap)
                    raise unittest.SkipTest(f"Device caps doesn't support {miss_caps}")

    def create_qp_attr(self):
        attr = QPAttr(port_num=self.ib_port)
        attr.qkey = self.SRD_QKEY
        attr.pkey_index = self.SRD_PKEY_INDEX
        return attr

    def to_rts(self):
        attr = self.create_qp_attr()
        for i in range(self.qp_count):
            attr.dest_qp_num = self.rqps_num[i]
            attr.sq_psn = self.rpsns[i]
            self.qps[i].to_rts(attr)

    def create_qps(self):
        qp_cap = QPCap(max_recv_wr=self.num_msgs, max_send_wr=self.num_msgs, max_recv_sge=1,
                       max_send_sge=1)
        comp_mask = ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_PD
        if self.send_ops_flags:
            comp_mask |= ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
        qp_init_attr_ex = QPInitAttrEx(cap=qp_cap, qp_type=ibv_qp_type.IBV_QPT_DRIVER, scq=self.cq,
                                       rcq=self.cq, pd=self.pd, send_ops_flags=self.send_ops_flags,
                                       comp_mask=comp_mask)
        efa_init_attr_ex = efa.EfaQPInitAttr()
        efa_init_attr_ex.driver_qp_type = efa_enums.EFADV_QP_DRIVER_TYPE_SRD
        efa_init_attr_ex.flags |= self.qp_flags
        try:
            for _ in range(self.qp_count):
                qp = efa.SRDQPEx(self.ctx, qp_init_attr_ex, efa_init_attr_ex)
                self.qps.append(qp)
                self.qps_num.append(qp.qp_num)
                self.psns.append(random.getrandbits(24))
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Extended SRD QP is not supported on this device')
            raise ex

    def create_mr(self):
        additional_access_flags = 0
        if self.send_ops_flags == ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_READ:
            additional_access_flags = ibv_access_flags.IBV_ACCESS_REMOTE_READ
        elif self.send_ops_flags in [ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE, ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM]:
            additional_access_flags = ibv_access_flags.IBV_ACCESS_REMOTE_WRITE
        self.mr = tests.utils.create_custom_mr(self, additional_access_flags)

    def create_cq(self):
        if self.efa_wc_flags == 0:
            super().create_cq()
        else:
            cia = CqInitAttrEx(wc_flags=IBV_WC_STANDARD_FLAGS)
            efa_cia = efa.EfaDVCQInitAttr(wc_flags=self.efa_wc_flags)
            try:
                self.cq = efa.EfaCQ(self.ctx, cia, efa_cia)
            except PyverbsRDMAError as ex:
                if ex.error_code == errno.EOPNOTSUPP:
                    raise unittest.SkipTest('Create EFA DV CQ is not supported')
                raise ex
