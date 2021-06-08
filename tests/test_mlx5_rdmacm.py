# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia Corporation. All rights reserved. See COPYING file

import unittest
import errno

from pyverbs.providers.mlx5.mlx5dv import Mlx5DVQPInitAttr, Mlx5QP, \
    Mlx5DVDCInitAttr, Mlx5Context
from tests.test_rdmacm import CMAsyncConnection
from tests.mlx5_base import Mlx5PyverbsAPITestCase, Mlx5RDMACMBaseTest
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.srq import SRQ, SrqInitAttr, SrqAttr
import pyverbs.providers.mlx5.mlx5_enums as dve
from tests.base_rdmacm import AsyncCMResources
from pyverbs.qp import QPCap, QPInitAttrEx
from pyverbs.cmid import ConnParam
from tests.base import DCT_KEY
from pyverbs.addr import AH
import pyverbs.enums as e
from pyverbs.cq import CQ
import tests.utils as u


class DcCMConnection(CMAsyncConnection):
    """
    Implement RDMACM connection management for asynchronous CMIDs using DC as
    an external QP.
    """
    def create_cm_res(self, ip_addr, passive, **kwargs):
        self.cm_res = DcCMResources(addr=ip_addr, passive=passive, **kwargs)
        if passive:
            self.cm_res.create_cmid()
        else:
            for conn_idx in range(self.num_conns):
                self.cm_res.create_cmid(conn_idx)

    def _ext_qp_server_traffic(self):
        recv_wr = u.get_recv_wr(self.cm_res)
        for _ in range(self.cm_res.num_msgs):
            u.post_recv(self.cm_res, recv_wr)
        self.syncer.wait()
        for _ in range(self.cm_res.num_msgs):
            u.poll_cq(self.cm_res.cq)

    def _ext_qp_client_traffic(self):
        self.cm_res.remote_dct_num = self.cm_res.remote_qpn
        _, send_wr = u.get_send_elements(self.cm_res, self.cm_res.passive)
        ah = AH(self.cm_res.cmid.pd, attr=self.cm_res.remote_ah)
        self.syncer.wait()
        for send_idx in range(self.cm_res.num_msgs):
            dci_idx = send_idx % len(self.cm_res.qps)
            u.post_send_ex(self.cm_res, send_wr, e.IBV_QP_EX_WITH_SEND, ah=ah,
                           qp_idx=dci_idx)
            u.poll_cq(self.cm_res.cq)

    def disconnect(self):
        if self.cm_res.reserved_qp_num and self.cm_res.passive:
            Mlx5Context.reserved_qpn_dealloc(self.cm_res.child_id.context,
                                             self.cm_res.reserved_qp_num)
            self.cm_res.reserved_qp_num = 0
        super().disconnect()


class DcCMResources(AsyncCMResources):
    """
    DcCMResources class contains resources for RDMA CM asynchronous
    communication using DC as an external QP.
    """
    def __init__(self, addr=None, passive=None, **kwargs):
        """
        Init DcCMResources instance.
        :param addr: Local address to bind to.
        :param passive: Indicate if this CM is the passive CM.
        """
        super().__init__(addr=addr, passive=passive, **kwargs)
        self.srq = None
        self.remote_dct_num = None
        self.reserved_qp_num = 0

    def create_qp(self, conn_idx=0):
        """
        Create an RDMACM QP. If self.with_ext_qp is set, then an external CQ and
        DC QP will be created. In case that CQ is already created, it is used
        for the newly created QP.
        """
        try:
            if not self.passive:
                # Create the DCI QPs.
                cmid = self.cmids[conn_idx]
                self.create_cq(cmid)
                qp_init_attr = self.create_qp_init_attr(cmid, e.IBV_QP_EX_WITH_SEND)
                attr = Mlx5DVQPInitAttr(comp_mask=dve.MLX5DV_QP_INIT_ATTR_MASK_DC,
                                        dc_init_attr=Mlx5DVDCInitAttr())
                self.qps[conn_idx] = Mlx5QP(cmid.context, qp_init_attr, attr)

            if self.passive and conn_idx == 0:
                # Create the DCT QP only for the first connection.
                cmid = self.child_id
                self.create_cq(cmid)
                self.create_srq(cmid)
                qp_init_attr = self.create_qp_init_attr(cmid)
                dc_attr = Mlx5DVDCInitAttr(dc_type=dve.MLX5DV_DCTYPE_DCT,
                                           dct_access_key=DCT_KEY)
                attr = Mlx5DVQPInitAttr(comp_mask=dve.MLX5DV_QP_INIT_ATTR_MASK_DC,
                                        dc_init_attr=dc_attr)
                self.qps[conn_idx] = Mlx5QP(cmid.context, qp_init_attr, attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create DC QP is not supported')
            raise ex

    def create_qp_cap(self):
        return QPCap(self.num_msgs, 0, 1, 0)

    def create_qp_init_attr(self, cmid, send_ops_flags=0):
        comp_mask = e.IBV_QP_INIT_ATTR_PD
        if send_ops_flags:
            comp_mask |= e.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
        return QPInitAttrEx(cap=self.create_qp_cap(), pd=cmid.pd, scq=self.cq,
                            rcq=self.cq, srq=self.srq, qp_type=e.IBV_QPT_DRIVER,
                            send_ops_flags=send_ops_flags, comp_mask=comp_mask,
                            sq_sig_all=1)

    def create_srq(self, cmid):
        srq_init_attr = SrqInitAttr(SrqAttr(max_wr=self.num_msgs))
        try:
            self.srq = SRQ(cmid.pd, srq_init_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create SRQ is not supported')
            raise ex

    def modify_ext_qp_to_rts(self, conn_idx=0):
        cmids = self.child_ids if self.passive else self.cmids
        if not self.passive or not conn_idx:
            qp = self.qps[conn_idx]
            attr, _ = cmids[conn_idx].init_qp_attr(e.IBV_QPS_INIT)
            qp.to_init(attr)
            attr, _ = cmids[conn_idx].init_qp_attr(e.IBV_QPS_RTR)
            qp.to_rtr(attr)
            if not self.passive:
                # The passive QP is DCT which should stay in RTR state.
                self.remote_ah = attr.ah_attr
                attr, _ = cmids[conn_idx].init_qp_attr(e.IBV_QPS_RTS)
                qp.to_rts(attr)

    def create_conn_param(self, qp_num=0, conn_idx=0):
        if conn_idx and self.passive:
            try:
                ctx = self.child_id.context
                self.reserved_qp_num = Mlx5Context.reserved_qpn_alloc(ctx)
            except PyverbsRDMAError as ex:
                if ex.error_code == errno.EOPNOTSUPP:
                    raise unittest.SkipTest('Alloc reserved QP number is not supported')
                raise ex
            qp_num = self.reserved_qp_num
        else:
            qp_num = self.qps[conn_idx].qp_num
        return ConnParam(qp_num=qp_num)


class Mlx5CMTestCase(Mlx5RDMACMBaseTest):
    """
    Mlx5 RDMACM test class.
    """
    def test_rdmacm_async_traffic_dc_external_qp(self):
        """
        Connect multiple RDMACM connections using DC as an external QP for
        traffic.
        """
        self.two_nodes_rdmacm_traffic(DcCMConnection, self.rdmacm_traffic,
                                      with_ext_qp=True, num_conns=2)


class ReservedQPTest(Mlx5PyverbsAPITestCase):

    def test_reservered_qpn(self):
        """
        Alloc reserved qpn multiple times and then dealloc the qpns. In addition,
        the test includes bad flows where a fake qpn gets deallocated, and a
        real qpn gets deallocated twice.
        """
        try:
            # Alloc qp number multiple times.
            qpns = []
            for i in range(1000):
                qpns.append(Mlx5Context.reserved_qpn_alloc(self.ctx))
            for i in range(1000):
                Mlx5Context.reserved_qpn_dealloc(self.ctx, qpns[i])

            # Dealloc qp number that was not allocated.
            qpn = Mlx5Context.reserved_qpn_alloc(self.ctx)
            with self.assertRaises(PyverbsRDMAError) as ex:
                fake_qpn = qpn - 1
                Mlx5Context.reserved_qpn_dealloc(self.ctx, fake_qpn)
            self.assertEqual(ex.exception.error_code, errno.EINVAL)

            # Try to dealloc same qp number twice.
            Mlx5Context.reserved_qpn_dealloc(self.ctx, qpn)
            with self.assertRaises(PyverbsRDMAError) as ex:
                Mlx5Context.reserved_qpn_dealloc(self.ctx, qpn)
            self.assertEqual(ex.exception.error_code, errno.EINVAL)

        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Alloc reserved QP number is not supported')
            raise ex
