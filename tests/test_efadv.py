# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020-2025 Amazon.com, Inc. or its affiliates. All rights reserved.
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
from pyverbs.libibverbs_enums import ibv_qp_type, ibv_qp_create_send_ops_flags, ibv_qp_init_attr_mask, \
    ibv_wr_opcode, ibv_access_flags
from pyverbs.pd import PD
from pyverbs import mem_alloc as mem

from tests.efa_base import EfaAPITestCase, EfaRDMATestCase, SRDResources
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
                qia.qp_type = ibv_qp_type.IBV_QPT_DRIVER
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
    send_ops_flags = [ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND,
                      ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND_WITH_IMM,
                      ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_READ,
                      ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE,
                      ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM]
    selected = u.sample(send_ops_flags)
    selected_ops_flags = 0
    for s in selected:
        selected_ops_flags += s.value
    return selected_ops_flags

def get_qp_init_attr_ex(cq, pd, attr):
    qp_cap = u.random_qp_cap(attr)
    sig = random.randint(0, 1)
    mask = ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_PD | ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
    send_ops_flags = get_random_send_op_flags()
    qia = QPInitAttrEx(qp_type=ibv_qp_type.IBV_QPT_DRIVER, cap=qp_cap, sq_sig_all=sig, comp_mask=mask,
                       create_flags=0, max_tso_header=0, send_ops_flags=send_ops_flags)
    qia.send_cq = cq
    qia.recv_cq = cq
    qia.pd = pd
    return qia


class EfaCqTest(EfaRDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 100
        self.server = None
        self.client = None

    def create_players(self, dev_cap, wc_flags, send_ops_flags, qp_count=8):
        super().create_players(SRDResources, send_ops_flags=send_ops_flags, qp_count=qp_count,
                               required_dev_cap=dev_cap, wc_flags=wc_flags)
        self.server.remote_gid = self.client.ctx.query_gid(self.client.ib_port, self.client.gid_index)

    def test_dv_cq_ex_with_sgid(self):
        wc_flag = efa_e.EFADV_WC_EX_WITH_SGID
        dev_cap = efa_e.EFADV_DEVICE_ATTR_CAPS_CQ_WITH_SGID
        self.create_players(dev_cap, wc_flag, ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND, qp_count=1)
        recv_wr = u.get_recv_wr(self.server)
        self.server.qps[0].post_recv(recv_wr)
        ah_client = u.get_global_ah(self.client, self.gid_index, self.ib_port)
        _ , sg = u.get_send_elements(self.client, False)
        u.send(self.client, sg, ibv_wr_opcode.IBV_WR_SEND, new_send=True, qp_idx=0, ah=ah_client)
        u.poll_cq_ex(self.client.cq)
        u.poll_cq_ex(self.server.cq, sgid=self.server.remote_gid)


class EfaMRTest(EfaAPITestCase):
    """
    Test various functionalities of the EfaMR class.
    """
    def test_efadv_query_mr(self):
        with PD(self.ctx) as pd:
            try:
                mr = efa.EfaMR(pd, 16, ibv_access_flags.IBV_ACCESS_LOCAL_WRITE)
                mr_attrs = mr.query()
                if self.config['verbosity']:
                    print(f'\n{mr_attrs}')

                assert(mr_attrs.ic_id_validity & ~(efa_e.EFADV_MR_ATTR_VALIDITY_RECV_IC_ID |
                                                   efa_e.EFADV_MR_ATTR_VALIDITY_RDMA_READ_IC_ID |
                                                   efa_e.EFADV_MR_ATTR_VALIDITY_RDMA_RECV_IC_ID) == 0)
            except PyverbsRDMAError as ex:
                if ex.error_code in [errno.EOPNOTSUPP, errno.ENOTTY, errno.EPROTONOSUPPORT]:
                    raise unittest.SkipTest(f'Query MR not supported, errno={ex.error_code}')
                raise ex


# Entry sizes a memory completion action accepts
MEM_MODIFY_SIZES = [1, 2, 4]

EXHAUSTION_TEST_LIMIT = 4096


class EfaCompActionTestCase(EfaAPITestCase):
    """Base class for completion action tests. Skips if not supported."""
    def setUp(self):
        super().setUp()
        self.efa_ctx = efa.EfaContext(name=self.ctx.name)
        self.dev_attrs = self.efa_ctx.query_efa_device()
        self.bufs = []
        if not (self.dev_attrs.device_caps &
                efa_e.EFADV_DEVICE_ATTR_CAPS_COMP_ACTION):
            # tearDown is not called when setUp raises; close explicitly so
            # the contexts don't linger to interpreter-exit finalization
            self.efa_ctx.close()
            self.ctx.close()
            raise unittest.SkipTest('Completion actions not supported')
        self.pd = PD(self.efa_ctx)

    def tearDown(self):
        self.pd.close()
        self.efa_ctx.close()
        for buf in self.bufs:
            mem.free(buf)
        super().tearDown()

    def alloc_buf(self, size=8, alignment=8):
        buf = mem.posix_memalign(size, alignment)
        self.bufs.append(buf)
        return buf

    def create_action(self, pd=None, mem_modify_size=4, mem_size=None, buf=None,
                      comp_mem_modify_type=efa_e.EFADV_MEM_COMP_ACTION_SET_INITIATOR_VAL):
        if buf is None:
            buf = self.alloc_buf()
        attr = efa.EfaMemCompActionInitAttr(pd=pd or self.pd, comp_mem_modify_type=comp_mem_modify_type,
                                            mem_modify_size=mem_modify_size,
                                            mem_size=mem_size,
                                            comp_mem_ptr=buf)
        return efa.EfaCompAction(self.efa_ctx, attr)


class EfaCompActionCapsTest(EfaCompActionTestCase):
    def test_caps_consistency(self):
        """COMP_ACTION implies completion action resources."""
        self.assertGreater(self.dev_attrs.max_comp_actions, 0,
                           'Completion actions supported but max_comp_actions is 0')
        write_ops = (efa_e.EFADV_DEVICE_ATTR_COMP_ACTION_SUPPORTED_OP_RDMA_WRITE |
                     efa_e.EFADV_DEVICE_ATTR_COMP_ACTION_SUPPORTED_OP_REMOTE_RDMA_WRITE)
        self.assertEqual(self.dev_attrs.comp_action_supp_ops & write_ops, write_ops,
                         'Completion actions supported but RDMA write is not a supported op')


class EfaCompActionTest(EfaCompActionTestCase):
    def test_create_destroy_mem_modify_sizes(self):
        """Create and destroy an action of each supported memory modification size."""
        for mem_modify_size in MEM_MODIFY_SIZES:
            action = self.create_action(mem_modify_size=mem_modify_size)
            action.close()

    def test_distinct_ids(self):
        """Action ids are distinct across live actions."""
        actions = [self.create_action() for _ in range(2)]
        self.assertNotEqual(actions[0].action_id, actions[1].action_id)
        for action in actions:
            action.close()

    def test_bad_op_type(self):
        """Unsupported operation types are rejected."""
        with self.assertRaises(PyverbsRDMAError) as ex:
            self.create_action(comp_mem_modify_type=0x7f)
        self.assertEqual(ex.exception.error_code, errno.EOPNOTSUPP)

    def test_unknown_flags_rejected(self):
        """The flags field is reserved and must be zero."""
        attr = efa.EfaMemCompActionInitAttr(pd=self.pd, comp_mem_ptr=self.alloc_buf())
        attr.flags = 1
        with self.assertRaises(PyverbsRDMAError) as ex:
            efa.EfaCompAction(self.efa_ctx, attr)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

    def test_unknown_comp_mask_rejected(self):
        """Unknown comp_mask bits are rejected."""
        attr = efa.EfaMemCompActionInitAttr(pd=self.pd, comp_mem_ptr=self.alloc_buf())
        attr.comp_mask = 1
        with self.assertRaises(PyverbsRDMAError) as ex:
            efa.EfaCompAction(self.efa_ctx, attr)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

    def test_missing_pd_rejected(self):
        """An action without a protection domain is rejected."""
        attr = efa.EfaMemCompActionInitAttr(comp_mem_ptr=self.alloc_buf())
        with self.assertRaises(PyverbsRDMAError) as ex:
            efa.EfaCompAction(self.efa_ctx, attr)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

    def test_zero_mem_modify_size_rejected(self):
        """A zero memory modification size is rejected."""
        with self.assertRaises(PyverbsRDMAError) as ex:
            self.create_action(mem_modify_size=0)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

    def test_destroy_pd_while_referenced(self):
        """Deallocating a PD associated with a live action fails with EBUSY."""
        pd = PD(self.efa_ctx)
        action = self.create_action(pd=pd)
        with self.assertRaises(PyverbsRDMAError) as ex:
            pd.close()
        self.assertEqual(ex.exception.error_code, errno.EBUSY)
        action.close()
        pd.close()

    def test_exhaustion(self):
        """Creating actions beyond the device limit fails cleanly."""
        max_actions = self.dev_attrs.max_comp_actions
        if max_actions > EXHAUSTION_TEST_LIMIT:
            raise unittest.SkipTest(
                f'max_comp_actions ({max_actions}) too large for exhaustion test')
        buf = self.alloc_buf()
        actions = []
        try:
            with self.assertRaises(PyverbsRDMAError) as ex:
                for _ in range(max_actions + 1):
                    actions.append(self.create_action(buf=buf))
            self.assertEqual(ex.exception.error_code, errno.ENOMEM)
            self.assertEqual(len(actions), max_actions)
        finally:
            for action in actions:
                action.close()
