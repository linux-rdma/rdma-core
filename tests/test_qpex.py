import unittest
import random
import errno

from pyverbs.qp import QPCap, QPInitAttrEx, QPAttr, QPEx, QP
from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from pyverbs.mr import MW, MWBindInfo
from pyverbs.base import inc_rkey
from tests.utils import wc_status_to_str
import pyverbs.enums as e

from tests.base import UDResources, RCResources, RDMATestCase, XRCResources
import tests.utils as u


def create_qp_ex(agr_obj, qp_type, send_flags):
    if qp_type == e.IBV_QPT_XRC_SEND:
        cap = QPCap(max_send_wr=agr_obj.num_msgs, max_recv_wr=0, max_recv_sge=0,
                    max_send_sge=1)
    else:
        cap = QPCap(max_send_wr=agr_obj.num_msgs, max_recv_wr=agr_obj.num_msgs,
                    max_recv_sge=1, max_send_sge=1)
    qia = QPInitAttrEx(cap=cap, qp_type=qp_type, scq=agr_obj.cq,
                       rcq=agr_obj.cq, pd=agr_obj.pd, send_ops_flags=send_flags,
                       comp_mask=e.IBV_QP_INIT_ATTR_PD |
                                 e.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS)
    qp_attr = QPAttr(port_num=agr_obj.ib_port)
    if qp_type == e.IBV_QPT_UD:
        qp_attr.qkey = agr_obj.UD_QKEY
        qp_attr.pkey_index = agr_obj.UD_PKEY_INDEX
    if qp_type == e.IBV_QPT_RC:
        qp_attr.qp_access_flags = e.IBV_ACCESS_REMOTE_WRITE | \
                                  e.IBV_ACCESS_REMOTE_READ | \
                                  e.IBV_ACCESS_REMOTE_ATOMIC | \
                                  e.IBV_ACCESS_FLUSH_GLOBAL | \
                                  e.IBV_ACCESS_FLUSH_PERSISTENT
    try:
        # We don't have capability bits for this
        qp = QPEx(agr_obj.ctx, qia, qp_attr)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EOPNOTSUPP:
            raise unittest.SkipTest('Extended QP is not supported on this device')
        raise ex
    if qp_type != e.IBV_QPT_XRC_SEND:
        agr_obj.qps.append(qp)
        agr_obj.qps_num.append(qp.qp_num)
        agr_obj.psns.append(random.getrandbits(24))
    else:
        return qp


class QpExUDSend(UDResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_UD, e.IBV_QP_EX_WITH_SEND)


class QpExRCSend(RCResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_RC, e.IBV_QP_EX_WITH_SEND)


class QpExXRCSend(XRCResources):
    def create_qps(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_attr.pkey_index = 0
        for _ in range(self.qp_count):
            attr_ex = QPInitAttrEx(qp_type=e.IBV_QPT_XRC_RECV,
                                   comp_mask=e.IBV_QP_INIT_ATTR_XRCD,
                                   xrcd=self.xrcd)
            qp_attr.qp_access_flags = e.IBV_ACCESS_REMOTE_WRITE | \
                                      e.IBV_ACCESS_REMOTE_READ
            recv_qp = QP(self.ctx, attr_ex, qp_attr)
            self.rqp_lst.append(recv_qp)

            send_qp = create_qp_ex(self, e.IBV_QPT_XRC_SEND, e.IBV_QP_EX_WITH_SEND)
            self.sqp_lst.append(send_qp)
            self.qps_num.append((recv_qp.qp_num, send_qp.qp_num))
            self.psns.append(random.getrandbits(24))


class QpExUDSendImm(UDResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_UD, e.IBV_QP_EX_WITH_SEND_WITH_IMM)


class QpExRCSendImm(RCResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_RC, e.IBV_QP_EX_WITH_SEND_WITH_IMM)


class QpExXRCSendImm(XRCResources):
    def create_qps(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_attr.pkey_index = 0
        for _ in range(self.qp_count):
            attr_ex = QPInitAttrEx(qp_type=e.IBV_QPT_XRC_RECV,
                                   comp_mask=e.IBV_QP_INIT_ATTR_XRCD,
                                   xrcd=self.xrcd)
            qp_attr.qp_access_flags = e.IBV_ACCESS_REMOTE_WRITE | \
                                      e.IBV_ACCESS_REMOTE_READ
            recv_qp = QP(self.ctx, attr_ex, qp_attr)
            self.rqp_lst.append(recv_qp)

            send_qp = create_qp_ex(self, e.IBV_QPT_XRC_SEND,
                                   e.IBV_QP_EX_WITH_SEND_WITH_IMM)
            self.sqp_lst.append(send_qp)
            self.qps_num.append((recv_qp.qp_num, send_qp.qp_num))
            self.psns.append(random.getrandbits(24))


class QpExRCFlush(RCResources):
    ptype = e.IBV_FLUSH_GLOBAL
    level = e.IBV_FLUSH_RANGE
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_RC, e.IBV_QP_EX_WITH_FLUSH | e.IBV_QP_EX_WITH_RDMA_WRITE)

    def create_mr(self):
        try:
            self.mr = u.create_custom_mr(self, e.IBV_ACCESS_FLUSH_GLOBAL | e.IBV_ACCESS_REMOTE_WRITE)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EINVAL:
                    raise unittest.SkipTest('Create mr with IBV_ACCESS_FLUSH_GLOBAL access flag is not supported in kernel')
            raise ex


class QpExRCAtomicWrite(RCResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_RC, e.IBV_QP_EX_WITH_ATOMIC_WRITE)

    def create_mr(self):
        self.mr = u.create_custom_mr(self, e.IBV_ACCESS_REMOTE_WRITE)


class QpExRCRDMAWrite(RCResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_RC, e.IBV_QP_EX_WITH_RDMA_WRITE)

    def create_mr(self):
        self.mr = u.create_custom_mr(self, e.IBV_ACCESS_REMOTE_WRITE)


class QpExRCRDMAWriteImm(RCResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_RC,
                               e.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM)

    def create_mr(self):
        self.mr = u.create_custom_mr(self, e.IBV_ACCESS_REMOTE_WRITE)


class QpExRCRDMARead(RCResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_RC, e.IBV_QP_EX_WITH_RDMA_READ)

    def create_mr(self):
        self.mr = u.create_custom_mr(self, e.IBV_ACCESS_REMOTE_READ)


class QpExRCAtomicCmpSwp(RCResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_RC,
                               e.IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP)
        self.mr = u.create_custom_mr(self, e.IBV_ACCESS_REMOTE_ATOMIC)


class QpExRCAtomicFetchAdd(RCResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_RC,
                               e.IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD)
        self.mr = u.create_custom_mr(self, e.IBV_ACCESS_REMOTE_ATOMIC)


class QpExRCBindMw(RCResources):
    def create_qps(self):
        create_qp_ex(self, e.IBV_QPT_RC, e.IBV_QP_EX_WITH_RDMA_WRITE |
                     e.IBV_QP_EX_WITH_BIND_MW)

    def create_mr(self):
        self.mr = u.create_custom_mr(self, e.IBV_ACCESS_REMOTE_WRITE |
                                     e.IBV_ACCESS_MW_BIND)


class QpExTestCase(RDMATestCase):
    """ Run traffic using the new post send API. """
    def setUp(self):
        super().setUp()
        self.iters = 100

    def test_qp_ex_ud_send(self):
        self.create_players(QpExUDSend)
        u.traffic(**self.traffic_args, new_send=True, send_op=e.IBV_WR_SEND)

    def test_qp_ex_ud_zero_size(self):
        self.create_players(QpExUDSend)
        self.client.msg_size = 0
        self.server.msg_size = 0
        u.traffic(**self.traffic_args, new_send=True, send_op=e.IBV_WR_SEND)

    def test_qp_ex_rc_send(self):
        self.create_players(QpExRCSend)
        u.traffic(**self.traffic_args, new_send=True, send_op=e.IBV_WR_SEND)

    def test_qp_ex_xrc_send(self):
        self.create_players(QpExXRCSend)
        u.xrc_traffic(self.client, self.server, send_op=e.IBV_WR_SEND)

    def test_qp_ex_ud_send_imm(self):
        self.create_players(QpExUDSendImm)
        u.traffic(**self.traffic_args, new_send=True, send_op=e.IBV_WR_SEND_WITH_IMM)

    def test_qp_ex_rc_send_imm(self):
        self.create_players(QpExRCSendImm)
        u.traffic(**self.traffic_args, new_send=True, send_op=e.IBV_WR_SEND_WITH_IMM)

    def test_qp_ex_xrc_send_imm(self):
        self.create_players(QpExXRCSendImm)
        u.xrc_traffic(self.client, self.server, send_op=e.IBV_WR_SEND_WITH_IMM)

    def test_qp_ex_rc_flush(self):
        self.create_players(QpExRCFlush)
        wcs = u.flush_traffic(**self.traffic_args, new_send=True,
                              send_op=e.IBV_WR_FLUSH)
        if wcs[0].status != e.IBV_WC_SUCCESS:
            raise PyverbsError(f'Unexpected {wc_status_to_str(wcs[0].status)}')

        self.client.level = e.IBV_FLUSH_MR
        wcs = u.flush_traffic(**self.traffic_args, new_send=True,
                              send_op=e.IBV_WR_FLUSH)
        if wcs[0].status != e.IBV_WC_SUCCESS:
            raise PyverbsError(f'Unexpected {wc_status_to_str(wcs[0].status)}')

    def test_qp_ex_rc_flush_type_violate(self):
        self.create_players(QpExRCFlush)
        self.client.ptype = e.IBV_FLUSH_PERSISTENT
        wcs = u.flush_traffic(**self.traffic_args, new_send=True,
                              send_op=e.IBV_WR_FLUSH)
        if wcs[0].status != e.IBV_WC_REM_ACCESS_ERR:
            raise PyverbsError(f'Expected errors {wc_status_to_str(e.IBV_WC_REM_ACCESS_ERR)} - got {wc_status_to_str(wcs[0].status)}')

    def test_qp_ex_rc_atomic_write(self):
        self.create_players(QpExRCAtomicWrite)
        self.client.msg_size = 8
        self.server.msg_size = 8
        u.rdma_traffic(**self.traffic_args,
                       new_send=True, send_op=e.IBV_WR_ATOMIC_WRITE)

    def test_qp_ex_rc_rdma_write(self):
        self.create_players(QpExRCRDMAWrite)
        u.rdma_traffic(**self.traffic_args,
                       new_send=True, send_op=e.IBV_WR_RDMA_WRITE)

    def test_qp_ex_rc_rdma_write_imm(self):
        self.create_players(QpExRCRDMAWriteImm)
        u.traffic(**self.traffic_args,
                  new_send=True, send_op=e.IBV_WR_RDMA_WRITE_WITH_IMM)

    def test_qp_ex_rc_rdma_write_zero_length(self):
        self.create_players(QpExRCRDMAWrite)
        self.client.msg_size = 0
        self.server.msg_size = 0
        u.rdma_traffic(**self.traffic_args,
                       new_send=True, send_op=e.IBV_WR_RDMA_WRITE)

    def test_qp_ex_rc_rdma_read(self):
        self.create_players(QpExRCRDMARead)
        self.server.mr.write('s' * self.server.msg_size, self.server.msg_size)
        u.rdma_traffic(**self.traffic_args,
                       new_send=True, send_op=e.IBV_WR_RDMA_READ)

    def test_qp_ex_rc_rdma_read_zero_size(self):
        self.create_players(QpExRCRDMARead)
        self.client.msg_size = 0
        self.server.msg_size = 0
        self.server.mr.write('s' * self.server.msg_size, self.server.msg_size)
        u.rdma_traffic(**self.traffic_args,
                       new_send=True, send_op=e.IBV_WR_RDMA_READ)

    def test_qp_ex_rc_atomic_cmp_swp(self):
        self.create_players(QpExRCAtomicCmpSwp)
        self.client.msg_size = 8  # Atomic work on 64b operators
        self.server.msg_size = 8
        self.server.mr.write('s' * 8, 8)
        u.atomic_traffic(**self.traffic_args,
                         new_send=True, send_op=e.IBV_WR_ATOMIC_CMP_AND_SWP)

    def test_qp_ex_rc_atomic_fetch_add(self):
        self.create_players(QpExRCAtomicFetchAdd)
        self.client.msg_size = 8  # Atomic work on 64b operators
        self.server.msg_size = 8
        self.server.mr.write('s' * 8, 8)
        u.atomic_traffic(**self.traffic_args,
                         new_send=True, send_op=e.IBV_WR_ATOMIC_FETCH_AND_ADD)

    def test_qp_ex_rc_bind_mw(self):
        """
        Verify bind memory window operation using the new post_send API.
        Instead of checking through regular pingpong style traffic, we'll
        do as follows:
        - Register an MR with remote write access
        - Bind a MW without remote write permission to the MR
        - Verify that remote write fails
        Since it's a unique flow, it's an integral part of that test rather
        than a utility method.
        """
        self.create_players(QpExRCBindMw)
        client_sge = u.get_send_elements(self.client, False)[1]
        # Create a MW and bind it
        self.server.qp.wr_start()
        self.server.qp.wr_id = 0x123
        self.server.qp.wr_flags = e.IBV_SEND_SIGNALED
        bind_info = MWBindInfo(self.server.mr, self.server.mr.buf, self.server.mr.length,
                               e.IBV_ACCESS_LOCAL_WRITE)
        try:
            mw = MW(self.server.pd, mw_type=e.IBV_MW_TYPE_2)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Memory Window allocation is not supported')
            raise ex
        new_key = inc_rkey(mw.rkey)
        self.server.qp.wr_bind_mw(mw, new_key, bind_info)
        self.server.qp.wr_complete()
        u.poll_cq(self.server.cq)
        # Verify that remote write fails
        self.client.qp.wr_start()
        self.client.qp.wr_id = 0x124
        self.client.qp.wr_flags = e.IBV_SEND_SIGNALED
        self.client.qp.wr_rdma_write(new_key, self.server.mr.buf)
        self.client.qp.wr_set_sge(client_sge)
        self.client.qp.wr_complete()
        wcs = u._poll_cq(self.client.cq)
        if wcs[0].status != e.IBV_WC_REM_ACCESS_ERR:
            raise PyverbsRDMAError(f'Completion status is {wc_status_to_str(wcs[0].status)}')

    def test_post_receive_qp_state_bad_flow(self):
        self.create_players(QpExUDSend)
        u.post_rq_state_bad_flow(self)

    def test_post_send_qp_state_bad_flow(self):
        self.create_players(QpExUDSend)
        u.post_sq_state_bad_flow(self)

    def test_full_rq_bad_flow(self):
        self.create_players(QpExUDSend)
        u.full_rq_bad_flow(self)

    def test_rq_with_larger_sgl_bad_flow(self):
        self.create_players(QpExUDSend)
        u.create_rq_with_larger_sgl_bad_flow(self)
