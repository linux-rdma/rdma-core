import unittest
import random
import errno

from pyverbs.qp import QPCap, QPInitAttrEx, QPAttr, QPEx, QP
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.mr import MW, MWBindInfo
from pyverbs.base import inc_rkey
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
                                  e.IBV_ACCESS_REMOTE_ATOMIC
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
        self.qp_dict = {'ud_send': QpExUDSend, 'rc_send': QpExRCSend,
                        'xrc_send': QpExXRCSend, 'ud_send_imm': QpExUDSendImm,
                        'rc_send_imm': QpExRCSendImm,
                        'xrc_send_imm': QpExXRCSendImm,
                        'rc_write': QpExRCRDMAWrite,
                        'rc_write_imm': QpExRCRDMAWriteImm,
                        'rc_read': QpExRCRDMARead,
                        'rc_cmp_swp': QpExRCAtomicCmpSwp,
                        'rc_fetch_add': QpExRCAtomicFetchAdd,
                        'rc_bind_mw': QpExRCBindMw}

    def create_players(self, qp_type):
        try:
            client = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                           self.gid_index)
            server = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                           self.gid_index)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create player with {} is not supported'.format(qp_type))
            raise ex
        client.pre_run(server.psns, server.qps_num)
        server.pre_run(client.psns, client.qps_num)
        return client, server

    def test_qp_ex_ud_send(self):
        client, server = self.create_players('ud_send')
        u.traffic(client, server, self.iters, self.gid_index, self.ib_port,
                  new_send=True, send_op=e.IBV_QP_EX_WITH_SEND)

    def test_qp_ex_ud_zero_size(self):
        client, server = self.create_players('ud_send')
        client.msg_size = 0
        server.msg_size = 0
        u.traffic(client, server, self.iters, self.gid_index, self.ib_port,
                  new_send=True, send_op=e.IBV_QP_EX_WITH_SEND)

    def test_qp_ex_rc_send(self):
        client, server = self.create_players('rc_send')
        u.traffic(client, server, self.iters, self.gid_index, self.ib_port,
                  new_send=True, send_op=e.IBV_QP_EX_WITH_SEND)

    def test_qp_ex_xrc_send(self):
        client, server = self.create_players('xrc_send')
        u.xrc_traffic(client, server, send_op=e.IBV_QP_EX_WITH_SEND)

    def test_qp_ex_ud_send_imm(self):
        client, server = self.create_players('ud_send_imm')
        u.traffic(client, server, self.iters, self.gid_index, self.ib_port,
                  new_send=True, send_op=e.IBV_QP_EX_WITH_SEND_WITH_IMM)

    def test_qp_ex_rc_send_imm(self):
        client, server = self.create_players('rc_send_imm')
        u.traffic(client, server, self.iters, self.gid_index, self.ib_port,
                  new_send=True, send_op=e.IBV_QP_EX_WITH_SEND_WITH_IMM)

    def test_qp_ex_xrc_send_imm(self):
        client, server = self.create_players('xrc_send_imm')
        u.xrc_traffic(client, server, send_op=e.IBV_QP_EX_WITH_SEND_WITH_IMM)

    def test_qp_ex_rc_rdma_write(self):
        client, server = self.create_players('rc_write')
        client.rkey = server.mr.rkey
        server.rkey = client.mr.rkey
        client.raddr = server.mr.buf
        server.raddr = client.mr.buf
        u.rdma_traffic(client, server, self.iters, self.gid_index, self.ib_port,
                       new_send=True, send_op=e.IBV_QP_EX_WITH_RDMA_WRITE)

    def test_qp_ex_rc_rdma_write_imm(self):
        client, server = self.create_players('rc_write_imm')
        client.rkey = server.mr.rkey
        server.rkey = client.mr.rkey
        client.raddr = server.mr.buf
        server.raddr = client.mr.buf
        u.traffic(client, server, self.iters, self.gid_index, self.ib_port,
                  new_send=True, send_op=e.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM)

    def test_qp_ex_rc_rdma_read(self):
        client, server = self.create_players('rc_read')
        client.rkey = server.mr.rkey
        server.rkey = client.mr.rkey
        client.raddr = server.mr.buf
        server.raddr = client.mr.buf
        server.mr.write('s' * server.msg_size, server.msg_size)
        u.rdma_traffic(client, server, self.iters, self.gid_index, self.ib_port,
                       new_send=True, send_op=e.IBV_QP_EX_WITH_RDMA_READ)

    def test_qp_ex_rc_atomic_cmp_swp(self):
        client, server = self.create_players('rc_cmp_swp')
        client.msg_size = 8  # Atomic work on 64b operators
        server.msg_size = 8
        client.rkey = server.mr.rkey
        server.rkey = client.mr.rkey
        client.raddr = server.mr.buf
        server.raddr = client.mr.buf
        server.mr.write('s' * 8, 8)
        u.atomic_traffic(client, server, self.iters, self.gid_index,
                         self.ib_port, new_send=True,
                         send_op=e.IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP)

    def test_qp_ex_rc_atomic_fetch_add(self):
        client, server = self.create_players('rc_fetch_add')
        client.msg_size = 8  # Atomic work on 64b operators
        server.msg_size = 8
        client.rkey = server.mr.rkey
        server.rkey = client.mr.rkey
        client.raddr = server.mr.buf
        server.raddr = client.mr.buf
        server.mr.write('s' * 8, 8)
        u.atomic_traffic(client, server, self.iters, self.gid_index,
                         self.ib_port, new_send=True,
                         send_op=e.IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD)

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
        client, server = self.create_players('rc_bind_mw')
        client_sge = u.get_send_elements(client, False)[1]
        # Create a MW and bind it
        server.qp.wr_start()
        server.qp.wr_id = 0x123
        server.qp.wr_flags = e.IBV_SEND_SIGNALED
        bind_info = MWBindInfo(server.mr, server.mr.buf, server.mr.length,
                               e.IBV_ACCESS_LOCAL_WRITE)
        try:
            mw = MW(server.pd, mw_type=e.IBV_MW_TYPE_2)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Memory Window allocation is not supported')
            raise ex
        new_key = inc_rkey(server.mr.rkey)
        server.qp.wr_bind_mw(mw, new_key, bind_info)
        server.qp.wr_complete()
        u.poll_cq(server.cq)
        # Verify that remote write fails
        client.qp.wr_start()
        client.qp.wr_id = 0x124
        client.qp.wr_flags = e.IBV_SEND_SIGNALED
        client.qp.wr_rdma_write(new_key, server.mr.buf)
        client.qp.wr_set_sge(client_sge)
        client.qp.wr_complete()
        try:
            u.poll_cq(client.cq)
        except PyverbsRDMAError as ex:
            if ex.error_code != e.IBV_WC_REM_ACCESS_ERR:
                raise ex

