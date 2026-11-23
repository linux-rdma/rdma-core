# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020-2025 Amazon.com, Inc. or its affiliates. All rights reserved.

import unittest
import errno
import ctypes
import struct
import time

from pyverbs.cq import CQ, CompChannel
from pyverbs.libibverbs_enums import ibv_qp_create_send_ops_flags, ibv_wr_opcode, ibv_qp_attr_mask, \
    ibv_send_flags, ibv_wc_status
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs import mem_alloc as mem
from pyverbs.pd import PD
import pyverbs.providers.efa.efa_enums as efa_enums
import pyverbs.providers.efa.efadv as efa

from tests.efa_base import EfaRDMATestCase
from tests.efa_base import SRDResources
import tests.utils as u


class CqEventsSRD(SRDResources):
    def __init__(self, dev_name, ib_port, gid_index):
        super().__init__(dev_name, ib_port, gid_index, ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND)

    def create_cq(self):
        self.comp_channel = CompChannel(self.ctx)
        self.cq = CQ(self.ctx, self.num_msgs, None, self.comp_channel)
        self.cq.req_notify()


class CqEventsSRDTestCase(EfaRDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 100

    def test_cq_events_srd(self):
        for use_new_send in [False, True]:
            with self.subTest():
                super().create_players(CqEventsSRD)
                u.traffic(**self.traffic_args, new_send=use_new_send)


class QPSRDTestCase(EfaRDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 100
        self.server = None
        self.client = None

    def create_players(self, send_ops_flags=0, qp_count=8, dev_cap=None, wc_flags=0, qp_flags=0):
        super().create_players(SRDResources, send_ops_flags=send_ops_flags, qp_count=qp_count,
                               required_dev_cap=dev_cap, wc_flags=wc_flags, qp_flags=qp_flags)

    def full_sq_bad_flow(self):
        """
        Check post_send while qp's sq is full.
        - Find qp's sq length
        - Fill the qp with work requests until overflow
        """
        qp_idx = 0
        send_op = ibv_wr_opcode.IBV_WR_SEND
        ah = u.get_global_ah(self.client, self.gid_index, self.ib_port)
        qp_attr, _ = self.client.qps[qp_idx].query(ibv_qp_attr_mask.IBV_QP_CAP)
        max_send_wr = qp_attr.cap.max_send_wr
        with self.assertRaises(PyverbsRDMAError) as ex:
            for _ in range (max_send_wr + 1):
                _, c_sg = u.get_send_elements(self.client, False)
                u.send(self.client, c_sg, send_op, new_send=True, qp_idx=qp_idx, ah=ah)
        self.assertEqual(ex.exception.error_code, errno.ENOMEM)

    def unsolicited_rdma_write_traffic(self, client, server, iters, gid_idx, port):
        """
        Runs unsolicited rdma write traffic between two sides
        """
        ah_client = u.get_global_ah(client, gid_idx, port)
        ah_server = u.get_global_ah(server, gid_idx, port)
        poll = u.poll_cq_ex
        imm_data = u.IMM_DATA
        send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE_WITH_IMM
        read_offset = 0
        for _ in range(iters):
            for qp_idx in range(server.qp_count):
                _, c_send_object = u.get_send_elements(client, False, send_op)
                u.send(client, c_send_object, send_op, True, qp_idx, ah_client, is_imm=True)
                poll(client.cq)
                poll(server.cq, data=imm_data)
                # Validate that the CQE is marked as unsolicited
                if not server.cq.is_unsolicited():
                    raise PyverbsError('Completion was not marked as unsolicited')
                msg_received_list = u.get_msg_received(server, read_offset)
                for msg in msg_received_list:
                    u.validate(msg, True, server.msg_size)

    def test_qp_ex_srd_send(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND)
        u.traffic(**self.traffic_args, new_send=True, send_op=ibv_wr_opcode.IBV_WR_SEND)

    def test_qp_ex_srd_send_imm(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND_WITH_IMM)
        u.traffic(**self.traffic_args, new_send=True, send_op=ibv_wr_opcode.IBV_WR_SEND_WITH_IMM)

    def test_qp_ex_srd_rdma_read(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_READ)
        self.server.mr.write('s' * self.server.msg_size, self.server.msg_size)
        u.rdma_traffic(**self.traffic_args, new_send=True, send_op=ibv_wr_opcode.IBV_WR_RDMA_READ)

    def test_qp_ex_srd_rdma_write(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE)
        u.rdma_traffic(**self.traffic_args, new_send=True, send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE)

    def test_qp_ex_srd_rdma_write_with_imm(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM)
        u.traffic(**self.traffic_args, new_send=True, send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE_WITH_IMM)

    def test_qp_ex_srd_rdma_unsolicited_write_with_imm(self):
        wc_flag = efa_enums.EFADV_WC_EX_WITH_IS_UNSOLICITED
        dev_cap = efa_enums.EFADV_DEVICE_ATTR_CAPS_UNSOLICITED_WRITE_RECV
        qp_flags = efa_enums.EFADV_QP_FLAGS_UNSOLICITED_WRITE_RECV
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM,
                            dev_cap=dev_cap, wc_flags=wc_flag, qp_flags=qp_flags)
        self.unsolicited_rdma_write_traffic(**self.traffic_args)

    def test_qp_ex_srd_old_send(self):
        self.create_players()
        u.traffic(**self.traffic_args, new_send=False)

    def test_qp_ex_srd_old_send_imm(self):
        self.create_players()
        u.traffic(**self.traffic_args, new_send=False, send_op=ibv_wr_opcode.IBV_WR_SEND_WITH_IMM)

    def test_qp_ex_srd_zero_size(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND)
        self.client.msg_size = 0
        self.server.msg_size = 0
        u.traffic(**self.traffic_args, new_send=True, send_op=ibv_wr_opcode.IBV_WR_SEND)

    def test_post_receive_qp_state_bad_flow(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND, qp_count=1)
        u.post_rq_state_bad_flow(self)

    def test_post_send_qp_state_bad_flow(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND, qp_count=1)
        u.post_sq_state_bad_flow(self)

    def test_full_rq_bad_flow(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND, qp_count=1)
        u.full_rq_bad_flow(self)

    def test_full_sq_bad_flow(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND, qp_count=1)
        self.full_sq_bad_flow()

    def test_rq_with_larger_sgl_bad_flow(self):
        self.create_players(ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND, qp_count=1)
        u.create_rq_with_larger_sgl_bad_flow(self)


# Entry sizes (operation widths in bytes) a memory completion action accepts
ENTRY_SIZES = [1, 2, 4]
# Action targets are 8 bytes, zeroed before the operation
ACTION_TARGET_SIZE = 8

COMP_ACTION_CAP = efa_enums.EFADV_DEVICE_ATTR_CAPS_COMP_ACTION

# Operand the setters without a data argument trigger the action with
ACTION_DEFAULT_DATA = 0

# Pattern the target buffers hold before an action fires; the device
# overwrites the low bytes of the operation width with the operand
ACTION_TARGET_INIT = 0xa5a5a5a5a5a5a5a5

ACTION_POLL_TIMEOUT = 3


def read_action_target(buf):
    return struct.unpack('Q', ctypes.string_at(buf, ACTION_TARGET_SIZE))[0]


def action_target_value(data, width=4):
    """Expected target content once an action of the given width fired."""
    mask = (1 << (width * 8)) - 1
    return (ACTION_TARGET_INIT & ~mask) | (data & mask)


def poll_action_target(buf, expected):
    """
    Busy-poll a completion mem op target buffer until it carries the
    expected value. Action-vs-CQE ordering is unspecified, so the target
    is polled independently with a timeout. The whole target is compared
    so that a store wider than the operation is detected too.
    """
    deadline = time.perf_counter() + ACTION_POLL_TIMEOUT
    val = None
    while time.perf_counter() < deadline:
        val = read_action_target(buf)
        if val == expected:
            return
        time.sleep(0.001)
    raise AssertionError(
        f'Action target holds {val:#x}, expected {expected:#x}')


def poll_raw_wc(cq):
    """
    Poll a single completion and return it whatever its status. The
    utils poll helpers raise on error statuses, which hides the status
    the device reported.
    """
    deadline = time.perf_counter() + u.POLL_CQ_TIMEOUT
    while time.perf_counter() < deadline:
        npolled, wcs = cq.poll(1)
        if npolled:
            return wcs[0]
    raise AssertionError('Timed out waiting for a completion')


class CompActionResources(SRDResources):
    """SRD traffic resources with a completion action factory."""
    def __init__(self, dev_name, ib_port, gid_index, wr_flags,
                 send_ops_flags=None, **kwargs):
        self.actions = []
        self.action_bufs = []
        if send_ops_flags is None:
            send_ops_flags = \
                ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE
        super().__init__(dev_name, ib_port, gid_index, send_ops_flags,
                         wr_flags=wr_flags, **kwargs)

    def create_context(self):
        # The action object must share the QP's device context and PD
        self.ctx = efa.EfaContext(name=self.dev_name)
        device_caps = self.ctx.query_efa_device().device_caps
        if not (device_caps & COMP_ACTION_CAP):
            raise unittest.SkipTest(
                f"Device caps doesn't support {efa.dev_cap_to_str(COMP_ACTION_CAP)}")

    def create_comp_action(self, mem_modify_size=4, pd=None):
        """
        Create a memory completion action owned by this side, on this side's
        PD unless another one is given. Returns the action id to post and the
        target buffer.
        """
        buf = mem.posix_memalign(ACTION_TARGET_SIZE, ACTION_TARGET_SIZE)
        ctypes.memmove(buf, struct.pack('Q', ACTION_TARGET_INIT),
                       ACTION_TARGET_SIZE)
        self.action_bufs.append(buf)
        attr = efa.EfaMemCompActionInitAttr(pd=pd or self.pd,
                                            mem_modify_size=mem_modify_size,
                                            comp_mem_ptr=buf)
        action = efa.EfaCompAction(self.ctx, attr)
        self.actions.append(action)
        return action.action_id, buf

    def release_comp_actions(self):
        for action in reversed(self.actions):
            action.close()
        self.actions = []
        for buf in self.action_bufs:
            mem.free(buf)
        self.action_bufs = []


class EfaCompActionTrafficBase(EfaRDMATestCase):
    """Two SRD players with completion action resources and helpers."""
    resource_class = CompActionResources

    def setUp(self):
        super().setUp()
        self.iters = 10
        self.client_ah = None
        self.server_ah = None

    def tearDown(self):
        for ah in [self.client_ah, self.server_ah]:
            if ah:
                ah.close()
        for player in [getattr(self, 'client', None),
                       getattr(self, 'server', None)]:
            if player:
                player.release_comp_actions()
        super().tearDown()

    def create_players(self, wr_flags, **resource_args):
        super().create_players(self.resource_class, wr_flags=wr_flags,
                               **resource_args)
        # The device resolves an incoming RDMA WRITE through an AH on the
        # receiving QP's PD as well, so both sides need one
        self.client_ah = u.get_global_ah(self.client, self.gid_index,
                                         self.ib_port)
        self.server_ah = u.get_global_ah(self.server, self.gid_index,
                                         self.ib_port)

    def start_client_wr(self):
        """Begin a signaled WR on the client QP and return the QP."""
        qp = self.client.qps[0]
        qp.wr_start()
        qp.wr_id = 0x123
        qp.wr_flags = ibv_send_flags.IBV_SEND_SIGNALED
        return qp

    def set_client_wr_addr(self, qp):
        client = self.client
        qp.wr_set_ud_addr(self.client_ah, client.rqps_num[0], client.SRD_QKEY)

    def post_write_with_actions(self, local=None, remote=None,
                                local_data=None, remote_data=None):
        """
        Post a single RDMA WRITE from the client, attaching the requested
        actions, and wait for the initiator completion.
        """
        client = self.client
        u.prepare_validate_data(client=client, server=self.server)
        _, sge = u.get_send_elements(client, False,
                                     opcode=ibv_wr_opcode.IBV_WR_RDMA_WRITE)
        qp = self.start_client_wr()
        qp.wr_rdma_write(client.rkey, client.raddr)
        self.set_client_wr_addr(qp)
        qp.wr_set_sge(sge)
        if local is not None:
            if local_data is None:
                qp.wr_set_local_comp_action(local)
            else:
                qp.wr_set_local_comp_action_with_data(local, local_data)
        if remote is not None:
            if remote_data is None:
                qp.wr_set_remote_comp_action(remote)
            else:
                qp.wr_set_remote_comp_action_with_data(remote, remote_data)
        qp.wr_complete()
        u.poll_cq(client.cq)
        msg_received = self.server.mr.read(client.msg_size, 0)
        u.validate(msg_received, True, client.msg_size)


class EfaCompActionTrafficTest(EfaCompActionTrafficBase):
    """RDMA WRITE traffic with local/remote completion actions."""
    def test_rdma_write_local_comp_action(self):
        """Local action on WRITE completion writes the default operand."""
        self.create_players(efa_enums.EFADV_WR_EX_WITH_COMP_ACTION)
        action_id, buf = self.client.create_comp_action()
        self.post_write_with_actions(local=action_id)
        poll_action_target(buf, action_target_value(ACTION_DEFAULT_DATA))

    def test_rdma_write_remote_comp_action(self):
        """Remote action delivery writes the default operand at the target."""
        self.create_players(efa_enums.EFADV_WR_EX_WITH_COMP_ACTION)
        action_id, buf = self.server.create_comp_action()
        self.post_write_with_actions(remote=action_id)
        poll_action_target(buf, action_target_value(ACTION_DEFAULT_DATA))

    def test_rdma_write_local_comp_action_with_data(self):
        """Local action carries an explicit operand."""
        self.create_players(
            efa_enums.EFADV_WR_EX_WITH_COMP_ACTION_WITH_DATA)
        action_id, buf = self.client.create_comp_action()
        self.post_write_with_actions(local=action_id, local_data=0x0badcafe)
        poll_action_target(buf, action_target_value(0x0badcafe))

    def test_rdma_write_remote_comp_action_with_data(self):
        """Remote action carries an explicit operand."""
        self.create_players(
            efa_enums.EFADV_WR_EX_WITH_COMP_ACTION_WITH_DATA)
        action_id, buf = self.server.create_comp_action()
        self.post_write_with_actions(remote=action_id, remote_data=0xabcd1234)
        poll_action_target(buf, action_target_value(0xabcd1234))

    def test_rdma_write_both_comp_actions_mem_modify_sizes(self):
        """Local and remote actions on one WR, across entry sizes."""
        self.create_players(
            efa_enums.EFADV_WR_EX_WITH_COMP_ACTION_WITH_DATA)
        data = 0x11223344
        for width in ENTRY_SIZES:
            with self.subTest(mem_modify_size=width):
                local_id, local_buf = self.client.create_comp_action(width)
                remote_id, remote_buf = self.server.create_comp_action(width)
                self.post_write_with_actions(local=local_id, remote=remote_id,
                                             local_data=data,
                                             remote_data=data)
                # Sub-64-bit operations use the operand LSB bits
                expected = action_target_value(data, width)
                poll_action_target(local_buf, expected)
                poll_action_target(remote_buf, expected)


# Device completion statuses reported as the vendor error, see efa_io_defs.h
EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_ACTION = 16
EFA_IO_COMP_STATUS_REMOTE_ERROR_INVALID_ACTION = 17

# Made-up action ids: the invalid-id sentinel, the largest index the id
# can encode, and an id carrying an unknown action type
BOGUS_ACTION_IDS = [0xffffffff, (1 << 21) - 1, 1 << 26]

SMOKE_WR_COUNT = 32


class NegativeActionResources(CompActionResources):
    """Action resources that can live on a foreign PD or die mid-test."""
    def __init__(self, *args, **kwargs):
        self.foreign_pds = []
        super().__init__(*args, **kwargs)

    def create_foreign_pd_comp_action(self):
        """Create an action on a PD other than the one the QP belongs to."""
        pd = PD(self.ctx)
        self.foreign_pds.append(pd)
        return self.create_comp_action(pd=pd)

    def destroy_comp_action(self, action_id):
        for action in self.actions:
            if action.action_id == action_id:
                action.close()
                self.actions.remove(action)
                return
        raise ValueError(f'Unknown action id {action_id:#x}')

    def release_comp_actions(self):
        super().release_comp_actions()
        for pd in self.foreign_pds:
            pd.close()
        self.foreign_pds = []


class EfaCompActionNegativeTest(EfaCompActionTrafficBase):
    """Invalid actions fail the WR; valid traffic survives the failure."""
    resource_class = NegativeActionResources

    def setUp(self):
        super().setUp()
        self.create_players(efa_enums.EFADV_WR_EX_WITH_COMP_ACTION)

    def start_write_wr(self, local=None, remote=None):
        """Build a signaled RDMA WRITE with raw action ids, without posting."""
        client = self.client
        u.prepare_validate_data(client=client, server=self.server)
        _, sge = u.get_send_elements(client, False,
                                     opcode=ibv_wr_opcode.IBV_WR_RDMA_WRITE)
        qp = self.start_client_wr()
        qp.wr_rdma_write(client.rkey, client.raddr)
        self.set_client_wr_addr(qp)
        qp.wr_set_sge(sge)
        if local is not None:
            qp.wr_set_local_comp_action(local)
        if remote is not None:
            qp.wr_set_remote_comp_action(remote)
        return qp

    def post_write_raw(self, local=None, remote=None):
        """Post a signaled WRITE and return the raw initiator completion."""
        qp = self.start_write_wr(local, remote)
        qp.wr_complete()
        return poll_raw_wc(self.client.cq)

    def assert_local_invalid(self, wc):
        self.assertEqual(wc.status, ibv_wc_status.IBV_WC_LOC_QP_OP_ERR,
                         f'status {wc.status}, vendor_err {wc.vendor_err}')
        self.assertEqual(wc.vendor_err,
                         EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_ACTION)

    def assert_remote_invalid(self, wc):
        self.assertEqual(wc.status, ibv_wc_status.IBV_WC_REM_INV_REQ_ERR,
                         f'status {wc.status}, vendor_err {wc.vendor_err}')
        self.assertEqual(wc.vendor_err,
                         EFA_IO_COMP_STATUS_REMOTE_ERROR_INVALID_ACTION)

    def assert_datapath_intact(self):
        """A freshly created action still fires on both sides."""
        local_id, local_buf = self.client.create_comp_action()
        remote_id, remote_buf = self.server.create_comp_action()
        self.post_write_with_actions(local=local_id, remote=remote_id)
        poll_action_target(local_buf, action_target_value(ACTION_DEFAULT_DATA))
        poll_action_target(remote_buf, action_target_value(ACTION_DEFAULT_DATA))

    def max_index_action_id(self):
        """An id whose index is one past the device's action table."""
        return self.client.ctx.query_efa_device().max_comp_actions

    def test_stale_local_action_rejected(self):
        """A destroyed local action fails the WR."""
        action_id, _ = self.client.create_comp_action()
        self.client.destroy_comp_action(action_id)
        self.assert_local_invalid(self.post_write_raw(local=action_id))
        self.assert_datapath_intact()

    def test_stale_remote_action_rejected(self):
        """A destroyed remote action fails the WR."""
        action_id, _ = self.server.create_comp_action()
        self.server.destroy_comp_action(action_id)
        self.assert_remote_invalid(self.post_write_raw(remote=action_id))
        self.assert_datapath_intact()

    def stale_action_after_slot_reuse(self, owner, remote):
        """
        Destroy an action and immediately create another one on the same PD,
        which recycles the slot with a new generation. The stale id must
        still fail and must not fire the new action.
        """
        stale_id, _ = owner.create_comp_action()
        owner.destroy_comp_action(stale_id)
        new_id, new_buf = owner.create_comp_action()
        self.assertNotEqual(new_id, stale_id)
        wc = self.post_write_raw(remote=stale_id) if remote else \
            self.post_write_raw(local=stale_id)
        # Check the recycled action's target before the status so that an
        # accepted stale id reports whether it fired the new action
        self.assertEqual(read_action_target(new_buf), ACTION_TARGET_INIT,
                         f'stale id {stale_id:#x} fired the action that '
                         f'recycled its slot ({new_id:#x}); WR status '
                         f'{wc.status}, vendor_err {wc.vendor_err}')
        if remote:
            self.assert_remote_invalid(wc)
        else:
            self.assert_local_invalid(wc)
        # The new action itself works
        if remote:
            self.post_write_with_actions(remote=new_id)
        else:
            self.post_write_with_actions(local=new_id)
        poll_action_target(new_buf, action_target_value(ACTION_DEFAULT_DATA))

    def test_stale_local_action_rejected_after_slot_reuse(self):
        """A stale local id fails even once its slot holds a new action."""
        self.stale_action_after_slot_reuse(self.client, remote=False)

    def test_stale_remote_action_rejected_after_slot_reuse(self):
        """A stale remote id fails even once its slot holds a new action."""
        self.stale_action_after_slot_reuse(self.server, remote=True)

    def test_foreign_pd_local_action_rejected(self):
        """A local action on another PD than the QP's fails the WR."""
        action_id, buf = self.client.create_foreign_pd_comp_action()
        self.assert_local_invalid(self.post_write_raw(local=action_id))
        self.assertEqual(read_action_target(buf), ACTION_TARGET_INIT)
        self.assert_datapath_intact()

    def test_foreign_pd_remote_action_rejected(self):
        """A remote action on another PD than the QP's fails the WR."""
        action_id, buf = self.server.create_foreign_pd_comp_action()
        self.assert_remote_invalid(self.post_write_raw(remote=action_id))
        self.assertEqual(read_action_target(buf), ACTION_TARGET_INIT)
        self.assert_datapath_intact()

    def test_bogus_local_action_ids_rejected(self):
        """Made-up local action ids fail the WR."""
        for action_id in BOGUS_ACTION_IDS + [self.max_index_action_id()]:
            with self.subTest(action_id=hex(action_id)):
                self.assert_local_invalid(self.post_write_raw(local=action_id))
        self.assert_datapath_intact()

    def test_bogus_remote_action_ids_rejected(self):
        """Made-up remote action ids fail the WR."""
        for action_id in BOGUS_ACTION_IDS + [self.max_index_action_id()]:
            with self.subTest(action_id=hex(action_id)):
                self.assert_remote_invalid(
                    self.post_write_raw(remote=action_id))
        self.assert_datapath_intact()

    def destroy_under_traffic(self, owner, remote):
        """
        Post a burst of signaled WRITEs and destroy the action halfway.
        Each WR completes either successfully or with the invalid-action
        error; nothing else, and the QP is healthy afterwards.
        """
        action_id, _ = owner.create_comp_action()
        for i in range(SMOKE_WR_COUNT):
            if i == SMOKE_WR_COUNT // 2:
                owner.destroy_comp_action(action_id)
            qp = self.start_write_wr(remote=action_id) if remote else \
                self.start_write_wr(local=action_id)
            qp.wr_complete()
        outcomes = {}
        for _ in range(SMOKE_WR_COUNT):
            wc = poll_raw_wc(self.client.cq)
            outcomes[wc.status] = outcomes.get(wc.status, 0) + 1
            if wc.status != ibv_wc_status.IBV_WC_SUCCESS:
                if remote:
                    self.assert_remote_invalid(wc)
                else:
                    self.assert_local_invalid(wc)
        self.assertGreater(outcomes.get(ibv_wc_status.IBV_WC_SUCCESS, 0), 0,
                           f'no WR completed before the destroy: {outcomes}')
        self.assert_datapath_intact()

    def test_destroy_local_action_under_traffic(self):
        """Destroying a local action with WRs in flight is survivable."""
        self.destroy_under_traffic(self.client, remote=False)

    def test_destroy_remote_action_under_traffic(self):
        """Destroying a remote action with WRs in flight is survivable."""
        self.destroy_under_traffic(self.server, remote=True)
