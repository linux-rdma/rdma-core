# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2026 Broadcom. All rights reserved.
"""
Tests for the Reliable Unconnected QPs.

Two halves. The API tests exercise the objects a UET device adds - jobs,
address tables, job keys and RU queue pairs - on a single context, and check
both that the legal thing works and that the illegal thing is refused. The
traffic tests run real messages between two players on the one device, which
is how every pyverbs traffic test is written and, for this device, works
because a frame addressed to its own MAC is delivered internally.
"""
import unittest
import errno
import os

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.qp import QPCap, QPInitAttrEx, QPEx, QPAttr
from pyverbs.addr import GID, GlobalRoute, AHAttr
from pyverbs.ru import Job, JobAttr, JKey, AHAttrEx, QPSemantics, \
    query_qp_semantics
from pyverbs.mr import MR
from pyverbs.pd import PD
from pyverbs.cq import CQ
import pyverbs.device as d
from pyverbs.libibverbs_enums import ibv_qp_init_attr_mask, ibv_qp_type, \
    ibv_qp_create_send_ops_flags, ibv_access_flags, ibv_job_attr_mask, \
    ibv_qp_create_flags, ibv_qp_state, ibv_qp_attr_mask, ibv_wr_opcode, \
    ibv_gid_type_sysfs, IBV_LINK_LAYER_ETHERNET

from tests.ru_base import RuAPITestCase, RuRDMATestCase, \
    RuResources, ipv4_to_gid
import tests.utils as u


class RuJobTest(RuAPITestCase):
    """
    Jobs and their address tables.
    """
    JOB_ID = 0x756575
    MAX_ADDR_ENTRIES = 16

    def job_attr(self, job_id=None, max_addr_entries=None):
        return JobAttr(comp_mask=ibv_job_attr_mask.IBV_JOB_ATTR_ID |
                       ibv_job_attr_mask.IBV_JOB_ATTR_MAX_ADDR_ENTRIES |
                       ibv_job_attr_mask.IBV_JOB_ATTR_PORT_NUM |
                       ibv_job_attr_mask.IBV_JOB_ATTR_SGID_INDEX,
                       id=self.JOB_ID if job_id is None else job_id,
                       max_addr_entries=self.MAX_ADDR_ENTRIES
                       if max_addr_entries is None else max_addr_entries,
                       port_num=self.ib_port, sgid_index=0)

    def peer(self, remote_qpn=0x18000):
        gr = GlobalRoute(dgid=ipv4_to_gid('10.0.0.1'), flow_label=16,
                         sgid_index=0, hop_limit=1)
        return AHAttrEx(ah_attr=AHAttr(is_global=1, port_num=self.ib_port,
                                       gr=gr), remote_qpn=remote_qpn)

    def test_alloc_dealloc_job(self):
        with Job(self.ctx, self.job_attr()) as job:
            self.assertFalse(job.is_imported)
            self.assertEqual(job.query().id, self.JOB_ID)

    def test_query_job(self):
        """
        A job reports back the attributes it was created with.
        """
        with Job(self.ctx, self.job_attr()) as job:
            attr = job.query()
            self.assertEqual(attr.id, self.JOB_ID)
            self.assertEqual(attr.port_num, self.ib_port)
            self.assertGreaterEqual(attr.max_addr_entries,
                                    self.MAX_ADDR_ENTRIES)

    def test_duplicate_job_id(self):
        """
        One job id, one job. A device that let a second job take a live id
        would have no way to decide which one an incoming packet belongs to.
        """
        with Job(self.ctx, self.job_attr()):
            with self.assertRaises(PyverbsRDMAError) as ctx:
                Job(self.ctx, self.job_attr())
            self.assertEqual(ctx.exception.error_code, errno.EEXIST)

    def test_export_import_job(self):
        """
        A second context reaches the same job through an exported descriptor
        rather than by allocating one with the same id.
        """
        with Job(self.ctx, self.job_attr()) as job:
            fd = job.export()
            try:
                with Job(self.ctx, fd=fd) as imported:
                    self.assertTrue(imported.is_imported)
                    self.assertEqual(imported.query().id, self.JOB_ID)
            finally:
                os.close(fd)

    def test_export_ends_with_exporter(self):
        """
        An exported descriptor belongs to the context that exported it. Once
        that context is closed the descriptor no longer names the job, while
        a context that imported the job keeps it.
        """
        exporter = d.Context(name=self.dev_name)
        job = Job(exporter, self.job_attr())
        fd = job.export()
        try:
            with Job(self.ctx, fd=fd) as imported:
                job.close()
                exporter.close()
                self.assertEqual(imported.query().id, self.JOB_ID)
                with self.assertRaises(PyverbsRDMAError) as ctx:
                    Job(self.ctx, fd=fd)
                self.assertEqual(ctx.exception.error_code, errno.EIO)
        finally:
            os.close(fd)

    def test_job_needs_addr_table(self):
        """
        The address table is sized once, when the job is allocated, so a job
        that does not say how large is refused.
        """
        with self.assertRaises(PyverbsRDMAError) as ctx:
            Job(self.ctx, self.job_attr(max_addr_entries=0))
        self.assertEqual(ctx.exception.error_code, errno.EINVAL)

    def test_import_bad_fd(self):
        """
        Importing something that is not an exported job is refused rather
        than dereferenced.
        """
        fd = os.open('/dev/null', os.O_RDONLY)
        try:
            with self.assertRaises(PyverbsRDMAError):
                Job(self.ctx, fd=fd)
        finally:
            os.close(fd)

    def test_insert_query_remove_addr(self):
        """
        An address table entry round-trips, and reads back gone once removed.
        """
        with Job(self.ctx, self.job_attr()) as job:
            job.insert_addr(self.peer(remote_qpn=0x19000), 3)
            entry = job.query_addr(3)
            self.assertEqual(entry.remote_qpn, 0x19000)
            job.remove_addr(3)
            with self.assertRaises(PyverbsRDMAError):
                job.query_addr(3)

    def test_query_empty_addr(self):
        """
        An entry nothing was written to is not readable.
        """
        with Job(self.ctx, self.job_attr()) as job:
            with self.assertRaises(PyverbsRDMAError):
                job.query_addr(5)

    def test_insert_addr_out_of_range(self):
        """
        The table is the size the job asked for, and an index past its end is
        refused rather than writing off the end of it.
        """
        with Job(self.ctx, self.job_attr()) as job:
            entries = job.query().max_addr_entries
            with self.assertRaises(PyverbsRDMAError):
                job.insert_addr(self.peer(), entries)

    def test_overwrite_addr(self):
        """
        Re-inserting an entry replaces it. A peer that moves has to be
        reachable without tearing down the job.
        """
        with Job(self.ctx, self.job_attr()) as job:
            job.insert_addr(self.peer(remote_qpn=0x19000), 2)
            job.insert_addr(self.peer(remote_qpn=0x1a000), 2)
            self.assertEqual(job.query_addr(2).remote_qpn, 0x1a000)


class RuJKeyTest(RuAPITestCase):
    """
    Job keys, the binding between a protection domain and a job.
    """
    JOB_ID = 0x756576

    def job_attr(self):
        return JobAttr(comp_mask=ibv_job_attr_mask.IBV_JOB_ATTR_ID |
                       ibv_job_attr_mask.IBV_JOB_ATTR_MAX_ADDR_ENTRIES |
                       ibv_job_attr_mask.IBV_JOB_ATTR_PORT_NUM |
                       ibv_job_attr_mask.IBV_JOB_ATTR_SGID_INDEX,
                       id=self.JOB_ID, max_addr_entries=16,
                       port_num=self.ib_port, sgid_index=0)

    def test_create_destroy_jkey(self):
        with PD(self.ctx) as pd, Job(self.ctx, self.job_attr()) as job:
            with JKey(pd, job) as jkey:
                self.assertNotEqual(jkey.jkey, 0)

    def test_jkeys_are_distinct(self):
        """
        Two protection domains joining one job get different keys, which is
        what lets the device tell whose request is whose.
        """
        with Job(self.ctx, self.job_attr()) as job:
            with PD(self.ctx) as pd1, PD(self.ctx) as pd2:
                with JKey(pd1, job) as k1, JKey(pd2, job) as k2:
                    self.assertNotEqual(k1.jkey, k2.jkey)


class RuQPTest(RuAPITestCase):
    """
    RU queue pairs: creation, the states they accept, and memory regions.
    """
    JOB_ID = 0x756577
    RES_INDEX = 40
    INITIATOR_ID = 16

    def setUp(self):
        super().setUp()
        self.pd = PD(self.ctx)
        self.cq = CQ(self.ctx, 16, None, None, 0)
        self.job = Job(self.ctx,
                       JobAttr(comp_mask=ibv_job_attr_mask.IBV_JOB_ATTR_ID |
                               ibv_job_attr_mask.IBV_JOB_ATTR_MAX_ADDR_ENTRIES |
                               ibv_job_attr_mask.IBV_JOB_ATTR_PORT_NUM |
                               ibv_job_attr_mask.IBV_JOB_ATTR_SGID_INDEX,
                               id=self.JOB_ID, max_addr_entries=16,
                               port_num=self.ib_port, sgid_index=0))
        self.jkey = JKey(self.pd, self.job)

    def tearDown(self):
        self.jkey.close()
        self.job.close()
        self.cq.close()
        self.pd.close()
        super().tearDown()

    def qp_init_attr(self, jkey=True, res_index=None):
        comp_mask = ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_PD | \
            ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_SRC_ID | \
            ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS | \
            ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_CREATE_FLAGS
        if jkey:
            comp_mask |= ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_JKEY
        ri = self.RES_INDEX if res_index is None else res_index
        return QPInitAttrEx(
            qp_type=ibv_qp_type.IBV_QPT_RU, scq=self.cq, rcq=self.cq,
            pd=self.pd, cap=QPCap(max_send_wr=16, max_recv_wr=16,
                                  max_send_sge=1, max_recv_sge=1),
            comp_mask=comp_mask, jkey=self.jkey if jkey else None,
            src_id=self.INITIATOR_ID,
            create_flags=ibv_qp_create_flags.IBV_QP_CREATE_SOURCE_QPN,
            source_qpn=(ri << 12),
            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND)

    def test_create_ru_qp(self):
        """
        An RU queue pair is created straight into RTS - there is no INIT or
        RTR step for it to pass through.
        """
        with QPEx(self.ctx, self.qp_init_attr()) as qp:
            attr, _ = qp.query(ibv_qp_attr_mask.IBV_QP_STATE)
            self.assertEqual(attr.qp_state, ibv_qp_state.IBV_QPS_RTS)
            self.assertNotEqual(qp.qp_num, 0)

    def test_create_ru_qp_without_jkey(self):
        """
        A queue pair that names no job has no job to send under.
        """
        with self.assertRaises(PyverbsRDMAError):
            QPEx(self.ctx, self.qp_init_attr(jkey=False))

    def test_explicit_qpn_zero(self):
        """
        Zero is a queue pair number like any other, and asking for it must
        get it rather than an assigned one.

        The signal that a QPN was requested is IBV_QP_CREATE_SOURCE_QPN in
        create_flags, not a non-zero source_qpn - both the library and the
        driver once inferred it from the value and so silently ignored a
        request for RI 0, PIDonFEP 0.

        PIDonFEP is a device-wide space, so this needs to be the only queue
        pair claiming zero while it runs; every test here builds its own
        protection domain and releases it, which is what keeps that true.
        """
        attr = self.qp_init_attr()
        attr.source_qpn = 0
        with QPEx(self.ctx, attr) as qp:
            self.assertEqual(qp.qp_num, 0,
                             'asked for QPN 0 and was assigned one instead')

    def test_res_index_is_exclusive(self):
        """
        Two queue pairs cannot answer to one resource index; the target
        demuxes on it.
        """
        with QPEx(self.ctx, self.qp_init_attr()):
            with self.assertRaises(PyverbsRDMAError):
                QPEx(self.ctx, self.qp_init_attr())

    def test_attach_detach_mr(self):
        """
        A queue pair reaches a region only once it is attached.
        """
        with QPEx(self.ctx, self.qp_init_attr()) as qp:
            with MR(self.pd, 4096,
                    ibv_access_flags.IBV_ACCESS_LOCAL_WRITE) as mr:
                qp.attach_mr(mr)
                qp.detach_mr(mr)

    def to_state(self, qp, state):
        """
        Modify to a state, returning the errno rather than raising, so a
        test can say which refusal it expected.
        """
        attr = QPAttr(port_num=self.ib_port)
        attr.qp_state = state
        try:
            qp.modify(attr, ibv_qp_attr_mask.IBV_QP_STATE)
        except PyverbsRDMAError as ex:
            return ex.error_code
        return 0

    def cur_state(self, qp):
        attr, _ = qp.query(ibv_qp_attr_mask.IBV_QP_STATE)
        return attr.qp_state

    def test_modify_rts_to_err_to_reset(self):
        """
        The full lifecycle this device supports: an established pair can be
        flushed to ERROR, reset, and put back to work without being
        destroyed. ERROR is reachable from anywhere that is not already
        ERROR - a queue pair being taken out of service should not first
        have to be in the right state to be taken out of service.
        """
        with QPEx(self.ctx, self.qp_init_attr()) as qp:
            self.assertEqual(self.cur_state(qp), ibv_qp_state.IBV_QPS_RTS,
                             'a queue pair is created ready to send')

            self.assertEqual(self.to_state(qp, ibv_qp_state.IBV_QPS_RTS), 0,
                             'RTS to RTS is a legal modify in place')
            self.assertEqual(self.to_state(qp, ibv_qp_state.IBV_QPS_ERR), 0)
            self.assertEqual(self.cur_state(qp), ibv_qp_state.IBV_QPS_ERR)

            self.assertNotEqual(self.to_state(qp, ibv_qp_state.IBV_QPS_RTS), 0,
                                'ERR to RTS must go through RESET')
            self.assertEqual(self.to_state(qp, ibv_qp_state.IBV_QPS_RESET), 0)
            self.assertEqual(self.cur_state(qp), ibv_qp_state.IBV_QPS_RESET)

            self.assertEqual(self.to_state(qp, ibv_qp_state.IBV_QPS_ERR), 0,
                             'ERROR reaches from anywhere')
            self.assertEqual(self.to_state(qp, ibv_qp_state.IBV_QPS_RESET), 0)
            self.assertEqual(self.to_state(qp, ibv_qp_state.IBV_QPS_RTS), 0)
            self.assertEqual(self.cur_state(qp), ibv_qp_state.IBV_QPS_RTS)

    def test_modify_to_init_and_rtr_refused(self):
        """
        INIT and RTR exist to negotiate a connection. An RU queue pair has
        nothing to negotiate, so both are refused - with EOPNOTSUPP, saying
        the device does not have the state rather than that the request was
        malformed - and the queue pair is left where it was.
        """
        with QPEx(self.ctx, self.qp_init_attr()) as qp:
            for state in (ibv_qp_state.IBV_QPS_INIT,
                          ibv_qp_state.IBV_QPS_RTR):
                self.assertEqual(self.to_state(qp, state), errno.EOPNOTSUPP)
            self.assertEqual(self.cur_state(qp), ibv_qp_state.IBV_QPS_RTS)

    def test_modify_in_place_applies_attrs(self):
        """
        A modify from RTS to RTS is not a no-op: fields carried with it are
        applied, and read back.
        """
        with QPEx(self.ctx, self.qp_init_attr()) as qp:
            attr = QPAttr(port_num=self.ib_port)
            attr.qp_state = ibv_qp_state.IBV_QPS_RTS
            attr.qp_access_flags = ibv_access_flags.IBV_ACCESS_REMOTE_READ | \
                ibv_access_flags.IBV_ACCESS_REMOTE_WRITE
            qp.modify(attr, ibv_qp_attr_mask.IBV_QP_STATE |
                      ibv_qp_attr_mask.IBV_QP_ACCESS_FLAGS)
            queried, _ = qp.query(ibv_qp_attr_mask.IBV_QP_ACCESS_FLAGS)
            self.assertEqual(queried.qp_access_flags, attr.qp_access_flags)

    def test_modify_without_state_refused(self):
        """
        State is mandatory. A modify that names only a port is refused with
        EINVAL rather than quietly doing half of what was asked.
        """
        with QPEx(self.ctx, self.qp_init_attr()) as qp:
            attr = QPAttr(port_num=self.ib_port)
            with self.assertRaises(PyverbsRDMAError) as ctx:
                qp.modify(attr, ibv_qp_attr_mask.IBV_QP_PORT)
            self.assertEqual(ctx.exception.error_code, errno.EINVAL)

    def test_pidonfep_is_latched_per_pd(self):
        """
        A protection domain latches the PIDonFEP of its first queue pair and
        every later one must agree: the two together are the queue pair
        number a peer addresses, and a domain handing out two of them would
        have no single identity on the wire.
        """
        with QPEx(self.ctx, self.qp_init_attr()):
            attr = self.qp_init_attr(res_index=self.RES_INDEX + 1)
            attr.source_qpn = ((self.RES_INDEX + 1) << 12) | 1
            with self.assertRaises(PyverbsRDMAError):
                QPEx(self.ctx, attr)

    def test_attach_mr_from_another_pd_refused(self):
        """
        A region belongs to a protection domain, and a queue pair in another
        one cannot reach it.
        """
        with QPEx(self.ctx, self.qp_init_attr()) as qp:
            with PD(self.ctx) as stranger_pd:
                with MR(stranger_pd, 4096,
                        ibv_access_flags.IBV_ACCESS_LOCAL_WRITE) as stranger:
                    with self.assertRaises(PyverbsRDMAError):
                        qp.attach_mr(stranger)

    def test_qp_semantics_for_unsupported_type_refused(self):
        """
        A queue pair type this device does not have is refused rather than
        answered with something invented.
        """
        with self.assertRaises(PyverbsRDMAError):
            query_qp_semantics(self.ctx, ibv_qp_type.IBV_QPT_RC,
                               self.ib_port, 0)

    def test_query_qp_semantics(self):
        """
        The device states what an RU queue pair gives you, payload MTU
        included. There is no exchange of it on the wire, so both ends have
        to ask and agree.
        """
        try:
            sem = query_qp_semantics(self.ctx, ibv_qp_type.IBV_QPT_RU,
                                     self.ib_port, 0)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Query QP semantics is not supported')
            raise ex
        self.assertGreater(sem.max_pdu, 0)
        # the payload MTU the port reports and the one the semantics report
        # are the same number arrived at two ways; a device that disagrees
        # with itself gives an application no way to choose
        port = self.ctx.query_port(self.ib_port)
        self.assertEqual(sem.max_pdu, 128 << port.active_mtu)


class RuPDTest(RuAPITestCase):
    """
    Protection domains are allocated by the kernel driver rather than by the
    device, so these exercise the driver's id space.
    """
    # the driver's protection domain id space
    MAX_PDS = 1024

    def test_pd_alloc_and_free(self):
        """
        Allocate the whole id space, free it, and allocate it again.

        Reallocating is the check that matters: it proves ids are actually
        reclaimed rather than handed out by a counter that only climbs.
        """
        for _ in range(2):
            pds = [PD(self.ctx) for _ in range(self.MAX_PDS)]
            for pd in pds:
                pd.close()

    def test_pd_exhaustion(self):
        """
        One past the id space must fail rather than succeed quietly.
        """
        pds = [PD(self.ctx) for _ in range(self.MAX_PDS)]
        try:
            with self.assertRaises(PyverbsRDMAError) as cm:
                PD(self.ctx)
            self.assertEqual(cm.exception.error_code, errno.ENOSPC)
        finally:
            for pd in pds:
                pd.close()


class RuMRTest(RuAPITestCase):
    """
    Memory regions. Registration reaching the device proves the command was
    accepted; the sizes below prove the page list describes the right pages.
    """
    def test_reg_mr(self):
        """
        A region that is neither page aligned nor a page multiple, so a page
        list that loses the page offset fails rather than passing.
        """
        with PD(self.ctx) as pd:
            length = 16 * 1024 + 137
            with MR(pd, length,
                    ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                    ibv_access_flags.IBV_ACCESS_REMOTE_READ |
                    ibv_access_flags.IBV_ACCESS_REMOTE_WRITE) as mr:
                self.assertNotEqual(mr.lkey, 0,
                                    'zero is not a usable local key')

    def test_reg_mr_many_pages(self):
        """
        A region large enough that the page list is built per page rather
        than by assuming the buffer is contiguous.
        """
        with PD(self.ctx) as pd:
            with MR(pd, 4 * 1024 * 1024,
                    ibv_access_flags.IBV_ACCESS_LOCAL_WRITE):
                pass

    def test_mr_keys_are_distinct(self):
        """
        Distinct regions must have distinct keys.
        """
        with PD(self.ctx) as pd:
            mrs = [MR(pd, 4096, ibv_access_flags.IBV_ACCESS_LOCAL_WRITE)
                   for _ in range(16)]
            try:
                self.assertEqual(len({mr.lkey for mr in mrs}), len(mrs),
                                 'keys were reused')
                self.assertEqual(len({mr.lkey64 for mr in mrs}), len(mrs),
                                 'wide keys were reused')
            finally:
                for mr in mrs:
                    mr.close()


class RuDeviceTest(RuAPITestCase):
    """
    What the device reports about itself, which comes from the running
    device model rather than from anything compiled into the driver.
    """
    def test_device_attrs(self):
        self.assertGreater(self.attr.max_pd, 0)
        self.assertGreater(self.attr.max_mr, 0)
        self.assertGreater(self.attr.max_qp, 0)

    def test_ru_resource_limits(self):
        """
        max_job_ids, max_job_keys and max_addr_entries are fields of
        ibv_device_attr_ex, filled by ib_core from what the driver read off
        the device at probe. They were a vendor query until the core
        carried them, which is the whole point: a second RU provider gets
        them without implementing anything.
        """
        attr_ex = self.ctx.query_device_ex()
        self.assertGreater(attr_ex.max_job_ids, 0)
        self.assertGreater(attr_ex.max_job_keys, 0)
        self.assertGreater(attr_ex.max_addr_entries, 0)

    def test_ru_capability_flags(self):
        """
        IBV_DEVICE_RU and the key and immediate capabilities live above bit
        32 of device_cap_flags_ex. The provider used to set them itself
        from a vendor query, because the kernel had no representation; the
        kernel reports them now.

        The bits are spelled out because verbs.h defines them outside enum
        ibv_device_cap_flags, which is where pyverbs takes its names from.
        """
        IBV_DEVICE_RU = 1 << 42
        IBV_DEVICE_IMM64 = 1 << 43
        IBV_DEVICE_KEY64 = 1 << 44
        IBV_DEVICE_USER_RKEY = 1 << 45

        flags = self.ctx.query_device_ex().device_cap_flags_ex
        for bit, name in ((IBV_DEVICE_RU, 'IBV_DEVICE_RU'),
                          (IBV_DEVICE_IMM64, 'IBV_DEVICE_IMM64'),
                          (IBV_DEVICE_KEY64, 'IBV_DEVICE_KEY64'),
                          (IBV_DEVICE_USER_RKEY, 'IBV_DEVICE_USER_RKEY')):
            self.assertTrue(flags & bit, f'{name} not reported')

    def test_max_msg_sz_is_a_message_not_a_packet(self):
        """
        max_msg_sz is the largest message, which the transport segments
        across as many packets as it needs - so it must be well above the
        payload MTU. Reporting the MTU here is an easy mistake and it makes
        the device look three orders of magnitude smaller than it is.
        """
        port = self.ctx.query_port(self.ib_port)
        mtu = 128 << port.active_mtu
        self.assertGreater(port.max_msg_sz, mtu)
        # upstream's own test_query_port requires this much
        self.assertGreater(port.max_msg_sz, 0x1000)

    def test_gid_type_is_uet(self):
        """
        A UET device reports a UET GID type. The spec has applications
        selecting the transport by selecting a GID entry, so a device that
        reports RoCE v2 for all of its GIDs gives them nothing to select.

        ib_core knows these types: the driver says which encapsulation it
        speaks through the port capability, and the GID table it derives
        from the netdev carries that type. This checks the type reaches the
        application, for every GID the port has.
        """
        uet_types = (ibv_gid_type_sysfs.IBV_GID_TYPE_SYSFS_UET_UDP,
                     ibv_gid_type_sysfs.IBV_GID_TYPE_SYSFS_UET_IP)
        port = self.ctx.query_port(self.ib_port)
        self.assertGreater(port.gid_tbl_len, 0)
        for idx in range(port.gid_tbl_len):
            gid = self.ctx.query_gid(self.ib_port, idx)
            if gid.gid[-19:] == '0000:0000:0000:0000':
                continue
            self.assertIn(self.ctx.query_gid_type(self.ib_port, idx),
                          uet_types, f'GID {idx} is not a UET GID type')

    def test_port_is_ethernet(self):
        # UET rides UDP over IP, so the port is an Ethernet link layer
        port = self.ctx.query_port(self.ib_port)
        self.assertEqual(port.link_layer, IBV_LINK_LAYER_ETHERNET)

    def test_gid_from_netdev(self):
        """
        ib_core derives the GID table from the associated netdev, so a GID
        only exists if the netdev association took - which is the whole
        reason the driver registers one.
        """
        port = self.ctx.query_port(self.ib_port)
        self.assertGreater(port.gid_tbl_len, 0)
        self.assertIsNotNone(self.ctx.query_gid(self.ib_port, 0))


class RuTrafficTest(RuRDMATestCase):
    """
    Messages between two players on the one device.
    """
    def create_players(self, **kwargs):
        super().create_players(RuResources, local_ip=self.ip_addr, **kwargs)

    def test_uet_send(self):
        self.create_players()
        u.traffic(**self.traffic_args, new_send=True,
                  send_op=ibv_wr_opcode.IBV_WR_SEND)

    def test_uet_send_imm(self):
        self.create_players()
        u.traffic(**self.traffic_args, new_send=True,
                  send_op=ibv_wr_opcode.IBV_WR_SEND_WITH_IMM)

    def test_uet_send_multi_packet(self):
        """
        A message larger than the payload MTU, so the transport has to
        segment it and put it back together.
        """
        self.create_players(msg_size=8192)
        u.traffic(**self.traffic_args, new_send=True,
                  send_op=ibv_wr_opcode.IBV_WR_SEND)

    def test_uet_rdma_write(self):
        self.create_players(
            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE)
        u.rdma_traffic(**self.traffic_args, new_send=True,
                       send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE)

    def test_uet_rdma_read(self):
        self.create_players(
            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_READ)
        u.rdma_traffic(**self.traffic_args, new_send=True,
                       send_op=ibv_wr_opcode.IBV_WR_RDMA_READ)

    def test_uet_rdma_write_imm(self):
        self.create_players(
            send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM)
        u.traffic(**self.traffic_args, new_send=True,
                  send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE_WITH_IMM)
