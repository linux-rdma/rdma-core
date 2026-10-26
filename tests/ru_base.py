# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2026 Broadcom. All rights reserved.
"""
Base resources for devices supporting reliable unconnected queue pairs.

Such a device does not connect queue pairs to each other. Every endpoint
taking part in a transfer joins a *job*, named by a job id and shared by all
of them, and addresses its peers through that job's address table: a send
names an index into the table rather than a destination queue pair. A queue
pair is created straight into RTS and stays there.

Two things follow for a pyverbs test, and both shape this file:

* Traffic is loopback. tests/base.py create_players() builds both sides on
  the same device, and the device delivers a frame addressed to its own MAC
  internally rather than putting it on the wire.

* The two sides must share one job, because an incoming packet's job id has
  to match the receiving buffer's. A device refuses a second job with a job
  id already live, so the first player allocates the job and the second
  imports it over an exported descriptor - which is what export/import is
  for.
"""
import unittest
import errno
import os

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.qp import QPCap, QPInitAttrEx, QPEx
from pyverbs.addr import GID, GlobalRoute, AHAttr
from pyverbs.ru import Job, JobAttr, JKey, AHAttrEx
import pyverbs.device as d
from pyverbs.libibverbs_enums import ibv_qp_init_attr_mask, ibv_qp_type, \
    ibv_qp_create_send_ops_flags, ibv_access_flags, ibv_job_attr_mask, \
    ibv_qp_create_flags

from tests.base import PyverbsAPITestCase, RDMATestCase, TrafficResources
import tests.utils


# Reliable unconnected support is a device capability, not a particular
# part: everything these tests use is ib_core's, so any device advertising
# it should pass them. The bit is above 32, so only the extended query
# reports it.
IBV_DEVICE_RU = 1 << 42


def is_ru_dev(ctx):
    return bool(ctx.query_device_ex().device_cap_flags_ex & IBV_DEVICE_RU)


def skip_if_not_ru_dev(ctx):
    if not is_ru_dev(ctx):
        raise unittest.SkipTest('Device does not support reliable '
                                'unconnected queue pairs')


def ipv4_to_gid(ip_addr):
    """
    The GID a UET address entry carries for an IPv4 peer: the four address
    bytes in the low half, nothing else set.
    :param ip_addr: Dotted-quad address string
    :return: A GID object
    """
    octets = [int(o) for o in ip_addr.split('.')]
    if len(octets) != 4:
        raise ValueError(f'{ip_addr} is not an IPv4 address')
    return GID('0000:0000:0000:0000:0000:0000:'
               f'{octets[0]:02x}{octets[1]:02x}:{octets[2]:02x}{octets[3]:02x}')


class SharedJob:
    """
    The one job both players use, and the order they arrived in.

    The first player through allocates it and exports a descriptor; the
    second imports that descriptor rather than allocating a job of its own,
    which a device with the job id already live would refuse. The player
    index it hands back is what keeps the two sides off each other's
    resource indices and address table entries.
    """
    fd = None
    players = 0

    @classmethod
    def get(cls, ctx, job_attr):
        index = cls.players
        cls.players += 1
        if cls.fd is not None:
            return Job(ctx, fd=cls.fd), index
        job = Job(ctx, job_attr)
        cls.fd = job.export()
        return job, index

    @classmethod
    def reset(cls):
        if cls.fd is not None:
            os.close(cls.fd)
            cls.fd = None
        cls.players = 0


class RuAPITestCase(PyverbsAPITestCase):
    def setUp(self):
        super().setUp()
        skip_if_not_ru_dev(self.ctx)


class RuRDMATestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        skip_if_not_ru_dev(d.Context(name=self.dev_name))
        if self.ip_addr is None:
            raise unittest.SkipTest('UET traffic needs the device to have an '
                                    'IP address')
        SharedJob.reset()

    def tearDown(self):
        SharedJob.reset()
        super().tearDown()

    def sync_remote_attr(self):
        """
        What each side needs to reach the other's region. UET addresses a
        region by an offset from its base rather than by a virtual address,
        and its keys are 64 bits wide - the narrow ones are a truncation the
        device will not accept.
        """
        self.server.rkey = self.client.mr.rkey64
        self.server.raddr = 0
        self.client.rkey = self.server.mr.rkey64
        self.client.raddr = 0


class RuResources(TrafficResources):
    """
    A UET player: a job, a job key, and one or more RU queue pairs that reach
    the other player through the job's shared address table.
    """
    # The JobID is 24 bits on the wire (uet_pkt_hdr.h,
    # UET_SES_REQ_JOB_ID_MASK). A wider id is accepted at allocation and
    # then truncated in the header, so the far end answers Bad Job ID.
    JOB_ID = 0x756574
    INITIATOR_ID = 16
    MAX_ADDR_ENTRIES = 16
    # Resource indices this test suite owns. A queue pair that shares an
    # index with another receives the other's stragglers, so the two players
    # are kept a block apart.
    RES_INDEX_BASE = 24

    def __init__(self, dev_name, ib_port, gid_index, local_ip=None,
                 send_ops_flags=ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND,
                 qp_count=1, msg_size=512, access_flags=None):
        """
        :param local_ip: The device's own IP address, which is also the peer's
                         since both players are on this device
        :param send_ops_flags: Send opcodes the queue pairs support
        :param qp_count: Number of queue pairs per player
        :param msg_size: Message size
        :param access_flags: Access flags for the memory region
        """
        if local_ip is None:
            raise unittest.SkipTest('UET traffic needs the device to have an '
                                    'IP address')
        self.local_ip = local_ip
        self.send_ops_flags = send_ops_flags
        self.access_flags = access_flags if access_flags is not None else \
            (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
             ibv_access_flags.IBV_ACCESS_REMOTE_WRITE |
             ibv_access_flags.IBV_ACCESS_REMOTE_READ)
        self.job = None
        self.jkey = None
        self.player = 0
        self.remote_addr_idx = None
        super().__init__(dev_name, ib_port, gid_index, qp_count=qp_count,
                         msg_size=msg_size)

    def init_resources(self):
        # the job has to exist before the queue pairs that join it
        self.create_job()
        super().init_resources()

    def create_job(self):
        attr = JobAttr(comp_mask=ibv_job_attr_mask.IBV_JOB_ATTR_ID |
                       ibv_job_attr_mask.IBV_JOB_ATTR_MAX_ADDR_ENTRIES |
                       ibv_job_attr_mask.IBV_JOB_ATTR_PORT_NUM |
                       ibv_job_attr_mask.IBV_JOB_ATTR_SGID_INDEX,
                       id=self.JOB_ID,
                       max_addr_entries=self.MAX_ADDR_ENTRIES,
                       port_num=self.ib_port, sgid_index=0)
        try:
            self.job, self.player = SharedJob.get(self.ctx, attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('UET jobs are not supported')
            raise ex
        self.jkey = JKey(self.pd, self.job)

    def res_index(self, qp_idx):
        """
        The resource index a queue pair answers to. The two players take
        neighbouring blocks so that no index is ever shared.
        """
        return self.RES_INDEX_BASE + self.player * self.qp_count + qp_idx

    @property
    def pid_on_fep(self):
        """
        The process identifier the queue pair numbers carry. It is claimed
        device-wide by the first protection domain that uses it, so the two
        players - which have a protection domain each - cannot share one.
        """
        return self.player

    def addr_index(self, qp_idx):
        """
        The address table entry this player writes its peer into. The table
        belongs to the shared job, so the two players must not write the same
        entry.
        """
        return self.player * self.qp_count + qp_idx

    def create_mr(self):
        self.mr = tests.utils.create_custom_mr(self, self.access_flags)

    def create_qp_cap(self):
        return QPCap(max_send_wr=self.num_msgs, max_recv_wr=self.num_msgs,
                     max_send_sge=1, max_recv_sge=1)

    def create_qp_init_attr(self, qp_idx=0):
        comp_mask = ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_PD | \
            ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_JKEY | \
            ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_SRC_ID | \
            ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS | \
            ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_CREATE_FLAGS
        return QPInitAttrEx(qp_type=ibv_qp_type.IBV_QPT_RU, scq=self.cq,
                            rcq=self.cq, pd=self.pd, cap=self.create_qp_cap(),
                            comp_mask=comp_mask, jkey=self.jkey,
                            src_id=self.INITIATOR_ID,
                            create_flags=ibv_qp_create_flags.IBV_QP_CREATE_SOURCE_QPN,
                            source_qpn=(self.res_index(qp_idx) << 12) |
                                       self.pid_on_fep,
                            send_ops_flags=self.send_ops_flags)

    def create_qps(self):
        """
        Create the RU queue pairs and attach the memory region to each. A UET
        queue pair reaches a region only once the region is attached to it.
        """
        try:
            for qp_idx in range(self.qp_count):
                qp = QPEx(self.ctx, self.create_qp_init_attr(qp_idx))
                qp.attach_mr(self.mr)
                self.qps.append(qp)
                self.qps_num.append(qp.qp_num)
                # RU queue pairs carry no packet serial number of their own
                self.psns.append(0)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('RU QPs are not supported')
            raise ex

    def pre_run(self, rpsns, rqps_num):
        """
        Write the peer into the job's address table. The peer is on this
        device, so the address is our own; what distinguishes it is the
        remote queue pair number, which carries the peer's resource index.
        """
        self.rpsns = rpsns
        self.rqps_num = rqps_num
        self.remote_addr_idx = []
        gr = GlobalRoute(dgid=ipv4_to_gid(self.local_ip),
                         flow_label=self.INITIATOR_ID, sgid_index=0,
                         hop_limit=1)
        for qp_idx in range(self.qp_count):
            ah_attr = AHAttr(is_global=1, port_num=self.ib_port, gr=gr)
            entry = AHAttrEx(ah_attr=ah_attr, remote_qpn=rqps_num[qp_idx])
            idx = self.addr_index(qp_idx)
            self.job.insert_addr(entry, idx)
            self.remote_addr_idx.append(idx)
        self.to_rts()

    def to_rts(self):
        """
        A UET queue pair is created in RTS. Nothing to do.
        """
        pass
