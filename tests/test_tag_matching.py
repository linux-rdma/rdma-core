# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2022 Nvidia, Inc. All rights reserved. See COPYING file

import unittest
import errno
import time

from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from pyverbs.cq import CqInitAttrEx, PollCqAttr, CQEX
from pyverbs.srq import SrqInitAttrEx, OpsWr, SRQ
from tests.base import RDMATestCase, RCResources
from pyverbs.wr import SGE, RecvWR, SendWR
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.qp import QPAttr, QPCap
from pyverbs.mr import MR
import pyverbs.enums as e
import tests.utils as u

TAG_MASK = 0xffff
TMH_SIZE = 16
SYNC_WRID = 27
HW_LIMITAION = 33
FIXED_SEND_TAG = 0x1234
# Tag matching header lengths and offsets
TM_OPCODE_OFFSET = 0
TM_OPCODE_LENGTH = 1
TM_TAG_OFFSET = 8
TM_TAG_LENGTH = 8
RNDV_VA_OFFSET = 0x10
RNDV_VA_LENGTH = 8
RNDV_RKEY_OFFSET = 0x18
RNDV_RKEY_LENGTH = 4
RNDV_LEN_OFFSET = 0x1c
RNDV_LEN_LENGTH = 4


def write_tm_header(mr, tag, tm_opcode):
    """
    Build a tag matching header, the header is written on the base address of the given mr.
    """
    mr.write(int(tm_opcode).to_bytes(1, byteorder='big'), TM_OPCODE_LENGTH, TM_OPCODE_OFFSET)
    mr.write(int(tag).to_bytes(8, byteorder='big'), TM_TAG_LENGTH, TM_TAG_OFFSET)


def write_rndvu_header(player, mr, tag, tm_opcode):
    """
    Build a tag matching header + rendezvous header
    """
    write_tm_header(mr=mr, tag=tag, tm_opcode=tm_opcode)
    mr.write(int(player.mr.buf).to_bytes(8, byteorder='big'),
             RNDV_VA_LENGTH, RNDV_VA_OFFSET)
    mr.write(int(player.mr.rkey).to_bytes(4, byteorder='big'),
             RNDV_RKEY_LENGTH, RNDV_RKEY_OFFSET)
    mr.write(int(player.msg_size).to_bytes(4, byteorder='big'),
             RNDV_LEN_LENGTH, RNDV_LEN_OFFSET)


class TMResources(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, qp_count=1, with_srq=True):
        self.unexp_cnt = 0
        super().__init__(dev_name=dev_name, ib_port=ib_port,
                         gid_index=gid_index, with_srq=with_srq,
                         qp_count=qp_count)
        if not self.ctx.query_device_ex().tm_caps.flags & e.IBV_TM_CAP_RC:
            raise unittest.SkipTest("Tag matching is not supported")

    def create_srq(self):
        srq_attr = SrqInitAttrEx()
        srq_attr.comp_mask = e.IBV_SRQ_INIT_ATTR_TYPE | e.IBV_SRQ_INIT_ATTR_PD | \
                             e.IBV_SRQ_INIT_ATTR_CQ | e.IBV_SRQ_INIT_ATTR_TM
        srq_attr.srq_type = e.IBV_SRQT_TM
        srq_attr.pd = self.pd
        srq_attr.cq = self.cq
        srq_attr.max_num_tags = self.ctx.query_device_ex().tm_caps.max_num_tags
        srq_attr.max_ops = 10
        self.srq = SRQ(self.ctx, srq_attr)

    def create_cq(self):
        cq_init_attr = CqInitAttrEx(wc_flags=e.IBV_WC_EX_WITH_TM_INFO | e.IBV_WC_STANDARD_FLAGS)
        try:
            self.cq = CQEX(self.ctx, cq_init_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Extended CQ is not supported')
            raise ex

    def create_qp_cap(self):
        return QPCap(max_send_wr=0, max_send_sge=0, max_recv_wr=0, max_recv_sge=0) if self.with_srq \
            else QPCap(max_send_wr=4, max_send_sge=1, max_recv_wr=self.num_msgs, max_recv_sge=4)

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_attr.qp_access_flags = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_READ | \
                                  e.IBV_ACCESS_REMOTE_WRITE
        return qp_attr

    def create_mr(self):
        access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_READ | e.IBV_ACCESS_REMOTE_WRITE
        self.mr = MR(self.pd, self.msg_size, access=access)


class TMTest(RDMATestCase):
    """
    Test various functionalities of tag matching.
    """

    def setUp(self):
        super().setUp()
        self.server = None
        self.client = None
        self.iters = 10
        self.curr_unexpected_cnt = 1
        self.create_players(TMResources)
        self.prepare_to_traffic()

    def create_players(self, resource):
        self.client = resource(**self.dev_info, with_srq=False)
        self.server = resource(**self.dev_info)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)

    def prepare_to_traffic(self):
        """
        Prepare the TM SRQ for tag matching traffic by posing 33
        (hardware limitation) recv WR for fill his queue
        """
        for _ in range(self.server.qp_count):
            u.post_recv(self.client, u.get_recv_wr(self.client), num_wqes=HW_LIMITAION)
            u.post_recv(self.server, u.get_recv_wr(self.server), num_wqes=HW_LIMITAION)

    def get_send_elements(self, tag=0, tm_opcode=e.IBV_TMH_EAGER, tm=True):
        """
        Creates a single SGE and a single Send WR for client QP. The content
        of the message is 'c' for client side. The function also generates TMH
        and RVH to the msg
        :return: Send wr and expected msg that is read from mr
        """
        sge = SGE(self.client.mr.buf, self.client.msg_size, self.client.mr_lkey)
        if tm_opcode == e.IBV_TMH_RNDV:
            max_rndv_hdr_size = self.server.ctx.query_device_ex().tm_caps.max_rndv_hdr_size
            sge.length = max_rndv_hdr_size if max_rndv_hdr_size <= self.server.mr.length else \
                self.server.mr.length
            write_rndvu_header(player=self.client, mr=self.client.mr, tag=tag, tm_opcode=tm_opcode)
            c_recv_wr = RecvWR(wr_id=tag, sg=[sge], num_sge=1)
            # Need to post_recv client because the server sends rdma-read request to client
            u.post_recv(self.client, c_recv_wr)
        else:
            msg = self.client.msg_size * 'c'
            self.client.mr.write(msg, self.client.msg_size)
            if tm:
                write_tm_header(mr=self.client.mr, tag=tag, tm_opcode=tm_opcode)

        send_wr = SendWR(opcode=e.IBV_WR_SEND, num_sge=1, sg=[sge])
        exp_msg = self.client.mr.read(self.client.msg_size, 0)
        return send_wr, exp_msg

    def get_exp_wc_flags(self, tm_opcode=e.IBV_TMH_EAGER, fixed_send_tag=None):
        if tm_opcode == e.IBV_TMH_RNDV:
            return e.IBV_WC_TM_MATCH
        return 0 if fixed_send_tag else e.IBV_WC_TM_MATCH | e.IBV_WC_TM_DATA_VALID

    def get_exp_params(self, fixed_send_tag=None, send_tag=0, tm_opcode=e.IBV_TMH_EAGER):
        wc_flags = self.get_exp_wc_flags(tm_opcode=tm_opcode, fixed_send_tag=fixed_send_tag)
        return (fixed_send_tag, 0, 0, wc_flags) if fixed_send_tag else \
            (send_tag, send_tag, send_tag, wc_flags)

    def validate_msg(self, actual_msg, expected_msg, msg_size):
        if actual_msg[0:msg_size] != expected_msg[0:msg_size]:
            raise PyverbsError(f'Data validation failure: expected {expected_msg}, '
                               f'received {actual_msg}')

    def verify_cqe(self, actual_cqe, wr_id=0, opcode=None, wc_flags=0, tag=0, is_server=True):
        expected_cqe = {'wr_id': wr_id, 'opcode': opcode, 'wc_flags': wc_flags}
        if is_server:
            expected_cqe['tag'] = tag
        for key in expected_cqe:
            if expected_cqe[key] != actual_cqe[key]:
                raise PyverbsError(f'CQE validation failure: {key} expected value: '
                                   f'{expected_cqe[key]}, received {actual_cqe[key]}')

    def validate_exp_recv_params(self, exp_parm, recv_parm, descriptor):
        if exp_parm != recv_parm:
            raise PyverbsError(f'{descriptor} validation failure: expected value {exp_parm}, '
                               f'received {recv_parm}')

    def poll_cq_ex(self, cqex, is_server=True, to_valid=True):
        start = time.perf_counter()
        poll_attr = PollCqAttr()
        ret = cqex.start_poll(poll_attr)
        while ret == 2 and (time.perf_counter() - start < u.POLL_CQ_TIMEOUT):
            ret = cqex.start_poll(poll_attr)
        if ret != 0:
            raise PyverbsRDMAErrno('Failed to poll CQ - got a timeout')
        if cqex.status != e.IBV_WC_SUCCESS:
            raise PyverbsError(f'Completion status is {cqex.status}')
        actual_cqe_dict = {}
        if to_valid:
            recv_flags = cqex.read_wc_flags()
            recv_opcode = cqex.read_opcode()
            actual_cqe_dict = {'wr_id': cqex.wr_id, 'opcode': cqex.read_opcode(),
                               'wc_flags': cqex.read_wc_flags()}
            if is_server:
                actual_cqe_dict['tag'] = cqex.read_tm_info().tag
            if recv_opcode == e.IBV_WC_TM_RECV and not \
                    (recv_flags & (e.IBV_WC_TM_MATCH | e.IBV_WC_TM_DATA_VALID)):
                # In case of receiving unexpected tag, HW doesn't return such wc_flags
                # updadte unexpected count and sync is required.
                self.server.unexp_cnt += 1
                cqex.end_poll()
                self.post_sync()
                return actual_cqe_dict
            if recv_opcode == e.IBV_WC_TM_ADD and (recv_flags & e.IBV_WC_TM_SYNC_REQ):
                # These completion is complemented by the IBV_WC_TM_SYNC_REQ flag,
                # which indicates whether further HW synchronization is needed.
                cqex.end_poll()
                self.post_sync()
                return actual_cqe_dict

        cqex.end_poll()
        return actual_cqe_dict

    def post_sync(self, wr_id=SYNC_WRID):
        """
        Whenever HW deems a message unexpected, tag matching must be disabled
        for new tags until SW and HW synchronize. This synchronization is
        achieved by reporting to HW the number of unexpected messages handled by
        SW (with respect to the current posted tags). When the SW and HW are in
        sync, tag matching resumes normally.
        """
        wr = OpsWr(wr_id=wr_id, opcode=e.IBV_WR_TAG_SYNC, unexpected_cnt=self.server.unexp_cnt,
                   recv_wr_id=wr_id, flags=e.IBV_OPS_SIGNALED | e.IBV_OPS_TM_SYNC)
        self.server.srq.post_srq_ops(wr)
        actual_cqe = self.poll_cq_ex(cqex=self.server.cq)
        self.verify_cqe(actual_cqe=actual_cqe, wr_id=SYNC_WRID, opcode=e.IBV_WC_TM_SYNC)

    def post_recv_tm(self, tag, wrid):
        """
        Create opswr according to user chooce of wr_id and a tag
        and post recv it with the srq and the special func
        post_srq_ops that posted opswr wqe.
        :return: The opswr'
        """
        recv_sge = SGE(self.server.mr.buf, self.server.msg_size, self.server.mr.lkey)
        wr = OpsWr(wr_id=wrid, unexpected_cnt=self.server.unexp_cnt, recv_wr_id=wrid, num_sge=1,
                   tag=tag, mask=TAG_MASK, sg_list=[recv_sge])
        self.server.srq.post_srq_ops(wr)
        return wr

    def build_expected_and_recv_msgs(self, exp_msg, tm_opcode=e.IBV_TMH_EAGER, fixed_send_tag=None):
        no_tag = tm_opcode == e.IBV_TMH_RNDV or fixed_send_tag
        actual_msg = self.server.mr.read(self.server.msg_size, 0)
        return (actual_msg, exp_msg, self.client.msg_size) if no_tag else \
            (actual_msg.decode(), (self.client.msg_size - TMH_SIZE) * 'c',
             self.client.msg_size - TMH_SIZE)

    def tm_traffic(self, tm_opcode=e.IBV_TMH_EAGER, fixed_send_tag=None):
        """
        Runs Tag matching traffic between two sides (server and client)
        :param tm_opcode: The TM opcode in the send WR
        :param fixed_send_tag: If not None complitions are expected to be with no tag
        """
        tags_list = list(range(1, self.iters))
        for recv_tag in tags_list:
            self.post_recv_tm(tag=recv_tag, wrid=recv_tag)
            actual_cqe = self.poll_cq_ex(cqex=self.server.cq)
            self.verify_cqe(actual_cqe=actual_cqe, wr_id=recv_tag, opcode=e.IBV_WC_TM_ADD)
        tags_list.reverse()
        for send_tag in tags_list:
            send_tag, tag_exp, wrid_exp, wc_flags = self.get_exp_params(
                fixed_send_tag=fixed_send_tag, send_tag=send_tag, tm_opcode=tm_opcode)
            send_wr, exp_msg = self.get_send_elements(tag=send_tag, tm_opcode=tm_opcode)
            u.send(self.client, send_wr)
            self.poll_cq_ex(cqex=self.client.cq, to_valid=False)
            actual_cqe = self.poll_cq_ex(cqex=self.server.cq)
            exp_recv_tm_opcode = e.IBV_WC_TM_NO_TAG if tm_opcode == e.IBV_TMH_NO_TAG else \
                e.IBV_WC_TM_RECV
            self.verify_cqe(actual_cqe=actual_cqe, wr_id=wrid_exp, opcode=exp_recv_tm_opcode,
                            wc_flags=wc_flags, tag=tag_exp)
            if tm_opcode == e.IBV_TMH_RNDV:
                actual_cqe = self.poll_cq_ex(cqex=self.client.cq)
                self.verify_cqe(actual_cqe=actual_cqe, opcode=e.IBV_WC_RECV, is_server=False)
                actual_cqe = self.poll_cq_ex(cqex=self.server.cq)
                self.verify_cqe(actual_cqe=actual_cqe, wr_id=wrid_exp, opcode=e.IBV_WC_TM_RECV,
                                wc_flags=e.IBV_WC_TM_DATA_VALID)
            actual_msg, exp_msg, msg_size = self.build_expected_and_recv_msgs \
                (exp_msg=exp_msg, tm_opcode=tm_opcode, fixed_send_tag=fixed_send_tag)
            self.validate_msg(actual_msg, exp_msg, msg_size)
            if fixed_send_tag and tm_opcode != e.IBV_TMH_NO_TAG:
                self.validate_exp_recv_params(exp_parm=self.curr_unexpected_cnt,
                                              recv_parm=self.server.unexp_cnt,
                                              descriptor='unexpected_count')
                self.curr_unexpected_cnt += 1
            u.post_recv(self.server, u.get_recv_wr(self.server))

    def test_tm_traffic(self):
        """
        Test basic Tag Matching traffic, client sends tagged WRs server receives
        and validates it.
        """
        self.tm_traffic()

    def test_tm_unexpected_tag(self):
        """
        Test unexpected Tag Matching traffic, client sends unexpected tagged WRs,
        server receives and validates it,
        completions are expected to be with no tag,
        and unexpected_count field of the server TM-SRQ expected to be increased.
        """
        self.tm_traffic(fixed_send_tag=FIXED_SEND_TAG)

    def test_tm_no_tag(self):
        """
        Test no_tag Tag Matching traffic,
        client sends WRs with tag and with opcode NO_TAG,
        server receives and validates it,
        completions are expected to be with no tag.
        """
        self.tm_traffic(tm_opcode=e.IBV_TMH_NO_TAG, fixed_send_tag=FIXED_SEND_TAG)

    def test_tm_rndv(self):
        """
        Test rendezvous Tag Matching traffic,
        client sends WRs with tag and with opcode RNDV,
        server receives and validates it,
        2 completions are expected to be received for every WRs.
        """
        self.tm_traffic(tm_opcode=e.IBV_TMH_RNDV)
