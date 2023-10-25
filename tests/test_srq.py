import unittest

from tests.base import RCResources, RDMATestCase
from pyverbs.srq import SrqAttr
import pyverbs.enums as e
import tests.utils as u


class SrqTestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 100
        self.create_players(RCResources, qp_count=2, with_srq=True)

    def test_rc_srq_traffic(self):
        """
        Test RC traffic with SRQ.
        """
        u.traffic(**self.traffic_args)

    def test_resize_srq(self):
        """
        Test modify_srq with IBV_SRQ_MAX_WR which allows to modify max_wr.
        Once modified, query the SRQ and verify that the new value is greater
        or equal than the requested max_wr.
        """
        device_attr = self.server.ctx.query_device()
        if not device_attr.device_cap_flags & e.IBV_DEVICE_SRQ_RESIZE:
            raise unittest.SkipTest('SRQ resize is not supported')
        srq_query_attr = self.server.srq.query()
        srq_query_max_wr = srq_query_attr.max_wr
        srq_max_wr = min(device_attr.max_srq_wr, srq_query_max_wr*2)
        srq_attr = SrqAttr(max_wr=srq_max_wr)
        self.server.srq.modify(srq_attr, e.IBV_SRQ_MAX_WR)
        srq_attr_modified = self.server.srq.query()
        self.assertGreaterEqual(srq_attr_modified.max_wr, srq_attr.max_wr,
                                'Resize SRQ failed')

    def test_modify_srq_limit(self):
        """
        Test IBV_SRQ_LIMIT modification.
        Add 10 wr to the SRQ and set the limit to 7,
        Query and verify that the SRQ limit changed to the expected value.
        send 4 packets from the client to the server, only 6 wr remain in the
        server SRQ so IBV_EVENT_SRQ_LIMIT_REACHED should be generated.
        Listen for income event and if one received check if it's equal to
        IBV_EVENT_SRQ_LIMIT_REACHED else fail.
        """
        for _ in range(10):
            self.server.srq.post_recv(u.get_recv_wr(self.server))
        srq_modify_attr = SrqAttr(srq_limit=7)
        self.server.srq.modify(srq_modify_attr, e.IBV_SRQ_LIMIT)
        server_query = self.server.srq.query()
        self.assertEqual(srq_modify_attr.srq_limit, server_query.srq_limit, 'Modify SRQ failed')
        for _ in range(4):
            c_send_wr, c_sg = u.get_send_elements(self.client, False)
            u.send(self.client, c_send_wr)
            u.poll_cq(self.client.cq)
            u.poll_cq(self.server.cq)
        event = self.server.ctx.get_async_event()
        event.ack()
        self.assertEqual(event.event_type, e.IBV_EVENT_SRQ_LIMIT_REACHED)
