import errno
import unittest

from pyverbs.pyverbs_error import PyverbsRDMAError
from tests.base import RCResources, UDResources
from tests.base import RDMATestCase
from tests.utils import traffic

from pyverbs.cq import CQ, CompChannel


def create_cq_with_comp_channel(agr_obj):
    agr_obj.comp_channel = CompChannel(agr_obj.ctx)
    agr_obj.cq = CQ(agr_obj.ctx, agr_obj.num_msgs, None, agr_obj.comp_channel)
    agr_obj.cq.req_notify()


class CqEventsUD(UDResources):
    def create_cq(self):
        create_cq_with_comp_channel(self)


class CqEventsRC(RCResources):
    def create_cq(self):
        create_cq_with_comp_channel(self)


class CqEventsTestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 100

    def test_cq_events_ud(self):
        self.create_players(CqEventsUD)
        traffic(**self.traffic_args)

    def test_cq_events_rc(self):
        self.create_players(CqEventsRC)
        traffic(**self.traffic_args)
