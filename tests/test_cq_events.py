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
        self.qp_dict = {'ud': CqEventsUD, 'rc': CqEventsRC}
        self.client = None
        self.server = None

    def create_players(self, qp_type):
        try:
            self.client = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                                self.gid_index)
            self.server = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                                self.gid_index)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create qp with attrs {} is not supported'.format(qp_type))
            raise ex
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)

    def test_cq_events_ud(self):
        self.create_players('ud')
        traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port)

    def test_cq_events_rc(self):
        self.create_players('rc')
        traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port)
