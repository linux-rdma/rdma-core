import unittest
import errno

from tests.base import RCResources, UDResources, XRCResources
from tests.utils import traffic, xrc_traffic
from tests.base import RDMATestCase
from pyverbs.mr import MR
import pyverbs.enums as e
from pyverbs.pyverbs_error import PyverbsRDMAError


class RoUD(UDResources):
    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size + self.GRH_SIZE,
                     e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_RELAXED_ORDERING)


class RoRC(RCResources):
    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size,
                     e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_RELAXED_ORDERING)


class RoXRC(XRCResources):
    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size,
                     e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_RELAXED_ORDERING)


class RoTestCase(RDMATestCase):
    def setUp(self):
        super(RoTestCase, self).setUp()
        self.iters = 100
        self.qp_dict = {'rc': RoRC, 'ud': RoUD, 'xrc': RoXRC}

    def create_players(self, qp_type):
        try:
            client = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                           self.gid_index)
            server = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                           self.gid_index)
        except PyverbsRDMAError as ex:
           if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create player with attrs {} is not supported'.format(qp_type))
           raise ex
        client.pre_run(server.psns, server.qps_num)
        server.pre_run(client.psns, client.qps_num)
        return client, server

    def test_ro_rc_traffic(self):
        client, server = self.create_players('rc')
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

    def test_ro_ud_traffic(self):
        client, server = self.create_players('ud')
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

    def test_ro_xrc_traffic(self):
        client, server = self.create_players('xrc')
        xrc_traffic(client, server)
