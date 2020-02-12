from tests.base import RCResources, UDResources, XRCResources
from tests.utils import traffic, xrc_traffic
from tests.base import RDMATestCase
from pyverbs.mr import MR
import pyverbs.enums as e


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
        client = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                       self.gid_index)
        server = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                       self.gid_index)
        if qp_type == 'xrc':
            client.pre_run(server.psns, server.qps_num)
            server.pre_run(client.psns, client.qps_num)
        else:
            client.pre_run(server.psn, server.qpn)
            server.pre_run(client.psn, client.qpn)
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
