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

    def test_ro_rc_traffic(self):
        self.create_players(RoRC)
        traffic(**self.traffic_args)

    def test_ro_ud_traffic(self):
        self.create_players(RoUD)
        traffic(**self.traffic_args)

    def test_ro_xrc_traffic(self):
        self.create_players(RoXRC)
        xrc_traffic(self.client, self.server)
