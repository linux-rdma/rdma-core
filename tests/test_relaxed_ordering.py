from tests.base import RCResources, UDResources, XRCResources
from tests.test_mr import MRExRes
from tests.utils import traffic, xrc_traffic, rdma_traffic
from tests.base import RDMATestCase
from pyverbs.mr import MR
from pyverbs.libibverbs_enums import ibv_access_flags, ibv_wr_opcode

class RoUD(UDResources):
    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size + self.GRH_SIZE,
                     ibv_access_flags.IBV_ACCESS_LOCAL_WRITE | ibv_access_flags.IBV_ACCESS_RELAXED_ORDERING)


class RoRC(RCResources):
    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size,
                     ibv_access_flags.IBV_ACCESS_LOCAL_WRITE | ibv_access_flags.IBV_ACCESS_RELAXED_ORDERING)


class RoXRC(XRCResources):
    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size,
                     ibv_access_flags.IBV_ACCESS_LOCAL_WRITE | ibv_access_flags.IBV_ACCESS_RELAXED_ORDERING)


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

    def test_ro_mr_ex_traffic(self):
        access = (ibv_access_flags.IBV_ACCESS_LOCAL_WRITE |
                  ibv_access_flags.IBV_ACCESS_REMOTE_WRITE |
                  ibv_access_flags.IBV_ACCESS_RELAXED_ORDERING)
        self.create_players(MRExRes, mr_access=access)
        rdma_traffic(**self.traffic_args, send_op=ibv_wr_opcode.IBV_WR_RDMA_WRITE)
