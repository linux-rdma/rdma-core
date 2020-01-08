from pyverbs.mem_alloc import mmap, munmap, MAP_ANONYMOUS_, MAP_PRIVATE_, \
    MAP_HUGETLB_, MAP_FIXED_
from tests.utils import requires_odp, requires_huge_pages, traffic, xrc_traffic
from tests.base import RCResources, UDResources, XRCResources
from tests.base import RDMATestCase
from pyverbs.mr import MR
import pyverbs.enums as e


HUGE_PAGE_SIZE = 0x200000


class OdpUD(UDResources):
    @requires_odp('ud')
    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size + self.GRH_SIZE,
                     e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_ON_DEMAND)


class OdpRC(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, is_huge=False,
                 user_addr=None):
        """
        Initialize an OdpRC object.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param is_huge: If True, use huge pages for MR registration
        :param user_addr: The MR's buffer address. If None, the buffer will be
                          allocated by pyverbs.
        """
        self.is_huge = is_huge
        self.user_addr = user_addr
        super(OdpRC, self).__init__(dev_name=dev_name, ib_port=ib_port,
                                    gid_index=gid_index)

    @requires_odp('rc')
    def create_mr(self):
        access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_ON_DEMAND
        if self.is_huge:
            access |= e.IBV_ACCESS_HUGETLB
        self.mr = MR(self.pd, self.msg_size, access, address=self.user_addr)

class OdpXRC(XRCResources):
    @requires_odp('xrc')
    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size,
                     e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_ON_DEMAND)


class OdpTestCase(RDMATestCase):
    def setUp(self):
        super(OdpTestCase, self).setUp()
        self.iters = 100
        self.user_addr = None
        self.qp_dict = {'rc': OdpRC, 'ud': OdpUD, 'xrc': OdpXRC}

    def create_players(self, qp_type, is_huge=False):
        if qp_type == 'rc':
            client = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                           self.gid_index, is_huge=is_huge,
                                           user_addr=self.user_addr)
            server = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                           self.gid_index, is_huge=is_huge,
                                           user_addr=self.user_addr)
        else:
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

    def tearDown(self):
        if self.user_addr:
            munmap(self.user_addr, HUGE_PAGE_SIZE)
        super(OdpTestCase, self).tearDown()

    def test_odp_rc_traffic(self):
        client, server = self.create_players('rc')
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

    def test_odp_ud_traffic(self):
        client, server = self.create_players('ud')
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

    def test_odp_xrc_traffic(self):
        client, server = self.create_players('xrc')
        xrc_traffic(client, server)

    @requires_huge_pages()
    def test_odp_rc_huge_traffic(self):
        client, server = self.create_players('rc', is_huge=True)
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

    @requires_huge_pages()
    def test_odp_rc_huge_user_addr_traffic(self):
        self.user_addr = mmap(length=HUGE_PAGE_SIZE,
                              flags=MAP_ANONYMOUS_| MAP_PRIVATE_| MAP_HUGETLB_)
        client, server = self.create_players('rc', is_huge=True)
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

