from pyverbs.mem_alloc import mmap, munmap, MAP_ANONYMOUS_, MAP_PRIVATE_, \
    MAP_HUGETLB_
from tests.utils import requires_odp, requires_huge_pages, traffic, \
    xrc_traffic, create_custom_mr, poll_cq, post_send, GRH_SIZE
from tests.base import RCResources, UDResources, XRCResources
from pyverbs.wr import SGE, SendWR, RecvWR
from tests.base import RDMATestCase
from pyverbs.mr import MR
import pyverbs.enums as e


HUGE_PAGE_SIZE = 0x200000


class OdpUD(UDResources):
    @requires_odp('ud', e.IBV_ODP_SUPPORT_SEND)
    def create_mr(self):
        self.send_mr = MR(self.pd, self.msg_size + self.GRH_SIZE,
                          e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_ON_DEMAND)
        self.recv_mr = MR(self.pd, self.msg_size + self.GRH_SIZE,
                          e.IBV_ACCESS_LOCAL_WRITE)


class OdpRC(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, is_huge=False,
                 user_addr=None, use_mr_prefetch=False, is_implicit=False):
        """
        Initialize an OdpRC object.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param use_mr_prefetch: If True, prefetch the MRs
        :param is_huge: If True, use huge pages for MR registration
        :param user_addr: The MR's buffer address. If None, the buffer will be
                          allocated by pyverbs.
        :param is_implicit: If True, register implicit MR.
        """
        self.is_huge = is_huge
        self.user_addr = user_addr
        self.is_implicit = is_implicit
        super(OdpRC, self).__init__(dev_name=dev_name, ib_port=ib_port,
                                    gid_index=gid_index)
        self.use_mr_prefetch = use_mr_prefetch

    @requires_odp('rc',  e.IBV_ODP_SUPPORT_SEND | e.IBV_ODP_SUPPORT_RECV)
    def create_mr(self):
        access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_ON_DEMAND
        if self.is_huge:
            access |= e.IBV_ACCESS_HUGETLB
        self.mr = MR(self.pd, self.msg_size, access, address=self.user_addr,
                     implicit=self.is_implicit)


class OdpXRC(XRCResources):
    @requires_odp('xrc',  e.IBV_ODP_SUPPORT_SEND | e.IBV_ODP_SUPPORT_SRQ_RECV)
    def create_mr(self):
        self.mr = create_custom_mr(self, e.IBV_ACCESS_ON_DEMAND)


class OdpTestCase(RDMATestCase):
    def setUp(self):
        super(OdpTestCase, self).setUp()
        self.iters = 100
        self.user_addr = None

    def create_players(self, resource, **resource_arg):
        """
        Init odp tests resources.
        :param resource: The RDMA resources to use. A class of type
                         BaseResources.
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        :return: The (client, server) resources.
        """
        client = resource(**self.dev_info, **resource_arg)
        server = resource(**self.dev_info, **resource_arg)
        psn = 'psns' if resource == OdpXRC else 'psn'
        qpn = 'qps_num' if resource == OdpXRC else 'qpn'
        client.pre_run(getattr(server, psn), getattr(server, qpn))
        server.pre_run(getattr(client, psn), getattr(client, qpn))
        return client, server

    def tearDown(self):
        if self.user_addr:
            munmap(self.user_addr, HUGE_PAGE_SIZE)
        super(OdpTestCase, self).tearDown()

    def test_odp_rc_traffic(self):
        client, server = self.create_players(OdpRC)
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

    def test_odp_implicit_rc_traffic(self):
        client, server = self.create_players(OdpRC, is_implicit=True)
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

    def test_odp_ud_traffic(self):
        client, server = self.create_players(OdpUD)
        # Implement the traffic here because OdpUD uses two different MRs for
        # send and recv.
        recv_sge = SGE(server.recv_mr.buf, server.msg_size + GRH_SIZE,
                       server.recv_mr.lkey)
        server_recv_wr = RecvWR(sg=[recv_sge], num_sge=1)
        send_sge = SGE(client.send_mr.buf + GRH_SIZE, client.msg_size,
                       client.send_mr.lkey)
        client_send_wr = SendWR(num_sge=1, sg=[send_sge])
        for i in range(self.iters):
            server.qp.post_recv(server_recv_wr)
            post_send(client, client_send_wr, self.gid_index, self.ib_port)
            poll_cq(client.cq)
            poll_cq(server.cq)

    def test_odp_xrc_traffic(self):
        client, server = self.create_players(OdpXRC)
        xrc_traffic(client, server)

    @requires_huge_pages()
    def test_odp_rc_huge_traffic(self):
        client, server = self.create_players(OdpRC, is_huge=True)
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

    @requires_huge_pages()
    def test_odp_rc_huge_user_addr_traffic(self):
        self.user_addr = mmap(length=HUGE_PAGE_SIZE,
                              flags=MAP_ANONYMOUS_| MAP_PRIVATE_| MAP_HUGETLB_)
        client, server = self.create_players(OdpRC, is_huge=True,
                                              user_addr=self.user_addr)
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

    def test_odp_prefetch_rc_traffic(self):
        client, server = self.create_players(OdpRC, use_mr_prefetch=True)
        traffic(client, server, self.iters, self.gid_index, self.ib_port)

    def test_odp_implicit_prefetch_rc_traffic(self):
        client, server = self.create_players(OdpRC, use_mr_prefetch=True, is_implicit=True)
        traffic(client, server, self.iters, self.gid_index, self.ib_port)
