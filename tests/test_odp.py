from pyverbs.mem_alloc import mmap, munmap, madvise, MAP_ANONYMOUS_, MAP_PRIVATE_, \
    MAP_HUGETLB_
from tests.base import RCResources, UDResources, XRCResources
from pyverbs.wr import SGE, SendWR, RecvWR
from pyverbs.qp import QPAttr, QPInitAttr
from tests.base import RDMATestCase
from pyverbs.mr import MR
import pyverbs.enums as e
import tests.utils as u

HUGE_PAGE_SIZE = 0x200000


class OdpUD(UDResources):
    def __init__(self, request_user_addr=False, **kwargs):
        self.request_user_addr = request_user_addr
        self.user_addr = None
        super(OdpUD, self).__init__(**kwargs)

    @u.requires_odp('ud', e.IBV_ODP_SUPPORT_SEND)
    def create_mr(self):
        if self.request_user_addr:
            self.user_addr = mmap(length=self.msg_size,
                                  flags=MAP_ANONYMOUS_ | MAP_PRIVATE_)
        self.send_mr = MR(self.pd, self.msg_size + u.GRH_SIZE,
                          e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_ON_DEMAND, address=self.user_addr)
        self.recv_mr = MR(self.pd, self.msg_size + u.GRH_SIZE,
                          e.IBV_ACCESS_LOCAL_WRITE)


class OdpRC(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, is_huge=False,
                 request_user_addr=False, use_mr_prefetch=None, is_implicit=False,
                 prefetch_advice=e._IBV_ADVISE_MR_ADVICE_PREFETCH_WRITE,
                 msg_size=1024, odp_caps=e.IBV_ODP_SUPPORT_SEND | e.IBV_ODP_SUPPORT_RECV):
        """
        Initialize an OdpRC object.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param is_huge: If True, use huge pages for MR registration
        :param request_user_addr: Request to provide the MR's buffer address.
                                  If False, the buffer will be allocated by pyverbs.
        :param use_mr_prefetch: Describes the properties of the prefetch
                                operation. The options are 'sync', 'async'
                                and None to skip the prefetch operation.
        :param is_implicit: If True, register implicit MR.
        :param prefetch_advice: The advice of the prefetch request (ignored
                                if use_mr_prefetch is None).
        """
        self.is_huge = is_huge
        self.request_user_addr = request_user_addr
        self.is_implicit = is_implicit
        self.odp_caps = odp_caps
        self.access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_ON_DEMAND | \
            e.IBV_ACCESS_REMOTE_ATOMIC | e.IBV_ACCESS_REMOTE_READ | \
            e.IBV_ACCESS_REMOTE_WRITE
        self.user_addr = None
        super(OdpRC, self).__init__(dev_name=dev_name, ib_port=ib_port,
                                    gid_index=gid_index)
        self.use_mr_prefetch = use_mr_prefetch
        self.prefetch_advice = prefetch_advice
        self.msg_size = msg_size

    @u.requires_odp('rc', e.IBV_ODP_SUPPORT_SEND | e.IBV_ODP_SUPPORT_RECV)
    def create_mr(self):
        u.odp_supported(self.ctx, 'rc', self.odp_caps)
        if self.request_user_addr:
            mmap_flags = MAP_ANONYMOUS_| MAP_PRIVATE_
            length = self.msg_size
            if self.is_huge:
                mmap_flags |= MAP_HUGETLB_
                length = HUGE_PAGE_SIZE
            self.user_addr = mmap(length=length, flags=mmap_flags)
        access = self.access
        if self.is_huge:
            access |= e.IBV_ACCESS_HUGETLB
        self.mr = MR(self.pd, self.msg_size, access, address=self.user_addr,
                     implicit=self.is_implicit)

    def create_qp_init_attr(self):
        return QPInitAttr(qp_type=e.IBV_QPT_RC, scq=self.cq, sq_sig_all=0,
                          rcq=self.cq, srq=self.srq, cap=self.create_qp_cap())

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_attr.qp_access_flags = self.access
        return qp_attr


class OdpXRC(XRCResources):
    def __init__(self, request_user_addr=False, **kwargs):
        self.request_user_addr = request_user_addr
        self.user_addr = None
        super(OdpXRC, self).__init__(**kwargs)

    @u.requires_odp('xrc',  e.IBV_ODP_SUPPORT_SEND | e.IBV_ODP_SUPPORT_SRQ_RECV)
    def create_mr(self):
        if self.request_user_addr:
            self.user_addr = mmap(length=self.msg_size,
                                  flags=MAP_ANONYMOUS_| MAP_PRIVATE_)
        self.mr = u.create_custom_mr(self, e.IBV_ACCESS_ON_DEMAND, user_addr=self.user_addr)


class OdpTestCase(RDMATestCase):
    def setUp(self):
        super(OdpTestCase, self).setUp()
        self.iters = 100
        self.force_page_faults = True
        self.is_huge = False

    def create_players(self, resource, **resource_arg):
        """
        Init odp tests resources.
        :param resource: The RDMA resources to use. A class of type
                         BaseResources.
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        """
        sync_attrs = False if resource == OdpUD else True
        super().create_players(resource, sync_attrs, **resource_arg)
        self.traffic_args['force_page_faults'] = self.force_page_faults

    def tearDown(self):
        if self.server and self.server.user_addr:
            length = HUGE_PAGE_SIZE if self.is_huge else self.server.msg_size
            munmap(self.server.user_addr, length)
        if self.client and self.client.user_addr:
            length = HUGE_PAGE_SIZE if self.is_huge else self.client.msg_size
            munmap(self.client.user_addr, length)
        super(OdpTestCase, self).tearDown()

    def test_odp_rc_traffic(self):
        self.create_players(OdpRC, request_user_addr=self.force_page_faults)
        u.traffic(**self.traffic_args)

    def test_odp_rc_atomic_cmp_and_swp(self):
        self.force_page_faults = False
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            msg_size=8, odp_caps=e.IBV_ODP_SUPPORT_ATOMIC)
        u.atomic_traffic(**self.traffic_args,
                         send_op=e.IBV_WR_ATOMIC_CMP_AND_SWP)
        u.atomic_traffic(**self.traffic_args, receiver_val=1, sender_val=1,
                         send_op=e.IBV_WR_ATOMIC_CMP_AND_SWP)

    def test_odp_rc_atomic_fetch_and_add(self):
        self.force_page_faults = False
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            msg_size=8, odp_caps=e.IBV_ODP_SUPPORT_ATOMIC)
        u.atomic_traffic(**self.traffic_args,
                         send_op=e.IBV_WR_ATOMIC_FETCH_AND_ADD)

    def test_odp_rc_rdma_read(self):
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            odp_caps=e.IBV_ODP_SUPPORT_READ)
        self.server.mr.write('s' * self.server.msg_size, self.server.msg_size)
        u.rdma_traffic(**self.traffic_args, send_op=e.IBV_WR_RDMA_READ)

    def test_odp_rc_rdma_write(self):
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            odp_caps=e.IBV_ODP_SUPPORT_WRITE)
        u.rdma_traffic(**self.traffic_args, send_op=e.IBV_WR_RDMA_WRITE)

    def test_odp_implicit_rc_traffic(self):
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            is_implicit=True)
        u.traffic(**self.traffic_args)

    def test_odp_ud_traffic(self):
        self.create_players(OdpUD, request_user_addr=self.force_page_faults)
        # Implement the traffic here because OdpUD uses two different MRs for
        # send and recv.
        ah_client = u.get_global_ah(self.client, self.gid_index, self.ib_port)
        recv_sge = SGE(self.server.recv_mr.buf, self.server.msg_size +
                       u.GRH_SIZE, self.server.recv_mr.lkey)
        server_recv_wr = RecvWR(sg=[recv_sge], num_sge=1)
        send_sge = SGE(self.client.send_mr.buf + u.GRH_SIZE,
                       self.client.msg_size, self.client.send_mr.lkey)
        client_send_wr = SendWR(num_sge=1, sg=[send_sge])
        for i in range(self.iters):
            madvise(self.client.send_mr.buf, self.client.msg_size)
            self.server.qp.post_recv(server_recv_wr)
            u.post_send(self.client, client_send_wr, ah=ah_client)
            u.poll_cq(self.client.cq)
            u.poll_cq(self.server.cq)

    def test_odp_xrc_traffic(self):
        self.create_players(OdpXRC, request_user_addr=self.force_page_faults)
        u.xrc_traffic(self.client, self.server)

    @u.requires_huge_pages()
    def test_odp_rc_huge_traffic(self):
        self.force_page_faults = False
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            is_huge=True)
        u.traffic(**self.traffic_args)

    @u.requires_huge_pages()
    def test_odp_rc_huge_user_addr_traffic(self):
        self.is_huge = True
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            is_huge=True)
        u.traffic(**self.traffic_args)

    def test_odp_sync_prefetch_rc_traffic(self):
        for advice in [e._IBV_ADVISE_MR_ADVICE_PREFETCH,
                       e._IBV_ADVISE_MR_ADVICE_PREFETCH_WRITE]:
            self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                                use_mr_prefetch='sync', prefetch_advice=advice)
            u.traffic(**self.traffic_args)

    def test_odp_async_prefetch_rc_traffic(self):
        for advice in [e._IBV_ADVISE_MR_ADVICE_PREFETCH,
                       e._IBV_ADVISE_MR_ADVICE_PREFETCH_WRITE]:
            self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                                use_mr_prefetch='async', prefetch_advice=advice)
            u.traffic(**self.traffic_args)

    def test_odp_implicit_sync_prefetch_rc_traffic(self):
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            use_mr_prefetch='sync', is_implicit=True)
        u.traffic(**self.traffic_args)

    def test_odp_implicit_async_prefetch_rc_traffic(self):
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            use_mr_prefetch='async', is_implicit=True)
        u.traffic(**self.traffic_args)

    def test_odp_prefetch_sync_no_page_fault_rc_traffic(self):
        prefetch_advice = e._IBV_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            use_mr_prefetch='sync', prefetch_advice=prefetch_advice)
        u.traffic(**self.traffic_args)

    def test_odp_prefetch_async_no_page_fault_rc_traffic(self):
        prefetch_advice = e._IBV_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT
        self.create_players(OdpRC, request_user_addr=self.force_page_faults,
                            use_mr_prefetch='async', prefetch_advice=prefetch_advice)
        u.traffic(**self.traffic_args)
