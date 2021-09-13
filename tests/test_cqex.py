from tests.base import RCResources, UDResources, XRCResources, RDMATestCase, \
    PyverbsAPITestCase
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.cq import CqInitAttrEx, CQEX
import pyverbs.enums as e
from pyverbs.mr import MR
import tests.utils as u
import unittest
import errno


def create_ex_cq(res):
    """
    Create an Extended CQ using res's context and assign it to res's cq member.
    IBV_WC_STANDARD_FLAGS is used for WC flags to avoid support differences
    between devices.
    :param res: An instance of TrafficResources
    """
    wc_flags = e.IBV_WC_STANDARD_FLAGS
    cia = CqInitAttrEx(cqe=2000, wc_flags=wc_flags)
    try:
        res.cq = CQEX(res.ctx, cia)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EOPNOTSUPP:
            raise unittest.SkipTest('Create Extended CQ is not supported')
        raise ex

class CqExUD(UDResources):
    def create_cq(self):
        create_ex_cq(self)

    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size + self.GRH_SIZE,
                     e.IBV_ACCESS_LOCAL_WRITE)


class CqExRC(RCResources):
    def create_cq(self):
        create_ex_cq(self)


class CqExXRC(XRCResources):
    def create_cq(self):
        create_ex_cq(self)


class CqExTestCase(RDMATestCase):
    """
    Run traffic over the existing UD, RC and XRC infrastructure, but use
    ibv_cq_ex instead of legacy ibv_cq
    """
    def setUp(self):
        super().setUp()
        self.iters = 100
        self.qp_dict = {'ud': CqExUD, 'rc': CqExRC, 'xrc': CqExXRC}

    def create_players(self, qp_type):
        client = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                       self.gid_index)
        server = self.qp_dict[qp_type](self.dev_name, self.ib_port,
                                       self.gid_index)
        client.pre_run(server.psns, server.qps_num)
        server.pre_run(client.psns, client.qps_num)
        return client, server

    def test_ud_traffic_cq_ex(self):
        client, server = self.create_players('ud')
        u.traffic(client, server, self.iters, self.gid_index, self.ib_port,
                  is_cq_ex=True)

    def test_rc_traffic_cq_ex(self):
        client, server = self.create_players('rc')
        u.traffic(client, server, self.iters, self.gid_index, self.ib_port,
                  is_cq_ex=True)

    def test_xrc_traffic_cq_ex(self):
        client, server = self.create_players('xrc')
        u.xrc_traffic(client, server, is_cq_ex=True)


class CQEXAPITest(PyverbsAPITestCase):
    """
    Test the API of the CQEX class.
    """
    def setUp(self):
        super().setUp()
        self.max_cqe = self.attr.max_cqe

    def test_create_cq_ex(self):
        """
        Test ibv_create_cq_ex()
        """
        cq_init_attrs_ex = CqInitAttrEx(cqe=10, wc_flags=0, comp_mask=0, flags=0)
        if self.attr_ex.raw_packet_caps & e.IBV_RAW_PACKET_CAP_CVLAN_STRIPPING:
            cq_init_attrs_ex.wc_flags = e.IBV_WC_EX_WITH_CVLAN
            CQEX(self.ctx, cq_init_attrs_ex)

        for flag in list(e.ibv_create_cq_wc_flags):
            cq_init_attrs_ex.wc_flags = flag
            try:
                cq_ex = CQEX(self.ctx, cq_init_attrs_ex)
                cq_ex.close()
            except PyverbsRDMAError as ex:
                if ex.error_code != errno.EOPNOTSUPP:
                    raise ex

        cq_init_attrs_ex.wc_flags = 0
        cq_init_attrs_ex.comp_mask = e.IBV_CQ_INIT_ATTR_MASK_FLAGS
        attr_flags = list(e.ibv_create_cq_attr_flags)
        for flag in attr_flags:
            cq_init_attrs_ex.flags = flag
            try:
                cq_ex = CQEX(self.ctx, cq_init_attrs_ex)
                cq_ex.close()
            except PyverbsRDMAError as ex:
                if ex.error_code != errno.EOPNOTSUPP:
                    raise ex

    def test_create_cq_ex_bad_flow(self):
        """
        Test ibv_create_cq_ex() with wrong comp_vector / number of cqes
        """
        cq_attrs_ex = CqInitAttrEx(cqe=self.max_cqe + 1, wc_flags=0, comp_mask=0, flags=0)
        with self.assertRaises(PyverbsRDMAError) as ex:
            CQEX(self.ctx, cq_attrs_ex)
        if ex.exception.error_code == errno.EOPNOTSUPP:
            raise unittest.SkipTest('Create Extended CQ is not supported')
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

        cq_attrs_ex = CqInitAttrEx(10, wc_flags=0, comp_mask=0, flags=0)
        cq_attrs_ex.comp_vector = self.ctx.num_comp_vectors + 1
        with self.assertRaises(PyverbsRDMAError) as ex:
            CQEX(self.ctx, cq_attrs_ex)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)
