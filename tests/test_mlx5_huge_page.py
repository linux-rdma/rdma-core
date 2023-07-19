import unittest

from pyverbs.pyverbs_error import PyverbsRDMAError
from tests.mlx5_base import Mlx5PyverbsAPITestCase
from pyverbs.qp import QP, QPInitAttr, QPCap
from pyverbs.srq import SRQ, SrqInitAttr
from pyverbs.pd import PD
from pyverbs.cq import CQ
import tests.utils as u


def huge_pages_supported():
    try:
        u.huge_pages_supported()
    except unittest.SkipTest:
        return False
    return True


class ResourcesOnHugePageTest(Mlx5PyverbsAPITestCase):
    def create_cq(self):
        return CQ(self.ctx, 100, None, None, 0)

    def create_qp(self):
        with PD(self.ctx) as pd:
            with self.create_cq() as cq:
                attr = QPInitAttr(scq=cq, rcq=cq, cap=QPCap(max_recv_wr=100,
                                                            max_send_wr=100))
                QP(pd, attr)

    def create_srq(self):
        with PD(self.ctx) as pd:
            SRQ(pd, SrqInitAttr())

    def set_env_alloc_type(self, alloc_type):
        self.set_env_variable('MLX_CQ_ALLOC_TYPE', alloc_type)
        self.set_env_variable('MLX_QP_ALLOC_TYPE', alloc_type)
        self.set_env_variable('MLX_SRQ_ALLOC_TYPE', alloc_type)

    def create_objects(self):
        self.create_cq()
        self.create_qp()
        self.create_srq()

    def test_prefer_obj_on_huge(self):
        """
        Test PREFER_HUGE allocation type for srq cq and qp.
        """
        self.set_env_alloc_type('PREFER_HUGE')
        self.create_objects()

    def test_obj_on_huge(self):
        """
        Test HUGE allocation type for srq cq and qp.
        If there are huge pages in the system expect to success,
        else expect to fail.
        """
        self.set_env_alloc_type('HUGE')
        if huge_pages_supported() and u.is_root():
            self.create_objects()
        else:
            with self.assertRaises(PyverbsRDMAError):
                self.create_objects()
