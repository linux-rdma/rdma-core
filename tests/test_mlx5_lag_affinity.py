import unittest
import errno


from pyverbs.qp import QP, QPAttr, QPInitAttr, QPCap
from pyverbs.pyverbs_error import PyverbsRDMAError
from tests.base import BaseResources, RDMATestCase
from pyverbs.providers.mlx5.mlx5dv import Mlx5QP
from tests.utils import requires_root_on_eth
import pyverbs.enums as e
from pyverbs.cq import CQ


class LagRawQP(BaseResources):
    def __init__(self, dev_name):
        super().__init__(dev_name, None, None)
        self.cq = self.create_cq()
        self.qp = self.create_qp()

    def create_cq(self):
        return CQ(self.ctx, 100)

    @requires_root_on_eth()
    def create_qp(self):
        qia = QPInitAttr(e.IBV_QPT_RAW_PACKET, rcq=self.cq, scq=self.cq,
                         cap=QPCap())
        qp = QP(self.pd, qia)
        qp.to_init(QPAttr())
        return qp


class LagPortTestCase(RDMATestCase):
    def modify_lag(self, resources):
        try:
            port_num, active_port_num = Mlx5QP.query_lag_port(resources.qp)
            # if port_num is 1 - modify to 2, else modify to 1
            new_port_num = (2 - port_num) + 1
            Mlx5QP.modify_lag_port(resources.qp, new_port_num)
            port_num, active_port_num = Mlx5QP.query_lag_port(resources.qp)
            self.assertEqual(port_num, new_port_num, 'Port num is not as expected')
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Set LAG affinity is not supported on this device')
            raise ex

    def test_raw_modify_lag_port(self):
        qp = LagRawQP(self.dev_name)
        self.modify_lag(qp)
