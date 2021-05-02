import unittest
import errno


from tests.base import BaseResources, RCResources, UDResources
from pyverbs.qp import QP, QPAttr, QPInitAttr, QPCap
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.providers.mlx5.mlx5dv import Mlx5QP
from tests.mlx5_base import Mlx5RDMATestCase
import tests.utils as u
import pyverbs.enums as e
from pyverbs.cq import CQ


class LagRawQP(BaseResources):
    def __init__(self, dev_name):
        super().__init__(dev_name, None, None)
        self.cq = self.create_cq()
        self.qp = self.create_qp()

    def create_cq(self):
        return CQ(self.ctx, 100)

    @u.requires_root_on_eth()
    def create_qp(self):
        qia = QPInitAttr(e.IBV_QPT_RAW_PACKET, rcq=self.cq, scq=self.cq,
                         cap=QPCap())
        try:
            qp = QP(self.pd, qia)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest("Create Raw Packet QP is not supported")
            raise ex
        qp.to_init(QPAttr())
        return qp


class LagPortTestCase(Mlx5RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

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

    def create_players(self, resource, **resource_arg):
        """
        Initialize tests resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dictionary of args that specify the resource
                             specific attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)
        self.modify_lag(self.client)
        self.modify_lag(self.server)

    def test_rc_modify_lag_port(self):
        self.create_players(RCResources)
        u.traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port)

    def test_ud_modify_lag_port(self):
        self.create_players(UDResources)
        u.traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port)
