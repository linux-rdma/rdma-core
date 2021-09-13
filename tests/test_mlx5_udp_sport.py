import unittest
import errno

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.providers.mlx5.mlx5dv import Mlx5QP
from tests.mlx5_base import Mlx5RDMATestCase
from tests.base import RCResources
import pyverbs.enums as e
import tests.utils as u


class UdpSportTestCase(Mlx5RDMATestCase):
    def __init__(self, methodName='runTest', dev_name=None, ib_port=None,
                 gid_index=None, pkey_index=None, gid_type=e.IBV_GID_TYPE_SYSFS_ROCE_V2):
        # Modify UDP source port is not supported on RoCEv1
        super().__init__(methodName, dev_name, ib_port, gid_index, pkey_index, gid_type)

    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

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

    def test_rc_modify_udp_sport(self):
        """
        Create RC resources and change the server QP's UDP source port to an
        arbitrary legal value (55555). Then run SEND traffic.
        :return: None
        """
        self.create_players(RCResources)
        try:
            Mlx5QP.modify_udp_sport(self.server.qp, udp_sport=55555)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Modifying a QP UDP sport is not supported')
            raise ex
        u.traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port)
