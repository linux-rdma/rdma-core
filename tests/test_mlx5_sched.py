import unittest
import errno

from pyverbs.providers.mlx5.mlx5dv_sched import Mlx5dvSchedAttr, \
    Mlx5dvSchedNode, Mlx5dvSchedLeaf
from tests.mlx5_base import Mlx5RDMATestCase, Mlx5PyverbsAPITestCase
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.providers.mlx5.mlx5dv import Mlx5QP
import pyverbs.providers.mlx5.mlx5_enums as dve
from tests.base import RCResources
import tests.utils as u


class Mlx5SchedTest(Mlx5PyverbsAPITestCase):
    def test_create_sched_tree(self):
        """
        Create schedule elements tree. Test the schedule elements API, this
        includes creating schedule nodes with different flags and connecting
        them with schedule leaves. In addition, modify some nodes with
        different BW share and max BW.
        """
        try:
            root_node = Mlx5dvSchedNode(self.ctx, Mlx5dvSchedAttr())
            # Create a node with only max_avg_bw argument.
            max_sched_attr = Mlx5dvSchedAttr(root_node, max_avg_bw=10,
                                             flags=dve.MLX5DV_SCHED_ELEM_ATTR_FLAGS_MAX_AVG_BW)
            max_bw_node = Mlx5dvSchedNode(self.ctx, max_sched_attr)

            # Create a node with only bw_share argument.
            weighed_sched_attr = Mlx5dvSchedAttr(root_node, bw_share=10,
                                                 flags=dve.MLX5DV_SCHED_ELEM_ATTR_FLAGS_BW_SHARE)
            max_bw_node = Mlx5dvSchedNode(self.ctx, weighed_sched_attr)

            # Create a node with max_avg_bw and bw_share arguments.
            mixed_flags = dve.MLX5DV_SCHED_ELEM_ATTR_FLAGS_MAX_AVG_BW | \
                dve.MLX5DV_SCHED_ELEM_ATTR_FLAGS_BW_SHARE
            mixed_sched_attr = Mlx5dvSchedAttr(root_node, max_avg_bw=10, bw_share=2,
                                               flags=mixed_flags)
            mixed_bw_node = Mlx5dvSchedNode(self.ctx, mixed_sched_attr)

            # Modify a node.
            modify_sched_attr = Mlx5dvSchedAttr(root_node, max_avg_bw=4, bw_share=1,
                                                flags=mixed_flags)
            mixed_bw_node.modify(modify_sched_attr)

            # Attach sched leaf to mixed_bw_node
            max_sched_attr = Mlx5dvSchedAttr(mixed_bw_node)
            sched_leaf = Mlx5dvSchedLeaf(self.ctx, max_sched_attr)

            # Modify a leaf.
            modify_sched_attr = Mlx5dvSchedAttr(mixed_bw_node, max_avg_bw=3, bw_share=3,
                                                flags=mixed_flags)
            sched_leaf.modify(modify_sched_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create schedule elements is not supported')
            raise ex


class Mlx5SchedTrafficTest(Mlx5RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None
        self.traffic_args = None

    def create_players(self, resource, **resource_arg):
        """
        Init schedule elements traffic tests resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)
        self.traffic_args = {'client': self.client, 'server': self.server,
                             'iters': self.iters, 'gid_idx': self.gid_index,
                             'port': self.ib_port}

    def test_sched_per_qp_traffic(self):
        """
        Tests attaching a QP to a sched leaf. The test creates a sched tree
        consisting of a root node and a leaf with max BW and share BW, modifies
        two RC QPs to be attached to the sched leaf and then run traffic using
        those QPs.
        """
        self.create_players(RCResources)
        try:
            root_node = Mlx5dvSchedNode(self.server.ctx, Mlx5dvSchedAttr())
            mixed_flags = dve.MLX5DV_SCHED_ELEM_ATTR_FLAGS_MAX_AVG_BW | \
                dve.MLX5DV_SCHED_ELEM_ATTR_FLAGS_BW_SHARE
            mixed_sched_attr = Mlx5dvSchedAttr(root_node, max_avg_bw=10,
                                               bw_share=2, flags=mixed_flags)
            leaf = Mlx5dvSchedLeaf(self.server.ctx, mixed_sched_attr)
            Mlx5QP.modify_qp_sched_elem(self.server.qp, req_sched_leaf=leaf,
                                        resp_sched_leaf=leaf)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Creation or usage of schedule elements is not supported')
            raise ex
        u.traffic(**self.traffic_args)
