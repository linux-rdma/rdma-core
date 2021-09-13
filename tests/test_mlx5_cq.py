import unittest
import errno

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, \
    Mlx5DVCQInitAttr, Mlx5CQ, context_flags_to_str, cqe_comp_to_str
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
import pyverbs.providers.mlx5.mlx5_enums as dve
from tests.mlx5_base import Mlx5RDMATestCase
from tests.mlx5_base import Mlx5DcResources
from pyverbs.cq import CqInitAttrEx
from tests.base import RCResources
import pyverbs.enums as e
import tests.utils as u


def create_dv_cq(res):
    """
    Create Mlx5 DV CQ.
    :param res: An instance of BaseResources.
    :return: None
    """
    dvcq_init_attr = Mlx5DVCQInitAttr()
    if res.cqe_comp_res_format:
        dvcq_init_attr.cqe_comp_res_format = res.cqe_comp_res_format
        dvcq_init_attr.comp_mask |= dve.MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE
        # Check CQE compression capability
        cqe_comp_caps = res.ctx.query_mlx5_device().cqe_comp_caps
        if not (cqe_comp_caps['supported_format'] & res.cqe_comp_res_format) or \
                not cqe_comp_caps['max_num']:
            cqe_comp_str = cqe_comp_to_str(res.cqe_comp_res_format)
            raise unittest.SkipTest(f'CQE compression {cqe_comp_str} is not supported')
    if res.flags:
        dvcq_init_attr.flags = res.flags
        dvcq_init_attr.comp_mask |= dve.MLX5DV_CQ_INIT_ATTR_MASK_FLAGS
    if res.cqe_size:
        dvcq_init_attr.cqe_size = res.cqe_size
        dvcq_init_attr.comp_mask |= dve.MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE
    try:
        res.cq = Mlx5CQ(res.ctx, CqInitAttrEx(), dvcq_init_attr)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EOPNOTSUPP:
            raise unittest.SkipTest('Create Mlx5DV CQ is not supported')
        raise ex


class Mlx5CQRes(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, cqe_comp_res_format=None,
                 flags=None, cqe_size=None, msg_size=1024, requested_dev_cap=None):
        """
        Initialize Mlx5 DV CQ resources based on RC resources that include RC
        QP.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param cqe_comp_res_format: Type of compression to use
        :param flags: DV CQ specific flags
        :param cqe_size: The CQE size
        :param msg_size: The resource msg size
        :param requested_dev_cap: A necessary device cap. If it's not supported
                                  by the device, the test will be skipped.
        """
        self.cqe_comp_res_format = cqe_comp_res_format
        self.flags = flags
        self.cqe_size = cqe_size
        self.requested_dev_cap = requested_dev_cap
        super().__init__(dev_name, ib_port, gid_index, msg_size=msg_size)

    def create_context(self):
        mlx5dv_attr = Mlx5DVContextAttr()
        try:
            self.ctx = Mlx5Context(mlx5dv_attr, name=self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 context is not supported')
        if self.requested_dev_cap:
            if not self.ctx.query_mlx5_device().flags & self.requested_dev_cap:
                miss_caps = context_flags_to_str(self.requested_dev_cap)
                raise unittest.SkipTest(f'Device caps doesn\'t support {miss_caps}')

    def create_cq(self):
        create_dv_cq(self)


class Mlx5DvCqDcRes(Mlx5DcResources):
    def __init__(self, dev_name, ib_port, gid_index, cqe_comp_res_format=None,
                 flags=None, cqe_size=None, create_flags=None):
        """
        Initialize Mlx5 DV CQ resources based on RC resources that include RC
        QP.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param cqe_comp_res_format: Type of compression to use
        :param flags: DV CQ specific flags
        :param cqe_size: The CQ's CQe size
        :param create_flags: DV QP specific flags
        """
        self.cqe_comp_res_format = cqe_comp_res_format
        self.flags = flags
        self.cqe_size = cqe_size
        super().__init__(dev_name, ib_port, gid_index,
                         send_ops_flags=e.IBV_QP_EX_WITH_SEND,
                         create_flags=create_flags)

    def create_cq(self):
        create_dv_cq(self)


class DvCqTest(Mlx5RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None
        self.traffic_args = None

    def create_players(self, resource, **resource_arg):
        """
        Init DV CQ tests resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
        attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)
        if resource == Mlx5DvCqDcRes:
            self.client.remote_dct_num = self.server.dct_qp.qp_num
            self.server.remote_dct_num = self.client.dct_qp.qp_num
        self.traffic_args = {'client': self.client, 'server': self.server,
                             'iters': self.iters, 'gid_idx': self.gid_index,
                             'port': self.ib_port}

    def test_dv_cq_traffic(self):
        """
        Run SEND traffic using DC CQ.
        """
        self.create_players(Mlx5CQRes)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_dv_cq_compression_flags(self):
        """
        Create DV CQ with different types of CQE compression formats. The test
        also does bad flow and try to use more than one compression formats.
        """
        # Create DV CQ with all legal compression flags.
        for comp_type in [dve.MLX5DV_CQE_RES_FORMAT_CSUM_STRIDX,
                          dve.MLX5DV_CQE_RES_FORMAT_CSUM,
                          dve.MLX5DV_CQE_RES_FORMAT_HASH]:
            self.create_players(Mlx5CQRes, cqe_comp_res_format=comp_type,
                                requested_dev_cap=dve.MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP)
            u.traffic(**self.traffic_args, is_cq_ex=True)

        # Try to create DV CQ with more than one compression flags.
        cqe_multi_format = dve.MLX5DV_CQE_RES_FORMAT_HASH | \
            dve.MLX5DV_CQE_RES_FORMAT_CSUM
        with self.assertRaises(PyverbsRDMAError) as ex:
            self.create_players(Mlx5CQRes, cqe_comp_res_format=cqe_multi_format)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

    def test_dv_cq_padding(self):
        """
        Create DV CQ with padding flag.
        """
        self.create_players(Mlx5CQRes, cqe_size=128,
                            flags=dve.MLX5DV_CQ_INIT_ATTR_FLAGS_CQE_PAD,
                            requested_dev_cap=dve.MLX5DV_CONTEXT_FLAGS_CQE_128B_PAD)
        u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_dv_cq_padding_not_aligned_cqe_size(self):
        """
        Create DV CQ with padding flag when CQE size is not 128B. The creation
        should fail because padding is supported only with CQE size of 128B.
        """
        # Padding flag works only when the cqe size is 128.
        with self.assertRaises(PyverbsRDMAError) as ex:
            self.create_players(Mlx5CQRes, cqe_size=64,
                                flags=dve.MLX5DV_CQ_INIT_ATTR_FLAGS_CQE_PAD,
                                requested_dev_cap=dve.MLX5DV_CONTEXT_FLAGS_CQE_128B_PAD)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

    def test_dv_cq_cqe_size_128(self):
        """
        Test multiple sizes of msg using CQE size of 128B.
        """
        msg_sizes = [60,  # Lower than 64B
                     70,  # In range of 64B - 128B
                     140]  # Bigger than 128B
        for size in msg_sizes:
            self.create_players(Mlx5CQRes, cqe_size=128, msg_size=size)
            u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_dv_cq_cqe_size_64(self):
        """
        Test multiple sizes of msg using CQE size of 64B.
        """
        msg_sizes = [16,  # Lower than 32B
                     60,  # In range of 32B - 64B
                     70]  # Bigger than 64B
        for size in msg_sizes:
            self.create_players(Mlx5CQRes, cqe_size=64, msg_size=size)
            u.traffic(**self.traffic_args, is_cq_ex=True)

    def test_dv_cq_cqe_size_with_bad_size(self):
        """
        Create CQ with ilegal cqe_size value.
        """
        # Set the CQE size in the CQE creation.
        with self.assertRaises(PyverbsRDMAError) as ex:
            self.create_players(Mlx5CQRes, cqe_size=100)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

        # Set the CQE size using the environment value.
        self.set_env_variable('MLX5_CQE_SIZE', '100')
        with self.assertRaises(PyverbsRDMAError) as ex:
            self.create_players(Mlx5CQRes)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

    def test_dv_cq_cqe_size_environment_var(self):
        """
        Create DV CQs with all the legal cqe_size values using the environment
        variable mechanism.
        """
        for cqe_size in ['64', '128']:
            self.set_env_variable('MLX5_CQE_SIZE', cqe_size)
            self.create_players(Mlx5CQRes)

    def test_scatter_to_cqe_control_by_qp(self):
        """
        Create QP with specific SCATTER_TO_CQE flags. The test set different
        values in the scatter2cqe environment variable and create the QP with
        enable/disable flags. The QP should ignore the environment variable
        value and behave according to the specific creation flag.
        """
        for s2c_env_val in ['0', '1']:
            for qp_s2c_value in [dve.MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE,
                                 dve.MLX5DV_QP_CREATE_ALLOW_SCATTER_TO_CQE]:
                self.set_env_variable('MLX5_SCATTER_TO_CQE', s2c_env_val)
                self.create_players(Mlx5DvCqDcRes, create_flags=qp_s2c_value)
                u.traffic(**self.traffic_args, new_send=True,
                          send_op=e.IBV_QP_EX_WITH_SEND, is_cq_ex=True)
