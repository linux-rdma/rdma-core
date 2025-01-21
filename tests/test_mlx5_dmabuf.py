# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2024 Nvidia Inc. All rights reserved. See COPYING file

from os import strerror
import unittest
import errno

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr
from pyverbs.providers.mlx5.mlx5dv_dmabuf import Mlx5DmaBufMR
from pyverbs.pyverbs_error import PyverbsRDMAError
import pyverbs.providers.mlx5.mlx5_enums as dve
from tests.mlx5_base import Mlx5RDMATestCase
from tests.base import RCResources
from pyverbs.qp import QPAttr
import tests.cuda_utils as cu
import pyverbs.enums as e
import tests.utils as u

try:
    from cuda import cuda
    cu.CUDA_FOUND = True
except ImportError:
    cu.CUDA_FOUND = False


GPU_PAGE_SIZE = 1 << 16


def requires_data_direct_support():
    """
    Check if the device support data-direct
    """
    def outer(func):
        def inner(instance):
            with Mlx5Context(Mlx5DVContextAttr(), name=instance.dev_name) as ctx:
                try:
                    ctx.get_data_direct_sysfs_path()
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.ENODEV:
                        raise unittest.SkipTest('There is no data direct device in the system')
                    raise ex
            return func(instance)
        return inner
    return outer


@cu.set_mem_io_cuda_methods
class Mlx5DmabufCudaRes(RCResources):
    def __init__(self, dev_name, ib_port, gid_index,
                 mr_access=e.IBV_ACCESS_LOCAL_WRITE, mlx5_access=0):
        """
        Initializes data-direct MR and DMA BUF resources on top of a CUDA memory.
        Uses RC QPs for traffic.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param mr_access: The MR access
        :param mlx5_access: The data-direct access
        """
        self.mr_access = mr_access
        self.mlx5_access = mlx5_access
        self.cuda_addr = None
        super().__init__(dev_name=dev_name, ib_port=ib_port, gid_index=gid_index)

    def create_mr(self):
        self.cuda_addr = cu.check_cuda_errors(cuda.cuMemAlloc(GPU_PAGE_SIZE))

        attr_flag = 1
        cu.check_cuda_errors(cuda.cuPointerSetAttribute(
            attr_flag,
            cuda.CUpointer_attribute.CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,
            int(self.cuda_addr)))

        cuda_flag = cuda.CUmemRangeHandleType.CU_MEM_RANGE_HANDLE_TYPE_DMA_BUF_FD
        dmabuf_fd = cu.check_cuda_errors(
            cuda.cuMemGetHandleForAddressRange(self.cuda_addr,
                                               GPU_PAGE_SIZE,
                                               cuda_flag,
                                               0))
        try:
            self.mr = Mlx5DmaBufMR(self.pd, offset=0, length=self.msg_size, access=self.mr_access,
                                   fd=dmabuf_fd, mlx5_access=self.mlx5_access)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Registering DV DMABUF MR is not supported')
            raise ex

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE | \
                    e.IBV_ACCESS_REMOTE_READ
        qp_attr.qp_access_flags = qp_access
        return qp_attr


@cu.set_init_cuda_methods
class Mlx5DmabufCudaTest(Mlx5RDMATestCase):
    """
    Test data-direct DV verbs
    """
    @requires_data_direct_support()
    def test_data_direct_sysfs_path_bad_length(self):
        """
        Query data direct sysfs path with buffer of 5 bytes. This is bad flow since 5 bytes aren't
        enough for any sysfs path, so ENOSPC should be raised.
        """
        ctx = Mlx5Context(Mlx5DVContextAttr(), name=self.dev_name)
        try:
            path = ctx.get_data_direct_sysfs_path(5)
        except PyverbsRDMAError as ex:
            self.assertEqual(ex.error_code, errno.ENOSPC,
                             f'Got {strerror(ex.error_code)} but Expected {strerror(errno.ENOSPC)}')
        else:
            raise PyverbsRDMAError('Successfully queried data direct sysfs path with 5 bytes: '
                                   f'{path}')

    def test_dv_dmabuf_mr(self):
        """
        Creates dmabuf MR with DV API. mlx5_access is 0, so the MR is regular dmabuf MR.
        Run RDMA write traffic.
        """
        access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        self.create_players(Mlx5DmabufCudaRes, mr_access=access)
        u.rdma_traffic(**self.traffic_args, send_op=e.IBV_WR_RDMA_WRITE)

    @requires_data_direct_support()
    def test_dv_dmabuf_mr_data_direct(self):
        """
        Runs RDMA Write traffic over CUDA allocated memory using Data Direct DMA BUF and
        RC QPs.
        """
        mr_access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        self.create_players(Mlx5DmabufCudaRes, mr_access=mr_access,
                            mlx5_access=dve.MLX5DV_REG_DMABUF_ACCESS_DATA_DIRECT_)
        u.rdma_traffic(**self.traffic_args, send_op=e.IBV_WR_RDMA_WRITE)
