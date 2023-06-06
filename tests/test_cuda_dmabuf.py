# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2022 Nvidia Inc. All rights reserved. See COPYING file

import unittest
import errno

from pyverbs.pyverbs_error import PyverbsRDMAError
from tests.base import RCResources, RDMATestCase
from pyverbs.mr import DmaBufMR
from pyverbs.qp import QPAttr
import tests.cuda_utils as cu
import pyverbs.enums as e
import tests.utils as u

try:
    from cuda import cuda, cudart, nvrtc
    cu.CUDA_FOUND = True
except ImportError:
    cu.CUDA_FOUND = False

GPU_PAGE_SIZE = 1 << 16


@cu.set_mem_io_cuda_methods
class DmabufCudaRes(RCResources):
    def __init__(self, dev_name, ib_port, gid_index,
                 mr_access=e.IBV_ACCESS_LOCAL_WRITE):
        """
        Initializes MR and DMA BUF resources on top of a CUDA memory.
        Uses RC QPs for traffic.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param mr_access: The MR access
        """
        self.mr_access = mr_access
        self.cuda_addr = None
        super().__init__(dev_name=dev_name, ib_port=ib_port, gid_index=gid_index)

    def create_mr(self):
        self.cuda_addr = cu.check_cuda_errors(cuda.cuMemAlloc(GPU_PAGE_SIZE))

        attr_flag = 1
        cu.check_cuda_errors(cuda.cuPointerSetAttribute(
            attr_flag,
            cuda.CUpointer_attribute.CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,
            int(self.cuda_addr)))

        dmabuf_fd = cu.check_cuda_errors(
            cuda.cuMemGetHandleForAddressRange(self.cuda_addr,
                                               GPU_PAGE_SIZE,
                                               cuda.CUmemRangeHandleType.CU_MEM_RANGE_HANDLE_TYPE_DMA_BUF_FD,
                                               0))
        try:
            self.mr = DmaBufMR(self.pd, self.msg_size, self.mr_access, dmabuf_fd)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest(f'Registering DMABUF MR is not supported')
            raise ex

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE | \
                    e.IBV_ACCESS_REMOTE_READ
        qp_attr.qp_access_flags = qp_access
        return qp_attr


@cu.set_init_cuda_methods
class DmabufCudaTest(RDMATestCase):
    """
    Test RDMA traffic over CUDA memory
    """

    def test_cuda_dmabuf_rdma_write_traffic(self):
        """
        Runs RDMA Write traffic over CUDA allocated memory using DMA BUF and
        RC QPs.
        """
        access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        self.create_players(DmabufCudaRes, mr_access=access)
        u.rdma_traffic(**self.traffic_args, send_op=e.IBV_WR_RDMA_WRITE)
