# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2022 Nvidia Inc. All rights reserved. See COPYING file

import resource

from pyverbs.providers.mlx5.mlx5dv import Mlx5DevxObj, WqeDataSeg, Mlx5UMEM
from tests.mlx5_base import Mlx5DevxRcResources, Mlx5DevxTrafficBase
import pyverbs.providers.mlx5.mlx5_enums as dve
import tests.cuda_utils as cu
import pyverbs.enums as e

try:
    from cuda import cuda, cudart, nvrtc
    cu.CUDA_FOUND = True
except ImportError:
    cu.CUDA_FOUND = False

GPU_PAGE_SIZE = 1 << 16


@cu.set_mem_io_cuda_methods
class CudaDevxRes(Mlx5DevxRcResources):
    def __init__(self, dev_name, ib_port, gid_index,
                 mr_access=e.IBV_ACCESS_LOCAL_WRITE):
        """
        Initialize DevX resources with CUDA memory allocations.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param mr_access: The MR access
        """
        self.mr_access = mr_access
        self.cuda_addr = None
        self.dmabuf_fd = None
        self.umem = None
        self.mkey = None
        self.lkey = None
        self.lkey = None
        super().__init__(dev_name=dev_name, ib_port=ib_port, gid_index=gid_index)

    def init_resources(self):
        self.alloc_cuda_mem()
        super().init_resources()
        self.create_dmabuf_umem()
        self.create_mkey()

    def get_wqe_data_segment(self):
        return WqeDataSeg(self.msg_size, self.lkey, int(self.cuda_addr))

    def alloc_cuda_mem(self):
        """
        Allocates CUDA memory and a DMABUF FD on that memory.
        """
        self.cuda_addr = cu.check_cuda_errors(cuda.cuMemAlloc(GPU_PAGE_SIZE))

        # Sync between memory operations
        attr_value = 1
        cu.check_cuda_errors(cuda.cuPointerSetAttribute(
            attr_value,
            cuda.CUpointer_attribute.CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,
            int(self.cuda_addr)
        ))

        # Memory address and size must be aligned to page size to get a handle
        assert (GPU_PAGE_SIZE % resource.getpagesize() == 0 and
                int(self.cuda_addr) % resource.getpagesize() == 0)
        self.dmabuf_fd = cu.check_cuda_errors(
            cuda.cuMemGetHandleForAddressRange(self.cuda_addr,
                                               GPU_PAGE_SIZE,
                                               cuda.CUmemRangeHandleType.CU_MEM_RANGE_HANDLE_TYPE_DMA_BUF_FD,
                                               0))

    def create_mr(self):
        pass

    def create_dmabuf_umem(self):
        umem_aligment = resource.getpagesize()
        self.umem = Mlx5UMEM(self.ctx, GPU_PAGE_SIZE, 0,
                             umem_aligment, self.mr_access, umem_aligment,
                             dve.MLX5DV_UMEM_MASK_DMABUF, self.dmabuf_fd)

    def create_mkey(self):
        from tests.mlx5_prm_structs import SwMkc, CreateMkeyIn, CreateMkeyOut
        accesses = [e.IBV_ACCESS_LOCAL_WRITE, e.IBV_ACCESS_REMOTE_READ, e.IBV_ACCESS_REMOTE_WRITE]
        lw, rr, rw = (list(map(lambda access: int(self.mr_access & access != 0), accesses)))
        mkey_ctx = SwMkc(lr=1, lw=lw, rr=rr, rw=rw, access_mode_1_0=0x1,
                         start_addr=int(self.cuda_addr),
                         len=GPU_PAGE_SIZE, pd=self.dv_pd.pdn, qpn=0xffffff)
        self.mkey = Mlx5DevxObj(self.ctx, CreateMkeyIn(sw_mkc=mkey_ctx,
                                                       mkey_umem_id=self.umem.umem_id,
                                                       mkey_umem_valid=1),
                                len(CreateMkeyOut()))
        self.lkey = CreateMkeyOut(self.mkey.out_view).mkey_index << 8


@cu.set_init_cuda_methods
class Mlx5GpuDevxRcTrafficTest(Mlx5DevxTrafficBase):
    """
    Test DevX traffic over CUDA memory using DMA BUF and UMEM
    """

    @cu.requires_cuda
    def test_mlx_devx_cuda_send_imm_traffic(self):
        """
        Creates two DevX RC QPs and runs SEND_IMM traffic over CUDA allocated
        memory using UMEM and DMA BUF.
        """
        self.create_players(CudaDevxRes)
        # Send traffic
        self.send_imm_traffic()
