# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

from enum import Enum
import unittest

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
from tests.mlx5_base import Mlx5RDMATestCase, Mlx5RcResources
import pyverbs.providers.mlx5.mlx5_enums as dve
from pyverbs.pd import PD
from pyverbs.mr import MR
import pyverbs.enums as e
import tests.utils as u


class BadFlowType(Enum):
    DIFFERENT_PD = 1
    MR_ILLEGAL_ACCESS = 2


class Mlx5DmaResources(Mlx5RcResources):
    def create_send_ops_flags(self):
        self.dv_send_ops_flags = dve.MLX5DV_QP_EX_WITH_MEMCPY
        self.send_ops_flags = e.IBV_QP_EX_WITH_SEND


class DmaGgaMemcpy(Mlx5RDMATestCase):
    def create_resources(self, bad_flow_type=0, **resource_arg):
        """
        Creates DmaGga test resources that include a "server" resource that
        can be used to send the MEMCPY WR, and a destination MR to copy data to.
        The destination MR can be created on a different PD or with insufficient
        access permissions, according to the bad_flow_type.
        :param bad_flow_type: (Optional) An enum of BadFlowType that indicates
                              the bad flow type (default: 0 - good flow)
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        :return: None
        """
        self.server = Mlx5DmaResources(**self.dev_info, **resource_arg)
        self.dest_pd = self.server.pd
        dest_mr_access = e.IBV_ACCESS_LOCAL_WRITE
        if bad_flow_type == BadFlowType.DIFFERENT_PD:
            self.dest_pd = PD(self.server.ctx)
        elif bad_flow_type == BadFlowType.MR_ILLEGAL_ACCESS:
            dest_mr_access = e.IBV_ACCESS_REMOTE_READ
        self.dest_mr = MR(self.dest_pd, self.server.msg_size, dest_mr_access)
        # No need to connect the QPs
        self.server.pre_run([0], [0])

    def dma_memcpy(self, msg_size=1024):
        """
        Creates resources and posts a memcpy WR.
        After posting the WR, the WC opcode and the data are verified.
        :param msg_size: Size of the data to be copied (in Bytes)
        :return: None
        """
        self.create_resources(msg_size=msg_size)
        self.dest_mr.write('0' * msg_size, msg_size)
        self.server.mr.write('s' * msg_size, msg_size)
        self.server.qp.wr_start()
        self.server.qp.wr_flags = e.IBV_SEND_SIGNALED
        self.server.qp.wr_memcpy(self.dest_mr.lkey, self.dest_mr.buf, self.server.mr.lkey,
                                 self.server.mr.buf, msg_size)
        self.server.qp.wr_complete()
        u.poll_cq_ex(self.server.cq)
        wc_opcode = self.server.cq.read_opcode()
        self.assertEqual(wc_opcode, dve.MLX5DV_WC_MEMCPY,
                         'WC opcode validation failed')
        self.assertEqual(self.dest_mr.read(msg_size, 0),
                         self.server.mr.read(msg_size, 0))

    def dma_memcpy_bad_protection_flow(self, bad_flow_type):
        """
        Creates resources with bad protection and posts a memcpy WR.
        The bad protection is either a destination MR created on a different PD
        or a destination MR created with insufficient access permissions.
        :param bad_flow_type: An enum of BadFlowType that indicates the bad flow type
        :return: None
        """
        self.create_resources(bad_flow_type)
        self.server.qp.wr_start()
        self.server.qp.wr_flags = e.IBV_SEND_SIGNALED
        self.server.qp.wr_memcpy(self.dest_mr.lkey, self.dest_mr.buf,
                                 self.server.mr.lkey,
                                 self.server.mr.buf, self.server.msg_size)
        self.server.qp.wr_complete()
        with self.assertRaises(PyverbsRDMAError):
            u.poll_cq_ex(self.server.cq)
        self.assertEqual(self.server.cq.status, e.IBV_WC_LOC_PROT_ERR,
                         'Expected CQE with Local Protection Error')

    def test_dma_memcpy_data(self):
        self.dma_memcpy()

    def test_dma_memcpy_different_pd_bad_flow(self):
        self.dma_memcpy_bad_protection_flow(BadFlowType.DIFFERENT_PD)

    def test_dma_memcpy_protection_bad_flow(self):
        self.dma_memcpy_bad_protection_flow(BadFlowType.MR_ILLEGAL_ACCESS)

    def test_dma_memcpy_large_data_bad_flow(self):
        """
        Bad flow test, testing DMA memcpy with data larger than the maximum
        allowed size, according to the HCA capabilities.
        :return: None
        """
        try:
            ctx = Mlx5Context(Mlx5DVContextAttr(), name=self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 context is not supported')
        max_size = ctx.query_mlx5_device(
            dve.MLX5DV_CONTEXT_MASK_WR_MEMCPY_LENGTH).max_wr_memcpy_length
        max_size = max_size if max_size else 1024

        with self.assertRaises(PyverbsRDMAError):
            self.dma_memcpy(max_size + 1)
