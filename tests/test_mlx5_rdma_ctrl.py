# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2025 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for Pyverbs' privileged context.
"""
import unittest
import errno

from pyverbs.providers.mlx5.mlx5dv import Mlx5DevxObj
from pyverbs.pyverbs_error import PyverbsRDMAError
from tests.mlx5_base import Mlx5RcResources, Mlx5PrivilegedRC
from tests.utils import requires_root
from tests.base import RDMATestCase
import tests.utils as u


class Mlx5RdmaCtrl(Mlx5PrivilegedRC):
    def __init__(self, dev_name, ib_port, gid_index, msg_size=1024, **kwargs):
        """
        Initialize mlx5 DV privileged context resources based on Mlx5PrivilegedRC.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param msg_size: The resource msg size
        :param kwargs: General arguments
        """
        self.rdma_ctrl_obj = None
        super().__init__(dev_name, ib_port, gid_index, msg_size=msg_size, **kwargs)

    def get_vhca_id(self):
        from tests.mlx5_prm_structs import QueryHcaCapIn, QueryCmdHcaCapOut
        try:
            query_cap_in = QueryHcaCapIn(op_mod=0x1)
            query_cap_out = QueryCmdHcaCapOut(self.ctx.devx_general_cmd(
                                              query_cap_in, len(QueryCmdHcaCapOut())))

            if query_cap_out.status:
                raise PyverbsRDMAError('Failed to query general HCA CAPs with syndrome '
                                    f'({query_cap_out.syndrome}')

        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest(f'mlx5dv_query_port() isn\'t supported')
            raise ex

        return query_cap_out.capability.vhca_id

    def create_rdma_ctrl_obj(self, vhca_id):
        """
        Create rdma ctrl obj.
        :param vhca_id: vhca id to control on.
        """
        from tests.mlx5_prm_structs import CreateGeneralObjIn, GeneralObjInCmdHdr, \
            CreateGeneralObjOut, RdmaCtrlObj, DevxOps, DevxGeneralObjTypes
        rdma_ctrl_obj_in = CreateGeneralObjIn(general_obj_in_cmd_hdr=GeneralObjInCmdHdr(
                                              opcode=DevxOps.MLX5_CMD_OP_CREATE_GENERAL_OBJECT,
                                              obj_type=DevxGeneralObjTypes.MLX5_OBJ_TYPE_RDMA_CTRL),
                                              obj_context=RdmaCtrlObj(other_vhca_id=vhca_id))
        self.rdma_ctrl_obj = Mlx5DevxObj(self.ctx, rdma_ctrl_obj_in, len(CreateGeneralObjOut()))
        rdma_ctrl_obj_out = CreateGeneralObjOut(self.rdma_ctrl_obj.out_view)

        if rdma_ctrl_obj_out.general_obj_out_cmd_hdr.status:
            raise PyverbsRDMAError(f'Failed to create rdma ctrl obj with syndrome \
                                   {rdma_ctrl_obj_out.general_obj_out_cmd_hdr.syndrome}')


class PrivilegeContextTestCase(RDMATestCase):
    def tearDown(self):
        """
        Cleans up resources if manual cleanup is needed.
        """
        if self.client and self.client.rdma_ctrl_obj:
            self.client.rdma_ctrl_obj.close()
        super().tearDown()

    @u.skip_unsupported
    @requires_root()
    def test_mlx5_rdma_ctrl_obj_traffic(self):
        """
        This test case verifies the functionality of Privilege RC traffic by executing the following
        steps:
        1. Initialize the client with Privilege RC context and server with regular RC context.
        2. Get the VHCA ID of the client.
        3. Create the RDMA control object on the client side (on privilege context).
        4. Run the traffic between client and server.
        """
        self.client = Mlx5RdmaCtrl(**self.dev_info)
        self.server = Mlx5RcResources(**self.dev_info)
        vhca_id = self.client.get_vhca_id()
        self.client.create_rdma_ctrl_obj(vhca_id)
        self.pre_run()
        self.sync_remote_attr()
        u.traffic(client=self.client, server=self.server,iters=self.iters,
                  gid_idx=self.gid_index, port=self.ib_port, is_cq_ex=True)
