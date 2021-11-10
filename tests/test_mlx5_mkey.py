# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

import unittest
import random
import errno

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, \
    Mlx5DVQPInitAttr, Mlx5QP
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError, \
    PyverbsError
from pyverbs.providers.mlx5.mlx5dv_mkey import Mlx5Mkey, Mlx5MrInterleaved, \
    Mlx5MkeyConfAttr, Mlx5SigT10Dif, Mlx5SigCrc, Mlx5SigBlockDomain, \
    Mlx5SigBlockAttr
from tests.base import RCResources, RDMATestCase
import pyverbs.providers.mlx5.mlx5_enums as dve
from pyverbs.wr import SGE, SendWR, RecvWR
from pyverbs.qp import QPInitAttrEx, QPCap, QPAttr
import pyverbs.enums as e
import tests.utils as u


class Mlx5MkeyResources(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, dv_send_ops_flags=0,
                 mkey_create_flags=dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT,
                 dv_qp_create_flags=dve.MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE):
        self.dv_send_ops_flags = dv_send_ops_flags
        self.mkey_create_flags = mkey_create_flags
        self.dv_qp_create_flags = dv_qp_create_flags
        if dv_send_ops_flags & dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE:
            self.max_inline_data = 512
        else:
            self.max_inline_data = 0

        self.qp_access_flags = e.IBV_ACCESS_LOCAL_WRITE
        self.send_ops_flags = e.IBV_QP_EX_WITH_SEND
        # The signature pipelining tests use RDMA_WRITE. Allow RDMA_WRITE
        # if the pipelining flag is enabled for the QP.
        if self.dv_qp_create_flags & dve.MLX5DV_QP_CREATE_SIG_PIPELINING:
            self.qp_access_flags |= e.IBV_ACCESS_REMOTE_WRITE
            self.send_ops_flags |= e.IBV_QP_EX_WITH_RDMA_WRITE

        super().__init__(dev_name, ib_port, gid_index)
        self.create_mkey()

    def create_context(self):
        mlx5dv_attr = Mlx5DVContextAttr()
        try:
            self.ctx = Mlx5Context(mlx5dv_attr, name=self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 context is not supported')

    def create_mkey(self):
        try:
            self.mkey = Mlx5Mkey(self.pd, self.mkey_create_flags, 3)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Create Mkey is not supported')
            raise ex

    def create_qp_cap(self):
        return QPCap(max_send_wr=self.num_msgs, max_recv_wr=self.num_msgs,
                     max_inline_data=self.max_inline_data)

    def create_qp_init_attr(self):
        comp_mask = e.IBV_QP_INIT_ATTR_PD | e.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
        return QPInitAttrEx(cap=self.create_qp_cap(), pd=self.pd, scq=self.cq,
                            rcq=self.cq, qp_type=e.IBV_QPT_RC,
                            send_ops_flags=self.send_ops_flags,
                            comp_mask=comp_mask)

    def create_qp_attr(self):
        attr = super().create_qp_attr()
        attr.qp_access_flags = self.qp_access_flags
        return attr

    def create_qps(self):
        try:
            qp_init_attr = self.create_qp_init_attr()
            comp_mask = dve.MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS |\
                 dve.MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS
            attr = Mlx5DVQPInitAttr(comp_mask=comp_mask,
                                    create_flags=self.dv_qp_create_flags,
                                    send_ops_flags=self.dv_send_ops_flags)
            qp = Mlx5QP(self.ctx, qp_init_attr, attr)
            self.qps.append(qp)
            self.qps_num.append(qp.qp_num)
            self.psns.append(random.getrandbits(24))
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create Mlx5DV QP is not supported')
            raise ex


class Mlx5MkeyTest(RDMATestCase):
    """
    Test various functionalities of the mlx5 mkeys.
    """
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

    def create_players(self, resource, **resource_arg):
        """
        Init Mkey test resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)

    def reg_mr_list(self, configure_mkey=False):
        """
        Register a list of SGEs using the player's mkeys.
        :param configure_mkey: If True, use the mkey configuration API.
        """
        for player in [self.server, self.client]:
            player.qp.wr_start()
            player.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
            sge_1 = SGE(player.mr.buf, 8, player.mr.lkey)
            sge_2 = SGE(player.mr.buf + 64, 8, player.mr.lkey)
            if configure_mkey:
                player.qp.wr_mkey_configure(player.mkey, 2, Mlx5MkeyConfAttr())
                player.qp.wr_set_mkey_access_flags(e.IBV_ACCESS_LOCAL_WRITE)
                player.qp.wr_set_mkey_layout_list([sge_1, sge_2])
            else:
                player.qp.wr_mr_list(player.mkey, e.IBV_ACCESS_LOCAL_WRITE,
                                     sge_list=[sge_1, sge_2])
            player.qp.wr_complete()
            u.poll_cq(player.cq)

    def reg_mr_interleaved(self, configure_mkey=False):
        """
        Register an interleaved memory layout using the player's mkeys.
        :param configure_mkey: Use the mkey configuration API.
        """
        for player in [self.server, self.client]:
            player.qp.wr_start()
            player.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
            mr_interleaved_1 = Mlx5MrInterleaved(addr=player.mr.buf, bytes_count=8,
                                                 bytes_skip=2, lkey=player.mr.lkey)
            mr_interleaved_2 = Mlx5MrInterleaved(addr=player.mr.buf + 64, bytes_count=8,
                                                 bytes_skip=2, lkey=player.mr.lkey)
            mr_interleaved_lst = [mr_interleaved_1, mr_interleaved_2]
            mkey_access = e.IBV_ACCESS_LOCAL_WRITE
            if configure_mkey:
                player.qp.wr_mkey_configure(player.mkey, 2, Mlx5MkeyConfAttr())
                player.qp.wr_set_mkey_access_flags(mkey_access)
                player.qp.wr_set_mkey_layout_interleaved(3, mr_interleaved_lst)
            else:
                player.qp.wr_mr_interleaved(player.mkey, e.IBV_ACCESS_LOCAL_WRITE,
                                            repeat_count=3, mr_interleaved_lst=mr_interleaved_lst)
            player.qp.wr_complete()
            u.poll_cq(player.cq)

    def reg_mr_sig_t10dif(self):
        """
        Register the player's mkeys with T10DIF signature on the wire domain.
        """
        for player in [self.server, self.client]:
            player.qp.wr_start()
            player.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
            sge = SGE(player.mr.buf, 512, player.mr.lkey)
            player.qp.wr_mkey_configure(player.mkey, 3, Mlx5MkeyConfAttr())
            player.qp.wr_set_mkey_access_flags(e.IBV_ACCESS_LOCAL_WRITE)
            player.qp.wr_set_mkey_layout_list([sge])

            t10dif_flags = (dve.MLX5DV_SIG_T10DIF_FLAG_REF_REMAP |
                            dve.MLX5DV_SIG_T10DIF_FLAG_APP_ESCAPE |
                            dve.MLX5DV_SIG_T10DIF_FLAG_APP_REF_ESCAPE)
            sig_t10dif = Mlx5SigT10Dif(bg_type=dve.MLX5DV_SIG_T10DIF_CRC,
                                       bg=0xFFFF, app_tag=0xABCD,
                                       ref_tag=0x01234567, flags=t10dif_flags)

            sig_type = dve.MLX5DV_SIG_TYPE_T10DIF
            block_size = dve.MLX5DV_BLOCK_SIZE_512
            sig_block_domain = Mlx5SigBlockDomain(sig_type=sig_type,
                                                  dif=sig_t10dif,
                                                  block_size=block_size)

            check_mask = (dve.MLX5DV_SIG_MASK_T10DIF_GUARD |
                          dve.MLX5DV_SIG_MASK_T10DIF_APPTAG |
                          dve.MLX5DV_SIG_MASK_T10DIF_REFTAG)
            sig_attr = Mlx5SigBlockAttr(wire=sig_block_domain,
                                        check_mask=check_mask)
            player.qp.wr_set_mkey_sig_block(sig_attr)
            player.qp.wr_complete()
            u.poll_cq(player.cq)

    def reg_mr_sig_crc(self):
        """
        Register the player's mkeys with CRC32 signature on the wire domain.
        """
        for player in [self.server, self.client]:
            player.qp.wr_start()
            player.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
            sge = SGE(player.mr.buf, 512, player.mr.lkey)
            player.qp.wr_mkey_configure(player.mkey, 3, Mlx5MkeyConfAttr())
            player.qp.wr_set_mkey_access_flags(e.IBV_ACCESS_LOCAL_WRITE)
            player.qp.wr_set_mkey_layout_list([sge])

            sig_crc = Mlx5SigCrc(crc_type=dve.MLX5DV_SIG_CRC_TYPE_CRC32,
                                 seed=0xFFFFFFFF)
            sig_block_domain = Mlx5SigBlockDomain(sig_type=dve.MLX5DV_SIG_TYPE_CRC,
                                                  crc=sig_crc,
                                                  block_size=dve.MLX5DV_BLOCK_SIZE_512)
            sig_attr = Mlx5SigBlockAttr(wire=sig_block_domain,
                                        check_mask=dve.MLX5DV_SIG_MASK_CRC32)
            player.qp.wr_set_mkey_sig_block(sig_attr)
            player.qp.wr_complete()
            u.poll_cq(player.cq)

    def reg_mr_sig_err(self):
        """
        Register the player's mkeys with an SGE and CRC32 signature on
        the memory domain. Data transport operation with these MKEYs will cause
        a signature error because the test does not fill out the signature in
        the memory buffer.
        """

        sig_crc = Mlx5SigCrc(crc_type=dve.MLX5DV_SIG_CRC_TYPE_CRC32,
                             seed=0xFFFFFFFF)

        block_size = dve.MLX5DV_BLOCK_SIZE_512
        sig_block_domain = Mlx5SigBlockDomain(sig_type=dve.MLX5DV_SIG_TYPE_CRC,
                                              crc=sig_crc,
                                              block_size=block_size)
        sig_attr = Mlx5SigBlockAttr(mem=sig_block_domain,
                                    check_mask=dve.MLX5DV_SIG_MASK_CRC32)

        # Configure the mkey on the server side
        self.server.qp.wr_start()
        self.server.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
        sge = SGE(self.server.mr.buf, 512, self.server.mr.lkey)
        self.server.qp.wr_mkey_configure(self.server.mkey, 2,
                                         Mlx5MkeyConfAttr())
        self.server.qp.wr_set_mkey_access_flags(e.IBV_ACCESS_LOCAL_WRITE)
        self.server.qp.wr_set_mkey_layout_list([sge])
        self.server.qp.wr_complete()
        u.poll_cq(self.server.cq)

        # Configure the mkey on the client side
        self.client.qp.wr_start()
        self.client.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
        sge = SGE(self.client.mr.buf, 512 + 4, self.client.mr.lkey)
        self.client.qp.wr_mkey_configure(self.client.mkey, 3,
                                         Mlx5MkeyConfAttr())
        self.client.qp.wr_set_mkey_access_flags(e.IBV_ACCESS_LOCAL_WRITE)
        self.client.qp.wr_set_mkey_layout_list([sge])
        self.client.qp.wr_set_mkey_sig_block(sig_attr)
        self.client.qp.wr_complete()
        u.poll_cq(self.client.cq)

    def reg_mr_sig_pipelining_server(self):
        """
        Register mkey without signature.
        """
        self.server.qp.wr_start()
        self.server.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
        sge = SGE(self.server.mr.buf, 512, self.server.mr.lkey)
        self.server.qp.wr_mkey_configure(self.server.mkey, 2,
                                         Mlx5MkeyConfAttr())
        self.server.qp.wr_set_mkey_access_flags(e.IBV_ACCESS_LOCAL_WRITE |
                                                e.IBV_ACCESS_REMOTE_WRITE)
        self.server.qp.wr_set_mkey_layout_list([sge])
        self.server.qp.wr_complete()
        u.poll_cq(self.server.cq)

    def reg_mr_sig_pipelining_client(self, check_mask=0):
        """
        Register mkey with CRC32 signature in memory domain and no
        signature in wire domain.
        :param check_mask: The mask for the signature checking.
        """
        self.client.qp.wr_start()
        self.client.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
        # Add 4 bytes for CRC32 signature
        sge = SGE(self.client.mr.buf, 512 + 4, self.client.mr.lkey)
        self.client.qp.wr_mkey_configure(self.client.mkey, 3,
                                         Mlx5MkeyConfAttr())
        self.client.qp.wr_set_mkey_access_flags(e.IBV_ACCESS_LOCAL_WRITE)
        self.client.qp.wr_set_mkey_layout_list([sge])

        sig = Mlx5SigCrc(crc_type = dve.MLX5DV_SIG_CRC_TYPE_CRC32)
        sig_domain = Mlx5SigBlockDomain(sig_type=dve.MLX5DV_SIG_TYPE_CRC,
                                        crc=sig,
                                        block_size=dve.MLX5DV_BLOCK_SIZE_512)
        sig_attr = Mlx5SigBlockAttr(mem=sig_domain,
                                    check_mask=check_mask)
        self.client.qp.wr_set_mkey_sig_block(sig_attr)
        self.client.qp.wr_complete()
        u.poll_cq(self.client.cq)

    def build_traffic_elements(self, sge_size):
        """
        Build the server and client send/recv work requests.
        :param sge_size: The sge send size using the mkey.
        """
        opcode = e.IBV_WR_SEND
        server_sge = SGE(0, sge_size, self.server.mkey.lkey)
        self.server_recv_wr = RecvWR(sg=[server_sge], num_sge=1)
        client_sge = SGE(0, sge_size, self.client.mkey.lkey)
        self.client_send_wr = SendWR(opcode=opcode, num_sge=1, sg=[client_sge])

    def build_traffic_elements_sig_pipelining(self):
        """
        Build two WRs for data and response on client side and one WR for
        response on server side. Transaction consists of two operations:
        RDMA write of data and send/recv of response. Data size is
        512 bytes, response size is 16 bytes. For simplicity the same
        memory is used for data and response. Data is transferred using
        the player signature mkey. Response is transferred using the
        plain MR.
        """
        server_sge_resp = SGE(self.server.mr.buf, 16, self.server.mr.lkey)
        self.server_resp_wr = RecvWR(sg=[server_sge_resp], num_sge=1)
        client_sge_data = SGE(0, 512, self.client.mkey.lkey)
        self.client_data_wr = SendWR(wr_id=1, opcode=e.IBV_WR_RDMA_WRITE,
                                     num_sge=1, sg=[client_sge_data],
                                     send_flags=0)
        self.client_data_wr.set_wr_rdma(self.server.mkey.rkey, 0)
        client_sge_resp = SGE(self.client.mr.buf, 16, self.client.mr.lkey)
        client_send_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_FENCE
        self.client_resp_wr = SendWR(wr_id=1, opcode=e.IBV_WR_SEND, num_sge=1,
                                     sg=[client_sge_resp],
                                     send_flags=client_send_flags)

    def traffic(self, sge_size, exp_buffer):
        """
        Perform RC traffic using the mkey.
        :param sge_size: The sge size using the mkey.
        :param exp_buffer: The expected result of the receive buffer after
                           the traffic operation.
        """
        self.build_traffic_elements(sge_size)
        self.server.qp.post_recv(self.server_recv_wr)
        for _ in range(self.iters):
            self.server.mr.write('s' * self.server.msg_size,
                                 self.server.msg_size)
            self.client.mr.write('c' * self.client.msg_size,
                                 self.client.msg_size)
            self.client.qp.post_send(self.client_send_wr)
            u.poll_cq(self.client.cq)
            u.poll_cq(self.server.cq)
            self.server.qp.post_recv(self.server_recv_wr)
            act_buffer = self.server.mr.read(len(exp_buffer), 0).decode()
            if act_buffer != exp_buffer:
                raise PyverbsError('Data validation failed: expected '
                                   f'{exp_buffer}, received {act_buffer}')

    def traffic_scattered_data(self, sge_size=16):
        exp_buffer=((('c' * 8 + 's' * 56) *2)[:100])
        self.traffic(sge_size=sge_size, exp_buffer=exp_buffer)

    def traffic_sig(self):
        exp_buffer=('c' * 512 + 's' * (self.server.msg_size - 512))
        self.traffic(sge_size=512, exp_buffer=exp_buffer)

    def invalidate_mkeys(self):
        """
        Invalidate the players mkey.
        """
        for player in [self.server, self.client]:
            inv_send_wr = SendWR(opcode=e.IBV_WR_LOCAL_INV)
            inv_send_wr.imm_data = player.mkey.lkey
            player.qp.post_send(inv_send_wr)
            u.poll_cq(player.cq)

    def check_mkey(self, player, expected=dve.MLX5DV_MKEY_NO_ERR):
        """
        Check the player's mkey for a signature error.
        param player: Player to check.
        param expected: The expected result of the checking.
        """
        mkey_err = player.mkey.mkey_check()
        if mkey_err.err_type != expected:
            raise PyverbsRDMAError('MKEY check failed: '
                    f'expected err_type: {expected_type}, '
                    f'actual err_type: {mkey_err.err_type}')

    def test_mkey_interleaved(self):
        """
        Create Mkeys, register an interleaved memory layout using this mkey and
        then perform traffic using it.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MR_INTERLEAVED)
        self.reg_mr_interleaved()
        self.traffic_scattered_data()
        self.invalidate_mkeys()

    def test_mkey_list(self):
        """
        Create Mkeys, register a memory layout using this mkey and then perform
        traffic using this mkey.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MR_LIST)
        self.reg_mr_list()
        self.traffic_scattered_data()
        self.invalidate_mkeys()

    def test_mkey_list_new_api(self):
        """
        Create Mkeys, configure it with memory layout using the new API and
        traffic using this mkey.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE)
        self.reg_mr_list(configure_mkey=True)
        self.traffic_scattered_data()
        self.invalidate_mkeys()

    def test_mkey_interleaved_new_api(self):
        """
        Create Mkeys, configure it with interleaved memory layout using the new
        API and then perform traffic using it.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE)
        self.reg_mr_interleaved(configure_mkey=True)
        self.traffic_scattered_data()
        self.invalidate_mkeys()

    def test_mkey_list_bad_flow(self):
        """
        Create Mkeys, register a memory layout using this mkey and then try to
        access the memory out of the mkey defined region. Expect this case to
        fail.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MR_LIST)
        self.reg_mr_list()
        with self.assertRaises(PyverbsRDMAError) as ex:
            self.traffic_scattered_data(sge_size=100)

    def test_mkey_sig_t10dif(self):
        """
        Create Mkeys, configure it with T10DIF signature and traffic using
        this mkey.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
                            mkey_create_flags=dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT |
                                              dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE)
        self.reg_mr_sig_t10dif()
        self.traffic_sig()
        self.check_mkey(self.server)
        self.check_mkey(self.client)
        self.invalidate_mkeys()

    def test_mkey_sig_crc(self):
        """
        Create Mkeys, configure it with CRC32 signature and traffic using
        this mkey.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
                            mkey_create_flags=dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT |
                                              dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE)
        self.reg_mr_sig_crc()
        self.traffic_sig()
        self.check_mkey(self.server)
        self.check_mkey(self.client)
        self.invalidate_mkeys()

    def test_mkey_sig_err(self):
        """
        Test the signature error handling flow. Create Mkeys, configure it
        CRC32 signature on the memory domain but do not set a valid signature
        in the memory buffer. Run traffic using this mkey, ensure that the
        signature error is detected.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
                            mkey_create_flags=dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT |
                                              dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE)
        self.reg_mr_sig_err()
        # The test supports only one iteration because mkey re-registration
        # is required after each signature error.
        self.iters = 1
        self.traffic_sig()
        self.check_mkey(self.client, dve.MLX5DV_MKEY_SIG_BLOCK_BAD_GUARD)
        self.check_mkey(self.server)
        self.invalidate_mkeys()

    def test_mkey_sig_pipelining_good(self):
        """
        Test the good signature pipelining scenario.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
                            mkey_create_flags=dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT |
                                              dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE,
                            dv_qp_create_flags=dve.MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE |
                                               dve.MLX5DV_QP_CREATE_SIG_PIPELINING)
        self.reg_mr_sig_pipelining_client()
        self.reg_mr_sig_pipelining_server()
        self.build_traffic_elements_sig_pipelining()

        self.server.qp.post_recv(self.server_resp_wr)
        self.client.qp.post_send(self.client_data_wr)
        self.client.qp.post_send(self.client_resp_wr)

        u.poll_cq(self.client.cq)
        u.poll_cq(self.server.cq)

    def test_mkey_sig_pipelining_bad(self):
        """
        Test the bad signature pipelining scenario.
        """
        self.create_players(Mlx5MkeyResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
                            mkey_create_flags=dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT |
                                              dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE,
                            dv_qp_create_flags=dve.MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE |
                                               dve.MLX5DV_QP_CREATE_SIG_PIPELINING)
        self.reg_mr_sig_pipelining_client(check_mask=dve.MLX5DV_SIG_MASK_CRC32)
        self.reg_mr_sig_pipelining_server()
        self.build_traffic_elements_sig_pipelining()

        self.server.qp.post_recv(self.server_resp_wr)
        self.client.qp.post_send(self.client_data_wr)
        self.client.qp.post_send(self.client_resp_wr)

        # Expect SQ_DRAINED event
        event = self.client.ctx.get_async_event()
        event.ack()
        self.assertEqual(event.event_type, e.IBV_EVENT_SQ_DRAINED)
        # No completion is expected on the client side
        nc, _ = self.client.cq.poll(1)
        self.assertEqual(nc, 0)
        # No completion is expected on the server side
        nc, _ = self.server.cq.poll(1)
        self.assertEqual(nc, 0)
        self.check_mkey(self.client, dve.MLX5DV_MKEY_SIG_BLOCK_BAD_GUARD)
        self.check_mkey(self.server)

        # Cancel and repost response WR
        canceled_count = self.client.qp.cancel_posted_send_wrs(1)
        self.assertEqual(canceled_count, 1)
        self.client.qp.post_send(self.client_resp_wr)

        # Move QP back to RTS and receive completions
        self.client.qp.modify(QPAttr(qp_state=e.IBV_QPS_RTS,
                                     cur_qp_state=e.IBV_QPS_SQD),
                              e.IBV_QP_STATE | e.IBV_QP_CUR_STATE)
        u.poll_cq(self.client.cq)
        u.poll_cq(self.server.cq)
