# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 NVIDIA Corporation . All rights reserved. See COPYING file

import unittest
import random
import errno

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, \
    Mlx5DVQPInitAttr, Mlx5QP, Mlx5DVDCInitAttr, Mlx5DCIStreamInitAttr
from tests.base import TrafficResources, set_rnr_attributes, DCT_KEY, \
    RDMATestCase, PyverbsAPITestCase, RDMACMBaseTest
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError, \
    PyverbsError
from pyverbs.qp import QPCap, QPInitAttrEx, QPAttr
import pyverbs.providers.mlx5.mlx5_enums as dve
from pyverbs.addr import AHAttr, GlobalRoute
import pyverbs.device as d
from pyverbs.pd import PD
import pyverbs.enums as e
from pyverbs.mr import MR

MELLANOX_VENDOR_ID = 0x02c9
MLX5_DEVS = {
	0x1011, # MT4113 Connect-IB
	0x1012, # Connect-IB Virtual Function
	0x1013, # ConnectX-4
	0x1014, # ConnectX-4 Virtual Function
	0x1015, # ConnectX-4LX
	0x1016, # ConnectX-4LX Virtual Function
	0x1017, # ConnectX-5, PCIe 3.0
	0x1018, # ConnectX-5 Virtual Function
	0x1019, # ConnectX-5 Ex
	0x101a, # ConnectX-5 Ex VF
	0x101b, # ConnectX-6
	0x101c, # ConnectX-6 VF
	0x101d, # ConnectX-6 DX
	0x101e, # ConnectX family mlx5Gen Virtual Function
	0x101f, # ConnectX-6 LX
	0x1021, # ConnectX-7
	0xa2d2, # BlueField integrated ConnectX-5 network controller
	0xa2d3, # BlueField integrated ConnectX-5 network controller VF
	0xa2d6, # BlueField-2 integrated ConnectX-6 Dx network controller
	0xa2dc, # BlueField-3 integrated ConnectX-7 network controller
}

DCI_TEST_GOOD_FLOW = 0
DCI_TEST_BAD_FLOW_WITH_RESET = 1
DCI_TEST_BAD_FLOW_WITHOUT_RESET = 2


def is_mlx5_dev(ctx):
    dev_attrs = ctx.query_device()
    return dev_attrs.vendor_id == MELLANOX_VENDOR_ID and \
        dev_attrs.vendor_part_id in MLX5_DEVS


def skip_if_not_mlx5_dev(ctx):
    if not is_mlx5_dev(ctx):
        raise unittest.SkipTest('Can not run the test over non MLX5 device')


class Mlx5PyverbsAPITestCase(PyverbsAPITestCase):
    def setUp(self):
        super().setUp()
        skip_if_not_mlx5_dev(self.ctx)


class Mlx5RDMATestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        skip_if_not_mlx5_dev(d.Context(name=self.dev_name))


class Mlx5RDMACMBaseTest(RDMACMBaseTest):
    def setUp(self):
        super().setUp()
        skip_if_not_mlx5_dev(d.Context(name=self.dev_name))


class Mlx5DcResources(TrafficResources):
    def __init__(self, dev_name, ib_port, gid_index, send_ops_flags,
                 qp_count=1, create_flags=0):
        self.send_ops_flags = send_ops_flags
        self.create_flags = create_flags
        super().__init__(dev_name, ib_port, gid_index, with_srq=True,
                         qp_count=qp_count)

    def to_rts(self):
        attr = self.create_qp_attr()
        for i in range(self.qp_count):
            self.qps[i].to_rts(attr)
        self.dct_qp.to_rtr(attr)

    def pre_run(self, rpsns, rqps_num):
        self.rpsns = rpsns
        self.rqps_num = rqps_num
        self.to_rts()

    def create_context(self):
        mlx5dv_attr = Mlx5DVContextAttr()
        try:
            self.ctx = Mlx5Context(mlx5dv_attr, name=self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 context is not supported')

    def create_mr(self):
        access = e.IBV_ACCESS_REMOTE_WRITE | e.IBV_ACCESS_LOCAL_WRITE
        self.mr = MR(self.pd, self.msg_size, access)

    def create_qp_cap(self):
        return QPCap(100, 0, 1, 0)

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        set_rnr_attributes(qp_attr)
        qp_access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        qp_attr.qp_access_flags = qp_access
        gr = GlobalRoute(dgid=self.ctx.query_gid(self.ib_port, self.gid_index),
                         sgid_index=self.gid_index)
        ah_attr = AHAttr(port_num=self.ib_port, is_global=1, gr=gr,
                         dlid=self.port_attr.lid)
        qp_attr.ah_attr = ah_attr
        return qp_attr

    def create_qp_init_attr(self, send_ops_flags=0):
        comp_mask = e.IBV_QP_INIT_ATTR_PD
        if send_ops_flags:
            comp_mask |= e.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
        return QPInitAttrEx(cap=self.create_qp_cap(), pd=self.pd, scq=self.cq,
                            rcq=self.cq, srq=self.srq, qp_type=e.IBV_QPT_DRIVER,
                            send_ops_flags=send_ops_flags, comp_mask=comp_mask,
                            sq_sig_all=1)

    def create_qps(self):
        # Create the DCI QPs.
        qp_init_attr = self.create_qp_init_attr(self.send_ops_flags)
        try:
            for _ in range(self.qp_count):
                comp_mask = dve.MLX5DV_QP_INIT_ATTR_MASK_DC
                if self.create_flags:
                    comp_mask |= dve.MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS
                attr = Mlx5DVQPInitAttr(comp_mask=comp_mask,
                                        create_flags=self.create_flags,
                                        dc_init_attr=Mlx5DVDCInitAttr())
                qp = Mlx5QP(self.ctx, qp_init_attr, attr)
                self.qps.append(qp)
                self.qps_num.append(qp.qp_num)
                self.psns.append(random.getrandbits(24))

            # Create the DCT QP.
            qp_init_attr = self.create_qp_init_attr()
            dc_attr = Mlx5DVDCInitAttr(dc_type=dve.MLX5DV_DCTYPE_DCT,
                                       dct_access_key=DCT_KEY)
            attr = Mlx5DVQPInitAttr(comp_mask=dve.MLX5DV_QP_INIT_ATTR_MASK_DC,
                                    dc_init_attr=dc_attr)
            self.dct_qp = Mlx5QP(self.ctx, qp_init_attr, attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest(f'Create DC QP is not supported')
            raise ex


class Mlx5DcStreamsRes(Mlx5DcResources):
    def __init__(self, dev_name, ib_port, gid_index, send_ops_flags,
                 qp_count=1, create_flags=0):
        self.bad_flow = 0
        self.mr_bad_flow = False
        self.stream_check = False
        super().__init__(dev_name, ib_port, gid_index, send_ops_flags,
                         qp_count, create_flags)

    def reset_qp(self, qp_idx):
        qp_attr = QPAttr(qp_state=e.IBV_QPS_RESET)
        self.qps[qp_idx].modify(qp_attr, e.IBV_QP_STATE)
        self.qps[qp_idx].to_rts(qp_attr)
        err_mask = self.qp_stream_errors[qp_idx][0]
        index = 0
        # Clear all set dci
        while err_mask != 0:
            if (err_mask & 0x1) == 0x1:
                Mlx5QP.modify_dci_stream_channel_id(self.qps[qp_idx], index)
            index += 1
            err_mask >>= 1
        self.qp_stream_errors[qp_idx][0] = 0

    def get_stream_id(self, qp_idx):
        return self.current_qp_stream_id[qp_idx]

    def generate_stream_id(self, qp_idx):
        self.current_qp_stream_id[qp_idx] += 1
        # Reset stream id to check double-usage
        if self.current_qp_stream_id[qp_idx] > self.dcis[qp_idx]['stream']+2:
            self.current_qp_stream_id[qp_idx] = 1
        return self.current_qp_stream_id[qp_idx]

    def dci_reset_stream_id(self, qp_idx):
        stream_id = self.get_stream_id(qp_idx)
        Mlx5QP.modify_dci_stream_channel_id(self.qps[qp_idx], stream_id)
        # Check once if error raised when reset wrong stream id
        if self.stream_check:
            try:
                Mlx5QP.modify_dci_stream_channel_id(self.qps[qp_idx],
                                                    stream_id+1)
            except PyverbsRDMAError as ex:
                self.stream_check = False

    def bad_flow_handler_qp(self, qp_idx, ex, reset=False):
        str_id = self.get_stream_id(qp_idx)
        bt_stream = (1 << str_id)
        if isinstance(ex, PyverbsRDMAError):
            if ex.error_code == e.IBV_WC_LOC_PROT_ERR:
                self.qp_stream_errors[qp_idx][1] += 1
                if (self.qp_stream_errors[qp_idx][0] & bt_stream) != 0:
                    raise PyverbsError(f'Dublicate error from stream id {str_id}')
                self.qp_stream_errors[qp_idx][0] |= bt_stream
            if ex.error_code == e.IBV_WC_WR_FLUSH_ERR:
                qp_attr, _ = self.qps[qp_idx].query(e.IBV_QP_STATE)
                if qp_attr.cur_qp_state == e.IBV_QPS_ERR and reset:
                    if self.qp_stream_errors[qp_idx][1] != self.dcis[qp_idx]['errored']:
                        msg = f'QP {qp_idx} in ERR state with wrong number of counter'
                        raise PyverbsError(msg)
                    self.reset_qp(qp_idx)
                    self.qp_stream_errors[qp_idx][2] = True
                if qp_attr.cur_qp_state == e.IBV_QPS_RTS:
                    if (self.qp_stream_errors[qp_idx][0] & bt_stream) == 0:
                        msg = f'WQE flushed for wrong stream id {str_id}'
                        raise PyverbsError(msg)
        return True

    def bad_flow_handling(self, qp_idx, ex, reset=False):
        if self.bad_flow == DCI_TEST_GOOD_FLOW:
            return False
        if self.bad_flow == DCI_TEST_BAD_FLOW_WITH_RESET:
            self.qp_stream_errors[qp_idx][1] += 1
            if reset:
                self.dci_reset_stream_id(qp_idx)
            return True
        if self.bad_flow == DCI_TEST_BAD_FLOW_WITHOUT_RESET:
            return self.bad_flow_handler_qp(qp_idx, ex, reset)
        return False

    def set_bad_flow(self, bad_flow):
        self.bad_flow = bad_flow
        if self.bad_flow:
            self.pd_bad = PD(self.ctx)
            self.mr_bad_flow = False
        if bad_flow == DCI_TEST_BAD_FLOW_WITH_RESET:
            self.stream_check = True

    def is_bad_flow(self, qp_idx):
        cnt = self.get_stream_id(qp_idx)
        if self.bad_flow == DCI_TEST_GOOD_FLOW:
            return False
        if self.bad_flow == DCI_TEST_BAD_FLOW_WITH_RESET:
            if (cnt % 3) != 0:
                return False
            self.qp_stream_errors[qp_idx][0] += 1
        if self.bad_flow == DCI_TEST_BAD_FLOW_WITHOUT_RESET:
            if self.qp_stream_errors[qp_idx][2]:
                return False
        return True

    def check_bad_flow(self, qp_idx):
        change_mr = False
        if self.is_bad_flow(qp_idx):
            if not self.mr_bad_flow:
                self.mr_bad_flow = True
                pd = self.pd_bad
                change_mr = True
        else:
            if self.mr_bad_flow:
                self.mr_bad_flow = False
                pd = self.pd
                change_mr = True
        if change_mr:
            self.mr.rereg(flags=e.IBV_REREG_MR_CHANGE_PD, pd=pd,
                          addr=0, length=0, access=0)

    def check_after_traffic(self):
        if self.bad_flow == DCI_TEST_BAD_FLOW_WITH_RESET:
            for errs in self.qp_stream_errors:
                if errs[0] != errs[1]:
                    msg = f'Number of qp_stream_errors {errs[0]} not same '\
                          f'as number of catches {errs[1]}'
                    raise PyverbsError(msg)
            if self.stream_check:
                msg = 'Reset of good stream id does not create exception'
                raise PyverbsError(msg)

    def generate_dci_attr(self, qpn):
        # This array contains current number of log_dci_streams
        # and log_dci_errored values per qp. For 1-st qp number
        # of streams greater than number of errored and vice-versa
        # for the 2nd qp.
        qp_arr = {0: [3, 2], 1: [2, 3]}
        try:
            dci_caps = self.ctx.query_mlx5_device().dci_streams_caps
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Get DCI caps is not supported')
            raise ex
        if not dci_caps or dci_caps['max_log_num_concurent'] == 0:
            raise unittest.SkipTest('DCI caps is not supported by HW')
        self.log_dci_streams = min(qp_arr.get(qpn, [1,1])[0],
                                   dci_caps['max_log_num_concurent'])
        self.log_dci_errored = min(qp_arr.get(qpn, [1,1])[1],
                                   dci_caps['max_log_num_errored'])

    def create_qps(self):
        # Create the DCI QPs.
        qp_init_attr = self.create_qp_init_attr(self.send_ops_flags)
        self.dcis = {}
        # This array contains current stream id
        self.current_qp_stream_id = {}
        # This array counts different errors in bad_flow
        self.qp_stream_errors = []
        comp_mask = dve.MLX5DV_QP_INIT_ATTR_MASK_DC | \
                    dve.MLX5DV_QP_INIT_ATTR_MASK_DCI_STREAMS
        try:
            for qpn in range(self.qp_count):
                if self.create_flags:
                    comp_mask |= dve.MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS
                self.generate_dci_attr(qpn)
                stream_ctx = Mlx5DCIStreamInitAttr(self.log_dci_streams,
                                                   self.log_dci_errored)
                self.dcis[qpn] = {'stream': 1 << self.log_dci_streams,
                                  'errored': 1 << self.log_dci_errored}
                attr = Mlx5DVQPInitAttr(comp_mask=comp_mask,
                                        create_flags=self.create_flags,
                                        dc_init_attr=Mlx5DVDCInitAttr(dci_streams=stream_ctx))
                qp = Mlx5QP(self.ctx, qp_init_attr, attr)
                self.qps.append(qp)
                # Different values for start point of stream id per qp
                self.current_qp_stream_id[qpn] = qpn
                # Array of errors for bad_flow
                # For DCI_TEST_BAD_FLOW_WITH_RESET
                #  First element - number of injected bad flows
                #  Second element - number of exceptions from bad flows
                # For DCI_TEST_BAD_FLOW_WITHOUT_RESET
                #  First element - bitmap of bad flow streams
                #  Second element - number of exceptions from bad flows
                #  Third element - flag if reset of qp been executed
                self.qp_stream_errors.append([0, 0, False])
                self.qps_num.append(qp.qp_num)
                self.psns.append(random.getrandbits(24))
            # Create the DCT QP.
            qp_init_attr = self.create_qp_init_attr()
            dc_attr = Mlx5DVDCInitAttr(dc_type=dve.MLX5DV_DCTYPE_DCT,
                                       dct_access_key=DCT_KEY)
            attr = Mlx5DVQPInitAttr(comp_mask=dve.MLX5DV_QP_INIT_ATTR_MASK_DC,
                                    dc_init_attr=dc_attr)
            self.dct_qp = Mlx5QP(self.ctx, qp_init_attr, attr)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Create DC QP is not supported')
            raise ex

    @staticmethod
    def traffic_with_bad_flow(client, server, iters, gid_idx, port):
        """
        Runs basic traffic with bad flow between two sides
        :param client: client side, clients base class is BaseTraffic
        :param server: server side, servers base class is BaseTraffic
        :param iters: number of traffic iterations
        :param gid_idx: local gid index
        :param port: IB port
        :return: None
        """
        import tests.utils as u
        send_op = e.IBV_QP_EX_WITH_SEND
        ah_client = u.get_global_ah(client, gid_idx, port)
        s_recv_wr = u.get_recv_wr(server)
        c_recv_wr = u.get_recv_wr(client)
        for qp_idx in range(server.qp_count):
            # Prepare the receive queue with RecvWR
            u.post_recv(client, c_recv_wr, qp_idx=qp_idx)
            u.post_recv(server, s_recv_wr, qp_idx=qp_idx)
        read_offset = 0
        for _ in range(iters):
            for qp_idx in range(server.qp_count):
                _, c_send_object = u.get_send_elements(client, False)
                u.send(client, c_send_object, send_op, True, qp_idx,
                       ah_client, False)
                try:
                    u.poll_cq(client.cq)
                except PyverbsError as ex:
                    if client.bad_flow_handling(qp_idx, ex, True):
                        continue
                    raise ex
                u.poll_cq(server.cq)
                u.post_recv(server, s_recv_wr, qp_idx=qp_idx)
                msg_received = server.mr.read(server.msg_size, read_offset)
                u.validate(msg_received, True, server.msg_size)
        client.check_after_traffic()
