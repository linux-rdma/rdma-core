# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 NVIDIA Corporation . All rights reserved. See COPYING file

import unittest
import random
import errno

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, \
    Mlx5DVQPInitAttr, Mlx5QP, Mlx5DVDCInitAttr
from tests.base import TrafficResources, set_rnr_attributes, DCT_KEY, \
    RDMATestCase, PyverbsAPITestCase, RDMACMBaseTest
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
from pyverbs.qp import QPCap, QPInitAttrEx, QPAttr
import pyverbs.providers.mlx5.mlx5_enums as dve
from pyverbs.addr import AHAttr, GlobalRoute
import pyverbs.device as d
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
