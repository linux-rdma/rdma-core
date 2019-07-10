# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for pyverbs' qp module.
"""
import random

from pyverbs.tests.base import PyverbsTestCase
from pyverbs.qp import QPInitAttr, QPAttr, QP
import pyverbs.tests.utils as u
import pyverbs.enums as e
from pyverbs.pd import PD
from pyverbs.cq import CQ


class QPTest(PyverbsTestCase):
    """
    Test various functionalities of the QP class.
    """

    def test_create_qp_no_attr_connected(self):
        """
        Test QP creation via ibv_create_qp without a QPAttr object proivded.
        QP type can be either RC or UC.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    qia = get_qp_init_attr(cq, [e.IBV_QPT_RC, e.IBV_QPT_UC],
                                           attr)
                    with QP(pd, qia) as qp:
                        assert qp.qp_state == e.IBV_QPS_RESET

    def test_create_qp_no_attr(self):
        """
        Test QP creation via ibv_create_qp without a QPAttr object proivded.
        QP type can be either Raw Packet or UD.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    for i in range(1, attr.phys_port_cnt + 1):
                        qpts = [e.IBV_QPT_UD, e.IBV_QPT_RAW_PACKET] \
                            if is_eth(ctx, i) else [e.IBV_QPT_UD]
                        qia = get_qp_init_attr(cq, qpts, attr)
                        with QP(pd, qia) as qp:
                            assert qp.qp_state == e.IBV_QPS_RESET

    def test_create_qp_with_attr_connected(self):
        """
        Test QP creation via ibv_create_qp without a QPAttr object proivded.
        QP type can be either RC or UC.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    qia = get_qp_init_attr(cq, [e.IBV_QPT_RC, e.IBV_QPT_UC],
                                           attr)
                    with QP(pd, qia, QPAttr()) as qp:
                        assert qp.qp_state == e.IBV_QPS_INIT

    def test_create_qp_with_attr(self):
        """
        Test QP creation via ibv_create_qp with a QPAttr object proivded.
        QP type can be either Raw Packet or UD.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    for i in range(1, attr.phys_port_cnt + 1):
                        qpts = [e.IBV_QPT_UD, e.IBV_QPT_RAW_PACKET] \
                            if is_eth(ctx, i) else [e.IBV_QPT_UD]
                        qia = get_qp_init_attr(cq, qpts, attr)
                        with QP(pd, qia, QPAttr()) as qp:
                            assert qp.qp_state == e.IBV_QPS_RTS

    def test_create_qp_ex_no_attr_connected(self):
        """
        Test QP creation via ibv_create_qp_ex without a QPAttr object proivded.
        QP type can be either RC or UC.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    qia = get_qp_init_attr_ex(cq, pd, [e.IBV_QPT_RC,
                                                       e.IBV_QPT_UC],
                                              attr, attr_ex)
                    with QP(ctx, qia) as qp:
                        assert qp.qp_state == e.IBV_QPS_RESET

    def test_create_qp_ex_no_attr(self):
        """
        Test QP creation via ibv_create_qp_ex without a QPAttr object proivded.
        QP type can be either Raw Packet or UD.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    for i in range(1, attr.phys_port_cnt + 1):
                        qpts = [e.IBV_QPT_UD, e.IBV_QPT_RAW_PACKET] \
                            if is_eth(ctx, i) else [e.IBV_QPT_UD]
                        qia = get_qp_init_attr_ex(cq, pd, qpts, attr,
                                                  attr_ex)
                        with QP(ctx, qia) as qp:
                            assert qp.qp_state == e.IBV_QPS_RESET

    def test_create_qp_ex_with_attr_connected(self):
        """
        Test QP creation via ibv_create_qp_ex with a QPAttr object proivded.
        QP type can be either RC or UC.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    qia = get_qp_init_attr_ex(cq, pd, [e.IBV_QPT_RC,
                                                       e.IBV_QPT_UC],
                                              attr, attr_ex)
                    with QP(ctx, qia, QPAttr()) as qp:
                        assert qp.qp_state == e.IBV_QPS_INIT

    def test_create_qp_ex_with_attr(self):
        """
        Test QP creation via ibv_create_qp_ex with a QPAttr object proivded.
        QP type can be either Raw Packet or UD.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    for i in range(1, attr.phys_port_cnt + 1):
                        qpts = [e.IBV_QPT_UD, e.IBV_QPT_RAW_PACKET] \
                            if is_eth(ctx, i) else [e.IBV_QPT_UD]
                        qia = get_qp_init_attr_ex(cq, pd, qpts, attr,
                                                  attr_ex)
                        with QP(ctx, qia, QPAttr()) as qp:
                            assert qp.qp_state == e.IBV_QPS_RTS

    def test_query_qp(self):
        """
        Queries a QP after creation. Verifies that its properties are as
        expected.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    for i in range(1, attr.phys_port_cnt + 1):
                        qpts = get_qp_types(ctx, i)
                        is_ex = random.choice([True, False])
                        if is_ex:
                            qia = get_qp_init_attr_ex(cq, pd, qpts, attr,
                                                      attr_ex)
                        else:
                            qia = get_qp_init_attr(cq, qpts, attr)
                        caps = qia.cap  # Save them to verify values later
                        qp = QP(ctx, qia) if is_ex else QP(pd, qia)
                        attr, init_attr = qp.query(e.IBV_QP_CUR_STATE |
                                                   e.IBV_QP_CAP)
                        verify_qp_attrs(caps, e.IBV_QPS_RESET, init_attr,
                                        attr)

    def test_modify_qp(self):
        """
        Queries a QP after calling modify(). Verifies that its properties are
        as expected.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    is_ex = random.choice([True, False])
                    if is_ex:
                        qia = get_qp_init_attr_ex(cq, pd, [e.IBV_QPT_UD],
                                                  attr, attr_ex)
                    else:
                        qia = get_qp_init_attr(cq, [e.IBV_QPT_UD], attr)
                    qp = QP(ctx, qia) if is_ex \
                        else QP(pd, qia)
                    qa = QPAttr()
                    qa.qkey = 0x123
                    qp.to_init(qa)
                    attr, iattr = qp.query(e.IBV_QP_QKEY)
                    assert attr.qkey == qa.qkey
                    qp.to_rtr(qa)
                    qa.sq_psn = 0x45
                    qp.to_rts(qa)
                    attr, iattr = qp.query(e.IBV_QP_SQ_PSN)
                    assert attr.sq_psn == qa.sq_psn
                    qa.qp_state = e.IBV_QPS_RESET
                    qp.modify(qa, e.IBV_QP_STATE)
                    assert qp.qp_state == e.IBV_QPS_RESET


def get_qp_types(ctx, port_num):
    """
    Returns a list of the commonly used QP types. Raw Packet QP will not be
    included if link layer is not Ethernet.
    :param ctx: The device's Context, to query the port's link layer
    :param port_num: Port number to query
    :return: An array of QP types that can be created on this port
    """
    qpts = [e.IBV_QPT_RC, e.IBV_QPT_UC, e.IBV_QPT_UD]
    if is_eth(ctx, port_num):
        qpts.append(e.IBV_QPT_RAW_PACKET)
    return qpts


def verify_qp_attrs(orig_cap, state, init_attr, attr):
    assert state == attr.cur_qp_state
    assert orig_cap.max_send_wr <= init_attr.cap.max_send_wr
    assert orig_cap.max_recv_wr <= init_attr.cap.max_recv_wr
    assert orig_cap.max_send_sge <= init_attr.cap.max_send_sge
    assert orig_cap.max_recv_sge <= init_attr.cap.max_recv_sge
    assert orig_cap.max_inline_data <= init_attr.cap.max_inline_data


def get_qp_init_attr(cq, qpts, attr):
    """
    Creates a QPInitAttr object with a QP type of the provided <qpts> array and
    other random values.
    :param cq: CQ to be used as send and receive CQ
    :param qpts: An array of possible QP types to use
    :param attr: Device attributes for capability checks
    :return: An initialized QPInitAttr object
    """
    qp_cap = u.random_qp_cap(attr)
    qpt = random.choice(qpts)
    sig = random.randint(0, 1)
    return QPInitAttr(qp_type=qpt, scq=cq, rcq=cq, cap=qp_cap, sq_sig_all=sig)


def get_qp_init_attr_ex(cq, pd, qpts, attr, attr_ex):
    """
    Creates a QPInitAttrEx object with a QP type of the provided <qpts> array
    and other random values.
    :param cq: CQ to be used as send and receive CQ
    :param pd: A PD object to use
    :param qpts: An array of possible QP types to use
    :param attr: Device attributes for capability checks
    :param attr_ex: Extended device attributes for capability checks
    :return: An initialized QPInitAttrEx object
    """
    qpt = random.choice(qpts)
    qia = u.random_qp_init_attr_ex(attr_ex, attr, qpt)
    qia.send_cq = cq
    qia.recv_cq = cq
    qia.pd = pd  # Only XRCD can be created without a PD
    return qia


def is_eth(ctx, port_num):
    """
    Querires the device's context's <port_num> port for its link layer.
    :param ctx: The Context to query
    :param port_num: Which Context's port to query
    :return: True if the port's link layer is Ethernet, else False
    """
    return ctx.query_port(port_num).link_layer == e.IBV_LINK_LAYER_ETHERNET
