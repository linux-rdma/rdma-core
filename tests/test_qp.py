# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for pyverbs' qp module.
"""
import unittest
import random
import errno
import os

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.qp import QPInitAttr, QPAttr, QP
from tests.base import PyverbsAPITestCase
import pyverbs.enums as e
from pyverbs.pd import PD
from pyverbs.cq import CQ
import tests.utils as u


class QPTest(PyverbsAPITestCase):
    """
    Test various functionalities of the QP class.
    """

    def test_create_qp_no_attr_connected(self):
        """
        Test QP creation via ibv_create_qp without a QPAttr object proivded.
        Checked QP types are RC and UC.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    qia = get_qp_init_attr(cq, attr)
                    qia.qp_type = e.IBV_QPT_RC
                    with QP(pd, qia) as qp:
                        assert qp.qp_state == e.IBV_QPS_RESET, 'RC QP should have been in RESET'
                    qia.qp_type = e.IBV_QPT_UC
                    with QP(pd, qia) as qp:
                        assert qp.qp_state == e.IBV_QPS_RESET, 'UC QP should have been in RESET'


    def test_create_qp_no_attr(self):
        """
        Test QP creation via ibv_create_qp without a QPAttr object proivded.
        Checked QP types are Raw Packet and UD. Raw Packet is skipped for
        non-root users / Infiniband link layer.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    for i in range(1, attr.phys_port_cnt + 1):
                        qia = get_qp_init_attr(cq, attr)
                        qia.qp_type = e.IBV_QPT_UD
                        with QP(pd, qia) as qp:
                            assert qp.qp_state == e.IBV_QPS_RESET, 'UD QP should have been in RESET'
                        if is_eth(ctx, i) and is_root():
                            qia.qp_type = e.IBV_QPT_RAW_PACKET
                            with QP(pd, qia) as qp:
                                assert qp.qp_state == e.IBV_QPS_RESET, 'Raw Packet QP should have been in RESET'

    def test_create_qp_with_attr_connected(self):
        """
        Test QP creation via ibv_create_qp without a QPAttr object proivded.
        Checked QP types are RC and UC.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    qia = get_qp_init_attr(cq, attr)
                    qia.qp_type = e.IBV_QPT_RC
                    with QP(pd, qia, QPAttr()) as qp:
                        assert qp.qp_state == e.IBV_QPS_INIT, 'RC QP should have been in INIT'
                    qia.qp_type = e.IBV_QPT_UC
                    with QP(pd, qia, QPAttr()) as qp:
                        assert qp.qp_state == e.IBV_QPS_INIT, 'UC QP should have been in INIT'

    def test_create_qp_with_attr(self):
        """
        Test QP creation via ibv_create_qp with a QPAttr object proivded.
        Checked QP types are Raw Packet and UD. Raw Packet is skipped for
        non-root users / Infiniband link layer.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    for i in range(1, attr.phys_port_cnt + 1):
                        qpts = [e.IBV_QPT_UD, e.IBV_QPT_RAW_PACKET] \
                            if is_eth(ctx, i) else [e.IBV_QPT_UD]
                        qia = get_qp_init_attr(cq, attr)
                        qia.qp_type = e.IBV_QPT_UD
                        with QP(pd, qia, QPAttr()) as qp:
                            assert qp.qp_state == e.IBV_QPS_RTS, 'UD QP should have been in RTS'
                        if is_eth(ctx, i) and is_root():
                            qia.qp_type = e.IBV_QPT_RAW_PACKET
                            with QP(pd, qia, QPAttr()) as qp:
                                assert qp.qp_state == e.IBV_QPS_RTS, 'Raw Packet QP should have been in RTS'

    def test_create_qp_ex_no_attr_connected(self):
        """
        Test QP creation via ibv_create_qp_ex without a QPAttr object proivded.
        Checked QP types are RC and UC.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    qia = get_qp_init_attr_ex(cq, pd, attr, attr_ex, e.IBV_QPT_RC)
                    try:
                        with QP(ctx, qia) as qp:
                            assert qp.qp_state == e.IBV_QPS_RESET, 'RC QP should have been in RESET'
                    except PyverbsRDMAError as ex:
                        if ex.error_code == errno.EOPNOTSUPP:
                            raise unittest.SkipTest('Create QP with extended attrs is not supported')
                        raise ex
                    qia = get_qp_init_attr_ex(cq, pd, attr, attr_ex, e.IBV_QPT_UC)
                    try:
                        with QP(ctx, qia) as qp:
                            assert qp.qp_state == e.IBV_QPS_RESET, 'UC QP should have been in RESET'
                    except PyverbsRDMAError as ex:
                        if ex.error_code == errno.EOPNOTSUPP:
                            raise unittest.SkipTest('Create QP with extended attrs is not supported')
                        raise ex

    def test_create_qp_ex_no_attr(self):
        """
        Test QP creation via ibv_create_qp_ex without a QPAttr object proivded.
        Checked QP types are Raw Packet and UD. Raw Packet is skipped for
        non-root users / Infiniband link layer.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    for i in range(1, attr.phys_port_cnt + 1):
                        qia = get_qp_init_attr_ex(cq, pd, attr, attr_ex,
                                                  e.IBV_QPT_UD)
                        try:
                            with QP(ctx, qia) as qp:
                                assert qp.qp_state == e.IBV_QPS_RESET, 'UD QP should have been in RESET'
                        except PyverbsRDMAError as ex:
                            if ex.error_code == errno.EOPNOTSUPP:
                                raise unittest.SkipTest('Create QP with extended attrs is not supported')
                            raise ex
                        if is_eth(ctx, i) and is_root():
                            qia = get_qp_init_attr_ex(cq, pd, attr, attr_ex,
                                                      e.IBV_QPT_RAW_PACKET)
                            try:
                                with QP(ctx, qia) as qp:
                                    assert qp.qp_state == e.IBV_QPS_RESET, 'Raw Packet QP should have been in RESET'
                            except PyverbsRDMAError as ex:
                                if ex.error_code == errno.EOPNOTSUPP:
                                    raise unittest.SkipTest('Create QP with extended attrs is not supported')
                                raise ex

    def test_create_qp_ex_with_attr_connected(self):
        """
        Test QP creation via ibv_create_qp_ex with a QPAttr object proivded.
        Checked QP type are RC and UC.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    qia = get_qp_init_attr_ex(cq, pd, attr, attr_ex,
                                              e.IBV_QPT_RC)
                    try:
                        with QP(ctx, qia, QPAttr()) as qp:
                            assert qp.qp_state == e.IBV_QPS_INIT, 'RC QP should have been in INIT'
                    except PyverbsRDMAError as ex:
                        if ex.error_code == errno.EOPNOTSUPP:
                            raise unittest.SkipTest('Create QP with extended attrs is not supported')
                        raise ex
                    qia = get_qp_init_attr_ex(cq, pd, attr, attr_ex,
                                              e.IBV_QPT_UC)
                    try:
                        with QP(ctx, qia, QPAttr()) as qp:
                            assert qp.qp_state == e.IBV_QPS_INIT, 'UC QP should have been in INIT'
                    except PyverbsRDMAError as ex:
                        if ex.error_code == errno.EOPNOTSUPP:
                            raise unittest.SkipTest('Create QP with extended attrs is not supported')
                        raise ex

    def test_create_qp_ex_with_attr(self):
        """
        Test QP creation via ibv_create_qp_ex with a QPAttr object proivded.
        Checked QP types are Raw Packet and UD. Raw Packet is skipped for
        non-root users / Infiniband link layer.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    for i in range(1, attr.phys_port_cnt + 1):
                        qia = get_qp_init_attr_ex(cq, pd, attr, attr_ex,
                                                  e.IBV_QPT_UD)
                        try:
                            with QP(ctx, qia, QPAttr()) as qp:
                                assert qp.qp_state == e.IBV_QPS_RTS, 'UD QP should have been in RTS'
                        except PyverbsRDMAError as ex:
                            if ex.error_code == errno.EOPNOTSUPP:
                                raise unittest.SkipTest('Create QP with extended attrs is not supported')
                            raise ex
                        if is_eth(ctx, i) and is_root():
                            qia = get_qp_init_attr_ex(cq, pd, attr, attr_ex,
                                                      e.IBV_QPT_RAW_PACKET)
                            try:
                                with QP(ctx, qia, QPAttr()) as qp:
                                    assert qp.qp_state == e.IBV_QPS_RTS, 'Raw Packet QP should have been in RTS'
                            except PyverbsRDMAError as ex:
                                if ex.error_code == errno.EOPNOTSUPP:
                                    raise unittest.SkipTest('Create QP with extended attrs is not supported')
                                raise ex

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
                        for qpt in qpts:
                            # Extended QP
                            qia = get_qp_init_attr_ex(cq, pd, attr, attr_ex,
                                                      qpt)
                            caps = qia.cap  # Save them to verify values later
                            try:
                                qp = QP(ctx, qia)
                            except PyverbsRDMAError as ex:
                                if ex.error_code == errno.EOPNOTSUPP:
                                    raise unittest.SkipTest('Create QP with extended attrs is not supported')
                                raise ex
                            qp_attr, qp_init_attr = qp.query(e.IBV_QP_CUR_STATE |
                                                             e.IBV_QP_CAP)
                            verify_qp_attrs(caps, e.IBV_QPS_RESET, qp_init_attr,
                                            qp_attr)
                            # Legacy QP
                            qia = get_qp_init_attr(cq, attr)
                            qia.qp_type = qpt
                            caps = qia.cap  # Save them to verify values later
                            qp = QP(pd, qia)
                            qp_attr, qp_init_attr = qp.query(e.IBV_QP_CUR_STATE |
                                                             e.IBV_QP_CAP)
                            verify_qp_attrs(caps, e.IBV_QPS_RESET, qp_init_attr,
                                            qp_attr)

    def test_modify_qp(self):
        """
        Queries a QP after calling modify(). Verifies that its properties are
        as expected.
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                with CQ(ctx, 100, None, None, 0) as cq:
                    # Extended QP
                    qia = get_qp_init_attr_ex(cq, pd, attr, attr_ex, e.IBV_QPT_UD)
                    try:
                        qp = QP(ctx, qia)
                    except PyverbsRDMAError as ex:
                        if ex.error_code == errno.EOPNOTSUPP:
                            raise unittest.SkipTest('Create QP with extended attrs is not supported')
                        raise ex
                    qa = QPAttr()
                    qa.qkey = 0x123
                    qp.to_init(qa)
                    qp_attr, qp_iattr = qp.query(e.IBV_QP_QKEY)
                    assert qp_attr.qkey == qa.qkey, 'Extended QP, QKey is not as expected'
                    qp.to_rtr(qa)
                    qa.sq_psn = 0x45
                    qp.to_rts(qa)
                    qp_attr, qp_iattr = qp.query(e.IBV_QP_SQ_PSN)
                    assert qp_attr.sq_psn == qa.sq_psn, 'Extended QP, SQ PSN is not as expected'
                    qa.qp_state = e.IBV_QPS_RESET
                    qp.modify(qa, e.IBV_QP_STATE)
                    assert qp.qp_state == e.IBV_QPS_RESET, 'Extended QP, QP state is not as expected'
                    # Legacy QP
                    qia = get_qp_init_attr(cq, attr)
                    qp = QP(pd, qia)
                    qa = QPAttr()
                    qa.qkey = 0x123
                    qp.to_init(qa)
                    qp_attr, qp_iattr = qp.query(e.IBV_QP_QKEY)
                    assert qp_attr.qkey == qa.qkey, 'Legacy QP, QKey is not as expected'
                    qp.to_rtr(qa)
                    qa.sq_psn = 0x45
                    qp.to_rts(qa)
                    qp_attr, qp_iattr = qp.query(e.IBV_QP_SQ_PSN)
                    assert qp_attr.sq_psn == qa.sq_psn, 'Legacy QP, SQ PSN is not as expected'
                    qa.qp_state = e.IBV_QPS_RESET
                    qp.modify(qa, e.IBV_QP_STATE)
                    assert qp.qp_state == e.IBV_QPS_RESET, 'Legacy QP, QP state is not as expected'


def get_qp_types(ctx, port_num):
    """
    Returns a list of the commonly used QP types. Raw Packet QP will not be
    included if link layer is not Ethernet or it current user is not root.
    :param ctx: The device's Context, to query the port's link layer
    :param port_num: Port number to query
    :return: An array of QP types that can be created on this port
    """
    qpts = [e.IBV_QPT_RC, e.IBV_QPT_UC, e.IBV_QPT_UD]
    if is_eth(ctx, port_num) and is_root():
        qpts.append(e.IBV_QPT_RAW_PACKET)
    return qpts


def verify_qp_attrs(orig_cap, state, init_attr, attr):
    assert state == attr.cur_qp_state
    assert orig_cap.max_send_wr <= init_attr.cap.max_send_wr
    assert orig_cap.max_recv_wr <= init_attr.cap.max_recv_wr
    assert orig_cap.max_send_sge <= init_attr.cap.max_send_sge
    assert orig_cap.max_recv_sge <= init_attr.cap.max_recv_sge
    assert orig_cap.max_inline_data <= init_attr.cap.max_inline_data


def get_qp_init_attr(cq, attr):
    """
    Creates a QPInitAttr object with a QP type of the provided <qpts> array and
    other random values.
    :param cq: CQ to be used as send and receive CQ
    :param attr: Device attributes for capability checks
    :return: An initialized QPInitAttr object
    """
    qp_cap = u.random_qp_cap(attr)
    sig = random.randint(0, 1)
    return QPInitAttr(scq=cq, rcq=cq, cap=qp_cap, sq_sig_all=sig)


def get_qp_init_attr_ex(cq, pd, attr, attr_ex, qpt):
    """
    Creates a QPInitAttrEx object with a QP type of the provided <qpts> array
    and other random values.
    :param cq: CQ to be used as send and receive CQ
    :param pd: A PD object to use
    :param attr: Device attributes for capability checks
    :param attr_ex: Extended device attributes for capability checks
    :param qpt: QP type
    :return: An initialized QPInitAttrEx object
    """
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


def is_root():
    return os.geteuid() == 0
