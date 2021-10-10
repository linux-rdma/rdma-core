# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.
"""
Test module for pyverbs' cq module.

"""
import unittest
import errno

from tests.base import PyverbsAPITestCase, RDMATestCase, UDResources
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.cq import CompChannel, CQ
from pyverbs.qp import QPCap
import tests.utils as u


class CQUDResources(UDResources):
    def __init__(self, dev_name, ib_port, gid_index, cq_depth=None):
        self.cq_depth = cq_depth
        super().__init__(dev_name, ib_port, gid_index)

    def create_cq(self):
        """
        Initializes self.cq with a CQ of depth <num_msgs> - defined by each
        test.
        :return: None
        """
        cq_depth = self.cq_depth if self.cq_depth is not None else self.num_msgs
        self.cq = CQ(self.ctx, cq_depth, None, None, 0)

    def create_qp_cap(self):
        return QPCap(max_recv_wr=self.num_msgs, max_send_wr=10)


class CQAPITest(PyverbsAPITestCase):
    """
    Test the API of the CQ class.
    """
    def setUp(self):
        super().setUp()

    def test_create_cq(self):
        for cq_size in [1, self.attr.max_cqe/2, self.attr.max_cqe]:
            for comp_vector in range(0, min(2, self.ctx.num_comp_vectors)):
                try:
                    cq = CQ(self.ctx, cq_size, None, None, comp_vector)
                    cq.close()
                except PyverbsRDMAError as ex:
                    cq_attr = f'cq_size={cq_size}, comp_vector={comp_vector}'
                    raise PyverbsRDMAErrno(f'Failed to create a CQ with {cq_attr}')

        # Create CQ with Max value of comp_vector.
        max_cqs_comp_vector = self.ctx.num_comp_vectors - 1
        cq = CQ(self.ctx, self.ctx.num_comp_vectors, None, None, max_cqs_comp_vector)


    def test_create_cq_with_comp_channel(self):
        for cq_size in [1, self.attr.max_cqe/2, self.attr.max_cqe]:
            try:
                cc = CompChannel(self.ctx)
                CQ(self.ctx, cq_size, None, cc, 0)
                cc.close()
            except PyverbsRDMAError as ex:
                if ex.error_code == errno.EOPNOTSUPP:
                    raise unittest.SkipTest(f'CQ with completion channel is not supported')

    def test_create_cq_bad_flow(self):
        """
        Test ibv_create_cq() with wrong comp_vector / number of cqes
        """
        with self.assertRaises(PyverbsRDMAError) as ex:
            CQ(self.ctx, self.attr.max_cqe + 1, None, None, 0)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

        with self.assertRaises(PyverbsRDMAError) as ex:
            CQ(self.ctx, 100, None, None, self.ctx.num_comp_vectors + 1)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)


class CQTest(RDMATestCase):
    """
    Test various functionalities of the CQ class.
    """
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

    def create_players(self, resource, **resource_arg):
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)
        self.traffic_args = {'client': self.client, 'server': self.server,
                             'iters': self.iters, 'gid_idx': self.gid_index,
                             'port': self.ib_port}

    def test_resize_cq(self):
        """
        Test resize CQ, start with specific value and then increase and decrease
        the CQ size. The test also check bad flow of decrease the CQ size when
        there are more completions on it than the new value.
        """
        self.create_players(CQUDResources, cq_depth=3)
        # Decrease the CQ size.
        new_cq_size = 1
        try:
            self.client.cq.resize(new_cq_size)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Resize CQ is not supported')
            raise ex
        self.assertTrue(self.client.cq.cqe >= new_cq_size,
                        f'The actual CQ size ({self.client.cq.cqe}) is less '
                        'than guaranteed ({new_cq_size})')

        # Increase the CQ size.
        new_cq_size = 7
        self.client.cq.resize(new_cq_size)
        self.assertTrue(self.client.cq.cqe >= new_cq_size,
                        f'The actual CQ size ({self.client.cq.cqe}) is less '
                        'than guaranteed ({new_cq_size})')

        # Fill the CQ entries except one for avoid cq_overrun warnings.
        send_wr, _ = u.get_send_elements(self.client, False)
        ah_client = u.get_global_ah(self.client, self.gid_index, self.ib_port)
        for i in range(self.client.cq.cqe - 1):
            u.send(self.client, send_wr, ah=ah_client)

        # Decrease the CQ size to less than the CQ unpolled entries.
        new_cq_size = 1
        with self.assertRaises(PyverbsRDMAError) as ex:
            self.client.cq.resize(new_cq_size)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)
