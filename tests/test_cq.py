# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for pyverbs' cq module.

"""
import errno

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.base import PyverbsRDMAErrno
from tests.base import PyverbsAPITestCase
from pyverbs.cq import CompChannel, CQ


class CQAPITest(PyverbsAPITestCase):
    """
    Test the API of the CQ class.
    """
    def setUp(self):
        super().setUp()
        self.ctx, attr, _ = self.devices[0]
        self.max_cqe = attr.max_cqe

    def test_create_cq(self):
        for cq_size in [1, self.max_cqe/2, self.max_cqe]:
            for comp_vector in [0, 1]:
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
        for cq_size in [1, self.max_cqe/2, self.max_cqe]:
            cc = CompChannel(self.ctx)
            CQ(self.ctx, cq_size, None, cc, 0)
            cc.close()

    def test_create_cq_bad_flow(self):
        """
        Test ibv_create_cq() with wrong comp_vector / number of cqes
        """
        with self.assertRaises(PyverbsRDMAError) as ex:
            CQ(self.ctx, self.max_cqe + 1, None, None, 0)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

        with self.assertRaises(PyverbsRDMAError) as ex:
            CQ(self.ctx, 100, None, None, self.ctx.num_comp_vectors + 1)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)
