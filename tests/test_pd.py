# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for pyverbs' pd module.
"""
import random

from tests.base import PyverbsAPITestCase
from pyverbs.pd import PD


class PDTest(PyverbsAPITestCase):
    """
    Test various functionalities of the PD class.
    """
    def test_alloc_pd(self):
        """
        Test ibv_alloc_pd()
        """
        with PD(self.ctx):
            pass

    def test_dealloc_pd(self):
        """
        Test ibv_dealloc_pd()
        """
        with PD(self.ctx) as pd:
            pd.close()

    def test_multiple_pd_creation(self):
        """
        Test multiple creations and destructions of a PD object
        """
        for i in range(random.randint(1, 200)):
            with PD(self.ctx) as pd:
                pd.close()

    def test_destroy_pd_twice(self):
        """
        Test bad flow cases in destruction of a PD object
        """
        with PD(self.ctx) as pd:
            # Pyverbs supports multiple destruction of objects, we are
            # not expecting an exception here.
            pd.close()
            pd.close()
