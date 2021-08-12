# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 HiSilicon Limited. All rights reserved.

import unittest
import errno

from pyverbs.pyverbs_error import PyverbsRDMAError
import pyverbs.enums as e

from tests.hns_base import HnsRDMATestCase
from tests.hns_base import HnsDcaResources
import tests.utils as u



class QPDCATestCase(HnsRDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 100
        self.server = None
        self.client = None

    def create_players(self, qp_count=8):
        try:
            self.client = HnsDcaResources(self.dev_name, self.ib_port, self.gid_index, qp_count)
            self.server = HnsDcaResources(self.dev_name, self.ib_port, self.gid_index, qp_count)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create DCA Resources is not supported')
            raise ex
        self.client.pre_run(self.server.psns, self.server.qps_num)
        self.server.pre_run(self.client.psns, self.client.qps_num)

    def test_qp_ex_dca_send(self):
        self.create_players()
        u.traffic(self.client, self.server, self.iters, self.gid_index, self.ib_port,
                  new_send=False)
