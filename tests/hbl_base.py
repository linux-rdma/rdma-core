# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2022-2024 HabanaLabs, Ltd.
# Copyright (C) 2023-2024, Intel Corporation.
# All Rights Reserved.

import unittest
import os
import re

from pyverbs.providers.hbl.hbldv import HblContext, HblDVContextAttr, \
    HblDVSetPortEx, HblDVPortExAttr
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.base import PyverbsRDMAError
from pyverbs.pyverbs_error import PyverbsUserError
import pyverbs.providers.hbl.hbl_enums as hbl_e
import pyverbs.providers.hbl.hbldv as hbl

from tests.base import PyverbsAPITestCase


HABANALABS_VENDOR_ID = 0x1da3


def is_hbl_dev(ctx):
    dev_attrs = ctx.query_device()
    return dev_attrs.vendor_id == HABANALABS_VENDOR_ID


def skip_if_not_hbl_dev(ctx):
    if not is_hbl_dev(ctx):
        raise unittest.SkipTest('Can not run the test over non hbl device')

def bits(n):
    b=0
    while n:
        if (n & 0x1):
            yield b
        b += 1
        n >>= 1


class HblAPITestCase(PyverbsAPITestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self.fd = None

    def setUp(self):
        super().setUp()
        skip_if_not_hbl_dev(self.ctx)

    def create_context(self):
        try:
            path = None
            for file in os.listdir('/dev/accel/'):
                if re.match('^accel[0-9]+$', file):
                    path = os.path.join('/dev/accel/', file)
                    break

            self.assertNotEqual(path, None, 'No core device found')

            self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
            attr = HblDVContextAttr()
            attr.ports_mask = 0
            attr.core_fd = self.fd
            self.ctx = HblContext(attr, name=self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open hbl context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening hbl context is not supported')

        try:
            # Set ports Ex should be called for all enabled ports
            ib_ports_mask = self.ctx.query_hbl_device().ports_mask
            for ib_port in bits(ib_ports_mask):
                attr = HblDVPortExAttr()
                attr.port_num = ib_port
                attr.mem_id = hbl_e.HBLDV_MEM_HOST
                attr.max_num_of_wqs = 8
                attr.max_num_of_wqes_in_wq = 16
                attr.swq_granularity = hbl_e.HBLDV_SWQE_GRAN_32B
                attr.caps = 1
                port = HblDVSetPortEx()
                port.set_port_ex(self.ctx, attr)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not set port extended params ({ex})')

    def tearDown(self):
        super().tearDown()
        os.close(self.fd)
