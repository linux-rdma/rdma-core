# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.
"""
Test module for efa direct-verbs.
"""

import errno
from pyverbs.base import PyverbsRDMAError
import pyverbs.providers.efa.efadv as efa
from tests.base import PyverbsAPITestCase
import unittest


class EfaDvTest(PyverbsAPITestCase):
    """
    Test various functionalities of the direct verbs class.
    """
    def test_efadv_query(self):
        """
        Verify that it's possible to read EFA direct-verbs.
        """
        for ctx, attr, attr_ex in self.devices:
            with efa.EfaContext(name=ctx.name) as efa_ctx:
                try:
                    efa_attrs = efa_ctx.query_efa_device()
                    if self.config['verbosity']:
                        print(f'\n{efa_attrs}')
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Not supported on non EFA devices')
                    raise ex
