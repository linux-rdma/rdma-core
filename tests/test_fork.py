# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2021 Amazon.com, Inc. or its affiliates. All rights reserved.

import errno
import pyverbs.enums as e
from pyverbs.fork import fork_init, is_fork_initialized
from pyverbs.pyverbs_error import PyverbsRDMAError

from tests.base import PyverbsAPITestCase


class ForkAPITest(PyverbsAPITestCase):
    """
    Test the API of the fork functions.
    """

    def test_is_fork_initialized(self):
        try:
            fork_init()
            expected_ret = [e.IBV_FORK_ENABLED, e.IBV_FORK_UNNEEDED]
        except PyverbsRDMAError as ex:
            # Depends on the order of the tests EINVAL could be returned if
            # fork_init() is called after an MR has already been registered.
            self.assertEqual(ex.error_code, errno.EINVAL)
            expected_ret = [e.IBV_FORK_DISABLED, e.IBV_FORK_UNNEEDED]

        ret = is_fork_initialized()
        if self.config['verbosity']:
            print(f'is_fork_initialized() = {ret}')
        self.assertIn(ret, expected_ret)
