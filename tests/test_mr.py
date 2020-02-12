# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for pyverbs' mr module.
"""
from itertools import combinations as com
import unittest
import random
import errno

from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from tests.base import PyverbsAPITestCase
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.mr import MR, MW, DMMR
import pyverbs.device as d
from pyverbs.pd import PD
import pyverbs.enums as e
import tests.utils as u

MAX_IO_LEN = 1048576


class MRTest(PyverbsAPITestCase):
    """
    Test various functionalities of the MR class.
    """
    def test_reg_mr(self):
        """
        Test ibv_reg_mr()
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, u.get_mr_length(), f) as mr:
                        pass

    def test_dereg_mr(self):
        """
        Test ibv_dereg_mr()
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, u.get_mr_length(), f) as mr:
                        mr.close()

    def test_dereg_mr_twice(self):
        """
        Verify that explicit call to MR's close() doesn't fail
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, u.get_mr_length(), f) as mr:
                        # Pyverbs supports multiple destruction of objects,
                        # we are not expecting an exception here.
                        mr.close()
                        mr.close()

    def test_reg_mr_bad_flags(self):
        """
        Verify that illegal flags combination fails as expected
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                for i in range(5):
                    flags = random.sample([e.IBV_ACCESS_REMOTE_WRITE,
                                           e.IBV_ACCESS_REMOTE_ATOMIC],
                                          random.randint(1, 2))
                    mr_flags = 0
                    for i in flags:
                        mr_flags += i.value
                    try:
                        MR(pd, u.get_mr_length(), mr_flags)
                    except PyverbsRDMAError as err:
                        assert 'Failed to register a MR' in err.args[0]
                    else:
                        raise PyverbsRDMAError('Registered a MR with illegal falgs')

    def test_write(self):
        """
        Test writing to MR's buffer
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                for i in range(10):
                    mr_len = u.get_mr_length()
                    flags = u.get_access_flags(ctx)
                    for f in flags:
                        with MR(pd, mr_len, f) as mr:
                            write_len = min(random.randint(1, MAX_IO_LEN),
                                            mr_len)
                            mr.write('a' * write_len, write_len)

    def test_read(self):
        """
        Test reading from MR's buffer
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                for i in range(10):
                    mr_len = u.get_mr_length()
                    flags = u.get_access_flags(ctx)
                    for f in flags:
                        with MR(pd, mr_len, f) as mr:
                            write_len = min(random.randint(1, MAX_IO_LEN),
                                            mr_len)
                            write_str = 'a' * write_len
                            mr.write(write_str, write_len)
                            read_len = random.randint(1, write_len)
                            offset = random.randint(0, write_len-read_len)
                            read_str = mr.read(read_len, offset).decode()
                            assert read_str in write_str

    def test_lkey(self):
        """
        Test reading lkey property
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                length = u.get_mr_length()
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, length, f) as mr:
                        mr.lkey

    def test_rkey(self):
        """
        Test reading rkey property
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                length = u.get_mr_length()
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, length, f) as mr:
                        mr.rkey

    def test_buffer(self):
        """
        Test reading buf property
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                length = u.get_mr_length()
                flags = u.get_access_flags(ctx)
                for f in flags:
                    with MR(pd, length, f) as mr:
                        mr.buf


class MWTest(PyverbsAPITestCase):
    """
    Test various functionalities of the MW class.
    """
    def test_reg_mw_type1(self):
        """
        Test ibv_alloc_mw() for type 1 MW
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                try:
                    with MW(pd, e.IBV_MW_TYPE_1):
                        pass
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Create memory window of type 1 is not supported')
                    raise ex

    def test_reg_mw_type2(self):
        """
        Test ibv_alloc_mw() for type 2 MW
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                try:
                    with MW(pd, e.IBV_MW_TYPE_2):
                        pass
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Create memory window of type 2 is not supported')
                    raise ex

    def test_dereg_mw_type1(self):
        """
        Test ibv_dealloc_mw() for type 1 MW
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                try:
                    with MW(pd, e.IBV_MW_TYPE_1) as mw:
                        mw.close()
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Create memory window of type 1 is not supported')
                    raise ex

    def test_dereg_mw_type2(self):
        """
        Test ibv_dealloc_mw() for type 2 MW
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                try:
                    with MW(pd, e.IBV_MW_TYPE_2) as mw:
                        mw.close()
                except PyverbsRDMAError as ex:
                    if ex.error_code == errno.EOPNOTSUPP:
                        raise unittest.SkipTest('Create memory window of type 2 is not supported')
                    raise ex

    def test_reg_mw_wrong_type(self):
        """
        Verify that trying to create a MW of a wrong type fails
        """
        for ctx, attr, attr_ex in self.devices:
            with PD(ctx) as pd:
                try:
                    mw_type = random.randint(3, 100)
                    MW(pd, mw_type)
                except PyverbsRDMAError:
                    pass
                else:
                    raise PyverbsError('Created a MW with type {t}'.\
                                       format(t=mw_type))


class DMMRTest(PyverbsAPITestCase):
    """
    Test various functionalities of the DMMR class.
    """
    def test_create_dm_mr(self):
        """
        Test ibv_reg_dm_mr
        """
        for ctx, attr, attr_ex in self.devices:
            if attr_ex.max_dm_size == 0:
                raise unittest.SkipTest('Device memory is not supported')
            with PD(ctx) as pd:
                for i in range(10):
                    dm_len = random.randrange(u.MIN_DM_SIZE, attr_ex.max_dm_size/2,
                                              u.DM_ALIGNMENT)
                    dm_attrs = u.get_dm_attrs(dm_len)
                    with d.DM(ctx, dm_attrs) as dm:
                        dm_mr_len = random.randint(1, dm_len)
                        dm_mr_offset = random.randint(0, (dm_len - dm_mr_len))
                        DMMR(pd, dm_mr_len, e.IBV_ACCESS_ZERO_BASED, dm=dm,
                             offset=dm_mr_offset)

    def test_destroy_dm_mr(self):
        """
        Test freeing of dm_mr
        """
        for ctx, attr, attr_ex in self.devices:
            if attr_ex.max_dm_size == 0:
                return
            with PD(ctx) as pd:
                for i in range(10):
                    dm_len = random.randrange(u.MIN_DM_SIZE, attr_ex.max_dm_size/2,
                                              u.DM_ALIGNMENT)
                    dm_attrs = u.get_dm_attrs(dm_len)
                    with d.DM(ctx, dm_attrs) as dm:
                        dm_mr_len = random.randint(1, dm_len)
                        dm_mr_offset = random.randint(0, (dm_len - dm_mr_len))
                        dm_mr = DMMR(pd, dm_mr_len, e.IBV_ACCESS_ZERO_BASED,
                                     dm=dm, offset=dm_mr_offset)
                        dm_mr.close()
