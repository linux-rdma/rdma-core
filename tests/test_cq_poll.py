# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
"""Device-independent tests for the CQ polling helpers."""

import socket
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from pyverbs.libibverbs_enums import ibv_wc_flags, ibv_wc_status
from pyverbs.pyverbs_error import PyverbsRDMAError
import tests.utils as u


class CQPollTest(unittest.TestCase):
    def make_cq(self, values):
        completions = [SimpleNamespace(status=ibv_wc_status.IBV_WC_SUCCESS,
                                       wc_flags=ibv_wc_flags.IBV_WC_WITH_IMM,
                                       imm_data=socket.htonl(value))
                       for value in values]
        cq = Mock(comp_channel=None)
        cq.poll.return_value = len(completions), completions
        return cq, completions

    def make_cqex(self, values):
        cq = Mock(status=ibv_wc_status.IBV_WC_SUCCESS, wr_id=1)
        cq.start_poll.return_value = 0
        cq.poll_next.return_value = 0
        cq.read_imm_data.side_effect = [socket.htonl(value) for value in values]
        return cq

    def test_cq_immediate_values(self):
        for data in (0, 0x01020304, 0xffffffff):
            with self.subTest(data=data):
                cq, completions = self.make_cq([data, data])
                self.assertEqual(u.poll_cq(cq, count=2, data=data), completions)

    def test_cq_immediate_mismatch(self):
        for data in (0, 0x01020304):
            for index in range(2):
                with self.subTest(data=data, index=index):
                    values = [data, data]
                    values[index] ^= 1
                    cq, _ = self.make_cq(values)
                    with self.assertRaises(AssertionError):
                        u.poll_cq(cq, count=2, data=data)

    def test_cq_missing_immediate_flag(self):
        for data in (0, 0x01020304):
            for index in range(2):
                with self.subTest(data=data, index=index):
                    cq, completions = self.make_cq([data, data])
                    completions[index].wc_flags = 0
                    with self.assertRaisesRegex(PyverbsRDMAError,
                                                'Completion without immediate'):
                        u.poll_cq(cq, count=2, data=data)

    def test_cq_without_immediate_validation(self):
        cq, completions = self.make_cq([0x01020304])
        completions[0].wc_flags = 0
        self.assertEqual(u.poll_cq(cq, data=None), completions)

    def test_cqex_immediate_values(self):
        for data in (0, 0x01020304, 0xffffffff):
            with self.subTest(data=data):
                cq = self.make_cqex([data, data])
                self.assertEqual(u.poll_cq_ex(cq, count=2, data=data), [1, 1])
                self.assertEqual(cq.read_imm_data.call_count, 2)
                cq.end_poll.assert_called_once_with()

    def test_cqex_immediate_mismatch_first(self):
        for data in (0, 0x01020304):
            with self.subTest(data=data):
                cq = self.make_cqex([data ^ 1])
                with self.assertRaises(AssertionError):
                    u.poll_cq_ex(cq, data=data)
                cq.end_poll.assert_called_once_with()

    def test_cqex_immediate_mismatch_next(self):
        for data in (0, 0x01020304):
            with self.subTest(data=data):
                cq = self.make_cqex([data, data ^ 1])
                with self.assertRaises(AssertionError):
                    u.poll_cq_ex(cq, count=2, data=data)
                cq.end_poll.assert_called_once_with()

    def test_cqex_immediate_list(self):
        values = [0, 0x01020304, 0]
        cq = self.make_cqex(values)
        self.assertEqual(u.poll_cq_ex(cq, count=3, data=values), [1, 1, 1])
        self.assertEqual(cq.read_imm_data.call_count, 3)
        cq.end_poll.assert_called_once_with()

    def test_cqex_immediate_list_mismatch(self):
        expected = [0, 0x01020304, 0]
        for index in range(len(expected)):
            with self.subTest(index=index):
                values = expected.copy()
                values[index] ^= 1
                cq = self.make_cqex(values)
                with self.assertRaises(AssertionError):
                    u.poll_cq_ex(cq, count=3, data=expected)
                cq.end_poll.assert_called_once_with()

    def test_cqex_without_immediate_validation(self):
        cq = self.make_cqex([0x01020304, 0x05060708])
        self.assertEqual(u.poll_cq_ex(cq, count=2, data=None), [1, 1])
        cq.read_imm_data.assert_not_called()
        cq.end_poll.assert_called_once_with()
