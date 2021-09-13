import unittest
import datetime
import errno

from pyverbs.enums import IBV_WC_EX_WITH_COMPLETION_TIMESTAMP as FREE_RUNNING, \
    IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK as REAL_TIME
from tests.base import RCResources, RDMATestCase, PyverbsAPITestCase
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.cq import CqInitAttrEx, CQEX
from tests.test_flow import FlowRes
from pyverbs.qp import QPInitAttr
from pyverbs.cq import PollCqAttr
import pyverbs.enums as e
import tests.utils as u


GIGA = 1000000000


def convert_ts_to_ns(ctx, device_ts):
    """
    Convert device timestamp from HCA core clock units to corresponding
    nanosecond counts.
    :param ctx: The context that gets this timestamp.
    :param device_ts: The device timestamp to translate.
    :return: Timestamp in nanoseconds
    """
    try:
        timestamp_in_ns = Mlx5Context.device_timestamp_to_ns(ctx, device_ts)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EOPNOTSUPP:
            raise unittest.SkipTest('Converting timestamp to nanoseconds is not supported')
        raise ex
    return timestamp_in_ns


def timestamp_res_cls(base_class):
    """
    This is a factory function which creates a class that inherits base_class of
    any BaseResources type.
    :param base_class: The base resources class to inherit from.
    :return: TimeStampRes class.
    """
    class TimeStampRes(base_class):
        def __init__(self, dev_name, ib_port, gid_index, qp_type, send_ts=None,
                     recv_ts=None):
            self.qp_type = qp_type
            self.send_ts = send_ts
            self.recv_ts = recv_ts
            self.timestamp = None
            self.scq = None
            self.rcq = None
            super().__init__(dev_name=dev_name, ib_port=ib_port, gid_index=gid_index)

        def create_cq(self):
            self.scq = self._create_ex_cq(self.send_ts)
            self.rcq = self._create_ex_cq(self.recv_ts)

        def _create_ex_cq(self, timestamp=None):
            """
            Create an Extended CQ.
            :param timestamp: If set, the timestamp type to use.
            """
            wc_flags = e.IBV_WC_STANDARD_FLAGS
            if timestamp:
                wc_flags |= timestamp
            cia = CqInitAttrEx(cqe=self.num_msgs, wc_flags=wc_flags)
            try:
                cq = CQEX(self.ctx, cia)
            except PyverbsRDMAError as ex:
                if ex.error_code == errno.EOPNOTSUPP:
                    raise unittest.SkipTest('Create Extended CQ is not supported')
                raise ex
            return cq

        def create_qp_init_attr(self):
            return QPInitAttr(qp_type=self.qp_type, scq=self.scq,
                              rcq=self.rcq, srq=self.srq, cap=self.create_qp_cap())

    return TimeStampRes


class TimeStampTest(RDMATestCase):
    """
    Test various types of timestamping formats.
    """
    def setUp(self):
        super().setUp()
        self.send_ts = None
        self.recv_ts = None
        self.qp_type = None

    @property
    def resource_arg(self):
        return {'send_ts': self.send_ts, 'recv_ts': self.recv_ts,
                'qp_type': self.qp_type}

    def create_players(self, resource, **resource_arg):
        """
        Init TimeStamp tests resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
        attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)
        if self.qp_type == e.IBV_QPT_RC:
            self.client.pre_run(self.server.psns, self.server.qps_num)
            self.server.pre_run(self.client.psns, self.client.qps_num)

    def test_timestamp_free_running_rc_traffic(self):
        """
        Test free running timestamp on RC traffic.
        """
        self.qp_type = e.IBV_QPT_RC
        self.send_ts = self.recv_ts = FREE_RUNNING
        self.create_players(timestamp_res_cls(RCResources), **self.resource_arg)
        self.ts_traffic()
        timestamp = convert_ts_to_ns(self.client.ctx, self.client.timestamp)
        self.verify_ts(timestamp)

    def test_timestamp_real_time_rc_traffic(self):
        """
        Test real time timestamp on RC traffic.
        """
        self.qp_type = e.IBV_QPT_RC
        self.send_ts = self.recv_ts = REAL_TIME
        self.create_players(timestamp_res_cls(RCResources), **self.resource_arg)
        self.ts_traffic()
        self.verify_ts(self.client.timestamp)

    def test_timestamp_free_running_send_raw_traffic(self):
        """
        Test timestamping on RAW traffic only on the send completions.
        """
        self.qp_type = e.IBV_QPT_RAW_PACKET
        self.send_ts = FREE_RUNNING
        self.create_players(timestamp_res_cls(FlowRes), **self.resource_arg)
        self.flow = self.server.create_flow([self.server.create_eth_spec()])
        self.ts_traffic()
        timestamp = convert_ts_to_ns(self.client.ctx, self.client.timestamp)
        self.verify_ts(timestamp)

    def test_timestamp_free_running_recv_raw_traffic(self):
        """
        Test timestamping on RAW traffic only on the recv completions.
        """
        self.qp_type = e.IBV_QPT_RAW_PACKET
        self.recv_ts = FREE_RUNNING
        self.create_players(timestamp_res_cls(FlowRes), **self.resource_arg)
        self.flow = self.server.create_flow([self.server.create_eth_spec()])
        self.ts_traffic()
        timestamp = convert_ts_to_ns(self.server.ctx, self.server.timestamp)
        self.verify_ts(timestamp)

    def test_timestamp_real_time_raw_traffic(self):
        """
        Test real time timestamp on RAW traffic.
        """
        self.qp_type = e.IBV_QPT_RAW_PACKET
        self.send_ts = self.recv_ts = REAL_TIME
        self.create_players(timestamp_res_cls(FlowRes), **self.resource_arg)
        self.flow = self.server.create_flow([self.server.create_eth_spec()])
        self.ts_traffic()
        self.verify_ts(self.client.timestamp)

    @staticmethod
    def verify_ts(timestamp):
        """
        Verify that the timestamp is a valid value of time.
        """
        datetime.datetime.fromtimestamp(timestamp/GIGA)

    @staticmethod
    def poll_cq_ex_ts(cqex, ts_type=None):
        """
        Poll completion from the extended CQ.
        :param cqex: CQEX to poll from
        :param ts_type: If set, read the CQE timestamp in this format
        :return: The CQE timestamp if it requested.
        """
        polling_timeout = 10
        start = datetime.datetime.now()
        ts = 0

        poll_attr = PollCqAttr()
        ret = cqex.start_poll(poll_attr)
        while ret == 2 and (datetime.datetime.now() - start).seconds < polling_timeout:
            ret = cqex.start_poll(poll_attr)
        if ret == 2:
            raise PyverbsRDMAError('Failed to poll CQEX - Got timeout')
        if ret != 0:
            raise PyverbsRDMAError('Failed to poll CQEX')
        if cqex.status != e.IBV_WC_SUCCESS:
            raise PyverbsRDMAError('Completion status is {cqex.status}')
        if ts_type == FREE_RUNNING:
            ts = cqex.read_timestamp()
        if ts_type == REAL_TIME:
            ts = cqex.read_completion_wallclock_ns()
        cqex.end_poll()
        return ts

    def ts_traffic(self):
        """
        Run RDMA traffic and read the completions timestamps.
        """
        s_recv_wr = u.get_recv_wr(self.server)
        u.post_recv(self.server, s_recv_wr)
        if self.qp_type == e.IBV_QPT_RAW_PACKET:
            c_send_wr, _, _ = u.get_send_elements_raw_qp(self.client)
        else:
            c_send_wr, _ = u.get_send_elements(self.client, False)
        u.send(self.client, c_send_wr, e.IBV_WR_SEND, False, 0)
        self.client.timestamp = self.poll_cq_ex_ts(self.client.scq, ts_type=self.send_ts)
        self.server.timestamp = self.poll_cq_ex_ts(self.server.rcq, ts_type=self.recv_ts)


class TimeAPITest(PyverbsAPITestCase):
    def test_query_rt_values(self):
        """
        Test the ibv_query_rt_values_ex API.
        Query the device real-time values, convert them to ns and verify that
        the timestamp is a valid value of time..
        """
        try:
            _, hw_time = self.ctx.query_rt_values_ex()
            time_in_ns = convert_ts_to_ns(self.ctx, hw_time)
            datetime.datetime.fromtimestamp(time_in_ns/GIGA)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Query device real time is not supported')
            raise ex
