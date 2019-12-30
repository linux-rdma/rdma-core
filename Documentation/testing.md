# Testing in rdma-core

rdma-core now offers an infrastructure for quick and easy additions of feature-
specific tests.

## Design
### Resources Management
`BaseResources` class is the basic objects aggregator available. It includes a
Context and a PD.
Inheriting from it is `TrafficResources` class, which also holds a MR, CQ and
QP, making it enough to support loopback traffic testing. It exposes methods for
creation of these objects which can be overridden by inheriting classes.
Inheriting from `TrafficResources` are currently three classes:
- `RCResources`
- `UDResources`
- `XRXResources`

The above subclasses add traffic-specific constants.  For example, `UDResources`
overrides create_mr and adds the size of the GRH header to the message size.
`RCResources` exposes a wrapper to modify the QP to RTS.

### Tests-related Classes
`unittest.TestCase` is a logical test unit in Python's unittest module.
`RDMATestCase` inherits from it and adds the option to accept parameters
(example will follow below) or use a random set of valid parameters:
- If no device was provided, it iterates over the existing devices, for each
  port of each device, it checks which GID indexes are valid (in RoCE, only
  IPv4 and IPv6 based GIDs are used). Each <dev, port, gid> is added to an array
  and one entry is selected.
- If a device was provided, the same process is done for all ports of this
  device, and so on.

### Traffic Utilities
tests/utils.py offers a few wrappers for common traffic operations, making the
use of default values even shorter. Those traffic utilities accept an
aggregation object as their first parameter and rely on that object to have
valid RDMA resources for proper functioning.
- get_[send, recv]_wr() creates a [Send, Recv]WR object with a single SGE. It
  also sets the MR content to be 'c's for client side or 's's for server side
  (this is later validated).
- post_send() posts a single send request to the aggregation object's QP. If the
  QP is a UD QP, an address vector will be added to the send WR.
- post_recv() posts the given RecvWR <num> times, so it can be used to fill the
  RQ prior to traffic as well as during traffic.
- poll_cq() polls <num> completions from the CQ and raises an exception on a
  non-success status.
- validate() verifies that the data in the MR is as expected ('c's for server,
  's's for client).
- traffic() runs <num> iterations of send/recv between 2 players.

## How to run rdma-core's tests
#### Developers
The tests can be executed from ./build/bin:
./build.sh
./build/bin/run_tests.py
#### Users
The tests are not a Python package, as such they can be found under
/usr/share/doc/rdma-core-{version}/tests.
In order to run all tests:
```
python /usr/share/doc/rdma-core-<version>/tests/run_tests.py
```
#### Execution output
Output will be something like:
```
$ ./build/bin/run_tests.py
..........................................ss...............
----------------------------------------------------------------------
Ran 59 tests in 13.268s

OK (skipped=2)
```
A dot represents a passing test. 's' means a skipped test. 'E' means a test
that failed.

Tests can also be executed in verbose mode:
```
$ python3 /usr/share/doc/rdma-core-26.0/tests/run_tests.py -v
test_create_ah (test_addr.AHTest) ... ok
test_create_ah_roce (test_addr.AHTest) ... ok
test_destroy_ah (test_addr.AHTest) ... ok
test_create_comp_channel (test_cq.CCTest) ... ok
< many more lines here>
test_odp_rc_traffic (test_odp.OdpTestCase) ... skipped 'No port is up, can't run traffic'
test_odp_ud_traffic (test_odp.OdpTestCase) ... skipped 'No port is up, can't run traffic'
<more lines>

----------------------------------------------------------------------
Ran 59 tests in 12.857s

OK (skipped=2)
```
Verbose mode provides the reason for skipping the test (if one was provided by
the test developer).

### Customized Execution
tests/__init__.py defines a `_load_tests` function that returns an array with
the tests that will be executed.
The default implementation collects all test_* methods from all the classes that
inherit from `unittest.TestCase` (or `RDMATestCase`) and located in files under
tests directory which names starts with test_.
Users can execute part of the tests by adding `-k` to the run_tests.py command.
The following example executes only tests cases in files starting with
`test_device` and not `test_`.

```
$ build/bin/run_tests.py -v -k test_device
test_create_dm (tests.test_device.DMTest) ... ok
test_create_dm_bad_flow (tests.test_device.DMTest) ... ok
test_destroy_dm (tests.test_device.DMTest) ... ok
test_destroy_dm_bad_flow (tests.test_device.DMTest) ... ok
test_dm_read (tests.test_device.DMTest) ... ok
test_dm_write (tests.test_device.DMTest) ... ok
test_dm_write_bad_flow (tests.test_device.DMTest) ... ok
test_dev_list (tests.test_device.DeviceTest) ... ok
test_open_dev (tests.test_device.DeviceTest) ... ok
test_query_device (tests.test_device.DeviceTest) ... ok
test_query_device_ex (tests.test_device.DeviceTest) ... ok
test_query_gid (tests.test_device.DeviceTest) ... ok
test_query_port (tests.test_device.DeviceTest) ... ok
test_query_port_bad_flow (tests.test_device.DeviceTest) ... ok

----------------------------------------------------------------------
Ran 14 tests in 0.152s

OK
```
We're using 'parametrize' as it instantiates the TestCase for us.
'parametrize' can accept arguments as well (device name, IB port, GID index and
PKey index):
```
suite = unittest.TestSuite()
suite.addTest(RDMATestCase.parametrize(YourTestCase, dev_name='devname'))
```

## Writing Tests
The following section explains how to add a new test, using tests/test_odp.py
as an example. It's a simple test that runs ping-pong over a few different
traffic types.

ODP requires capability check, so a decorator was added to tests/utils.py.
The first change for ODP execution is when registering a memory region (need to
set the ON_DEMAND access flag), so we do as follows:
1. Create the players by inheriting from `RCResources` (for RC traffic).
2. In the player, override create_mr() and add the decorator to it. It will run
   before the actual call to ibv_reg_mr and if ODP caps are off, the test will
   be skipped.
 3. Create the `OdpTestCase` by inheriting from `RDMATestCase`.
 4. In the test case, add a method starting with test_, to let the unittest
    infrastructure that this is a test.
 5. In the test method, create the players (which already check the ODP caps)
    and call the traffic() function, providing it the two players.
