# Pyverbs

Pyverbs provides a Python API over rdma-core, the Linux userspace C API for
the RDMA stack.

## Goals

1. Provide easier access to RDMA: RDMA has a steep learning curve as is and
   the C interface requires the user to initialize multiple structs before
   having usable objects. Pyverbs attempts to remove much of this overhead and
   provide a smoother user experience.
2. Improve our code by providing a test suite for rdma-core. This means that
   new features will be tested before merge, and it also means that users and
   distros will have tests for new and existing features, as well as the means
   to create them quickly.
3. Stay up-to-date with rdma-core - cover new features during development and
   provide a test / unit-test alongside the feature.

## Limitations

Python handles memory for users. As a result, memory is allocated by Pyverbs
when needed (e.g. user buffer for memory region). The memory will be accessible
to the users, but not allocated or freed by them.

## Usage Examples
Note that all examples use a hard-coded device name ('mlx5_0').
##### Open an IB device

Import the device module and open a device by name:

```python
import pyverbs.device as d
ctx = d.Context(name='mlx5_0')
```

'ctx' is Pyverbs' equivalent to rdma-core's ibv_context. At this point, the IB
device is already open and ready to use.

##### Query a device
```python
import pyverbs.device as d
ctx = d.Context(name='mlx5_0')
attr = ctx.query_device()
print(attr)
FW version            : 16.24.0185
Node guid             : 9803:9b03:0000:e4c6
Sys image GUID        : 9803:9b03:0000:e4c6
Max MR size           : 0xffffffffffffffff
Page size cap         : 0xfffffffffffff000
Vendor ID             : 0x2c9
Vendor part ID        : 4119
HW version            : 0
Max QP                : 262144
Max QP WR             : 32768
Device cap flags      : 3983678518
Max SGE               : 30
Max SGE RD            : 30
MAX CQ                : 16777216
Max CQE               : 4194303
Max MR                : 16777216
Max PD                : 16777216
Max QP RD atom        : 16
Max EE RD atom        : 0
Max res RD atom       : 4194304
Max QP init RD atom   : 16
Max EE init RD atom   : 0
Atomic caps           : 1
Max EE                : 0
Max RDD               : 0
Max MW                : 16777216
Max raw IPv6 QPs      : 0
Max raw ethy QP       : 0
Max mcast group       : 2097152
Max mcast QP attach   : 240
Max AH                : 2147483647
Max FMR               : 0
Max map per FMR       : 2147483647
Max SRQ               : 8388608
Max SRQ WR            : 32767
Max SRQ SGE           : 31
Max PKeys             : 128
local CA ack delay    : 16
Phys port count       : 1
```

'attr' is Pyverbs' equivalent to ibv_device_attr. Pyverbs will provide it to
the user upon completion of the call to ibv_query_device.

##### Query GID

```python
import pyverbs.device as d
ctx = d.Context(name='mlx5_0')
gid = ctx.query_gid(port_num=1, index=3)
print(gid)
0000:0000:0000:0000:0000:ffff:0b87:3c08
```

'gid' is Pyverbs' equivalent to ibv_gid, provided to the user by Pyverbs.

##### Query port
The following code snippet provides an example of pyverbs' equivalent of
querying a port. Context's query_port() command wraps ibv_query_port().
The example below queries the first port of the device.
```python
import pyverbs.device as d
ctx=d.Context(name='mlx5_0')
port_attr = ctx.query_port(1)
print(port_attr)
Port state              : Active (4)
Max MTU                 : 4096 (5)
Active MTU              : 1024 (3)
SM lid                  : 0
Port lid                : 0
lmc                     : 0x0
Link layer              : Ethernet
Max message size        : 0x40000000
Port cap flags          : IBV_PORT_CM_SUP IBV_PORT_IP_BASED_GIDS
Port cap flags 2        :
max VL num              : 0
Bad Pkey counter        : 0
Qkey violations counter : 0
Gid table len           : 256
Pkey table len          : 1
SM sl                   : 0
Subnet timeout          : 0
Init type reply         : 0
Active width            : 4X (2)
Ative speed             : 25.0 Gbps (32)
Phys state              : Link up (5)
Flags                   : 1
```

##### Extended query device
The example below shows how to open a device using pyverbs and query the
extended device's attributes.
Context's query_device_ex() command wraps ibv_query_device_ex().
```python
import pyverbs.device as d

ctx = d.Context(name='mlx5_0')
attr = ctx.query_device_ex()
attr.max_dm_size
131072
attr.rss_caps.max_rwq_indirection_table_size
2048
```

#### Create RDMA objects
##### PD
The following example shows how to open a device and use its context to create
a PD.
```python
import pyverbs.device as d
from pyverbs.pd import PD

with d.Context(name='mlx5_0') as ctx:
    pd = PD(ctx)
```
##### MR
The example below shows how to create a MR using pyverbs. Similar to C, a
device must be opened prior to creation and a PD has to be allocated.
```python
import pyverbs.device as d
from pyverbs.pd import PD
from pyverbs.mr import MR
import pyverbs.enums as e

with d.Context(name='mlx5_0') as ctx:
    with PD(ctx) as pd:
        mr_len = 1000
        flags = e.IBV_ACCESS_LOCAL_WRITE
        mr = MR(pd, mr_len, flags)
```
##### Memory window
The following example shows the equivalent of creating a type 1 memory window.
It includes opening a device and allocating the necessary PD.
```python
import pyverbs.device as d
from pyverbs.pd import PD
from pyverbs.mr import MW
import pyverbs.enums as e

with d.Context(name='mlx5_0') as ctx:
    with PD(ctx) as pd:
        mw = MW(pd, e.IBV_MW_TYPE_1)
```
##### Device memory
The following snippet shows how to allocate a DM - a direct memory object,
using the device's memory.
```python
import random

from pyverbs.device import DM, AllocDmAttr
import pyverbs.device as d

with d.Context(name='mlx5_0') as ctx:
    attr = ctx.query_device_ex()
    if attr.max_dm_size != 0:
        dm_len = random.randint(4, attr.max_dm_size)
        dm_attrs = AllocDmAttr(dm_len)
        dm = DM(ctx, dm_attrs)
```

##### DM MR
The example below shows how to open a DMMR - device memory MR, using the
device's own memory rather than a user-allocated buffer.
```python
import random

from pyverbs.device import DM, AllocDmAttr
from pyverbs.mr import DMMR
import pyverbs.device as d
from pyverbs.pd import PD
import pyverbs.enums as e

with d.Context(name='mlx5_0') as ctx:
    attr = ctx.query_device_ex()
    if attr.max_dm_size != 0:
        dm_len = random.randint(4, attr.max_dm_size)
        dm_attrs = AllocDmAttr(dm_len)
        dm_mr_len = random.randint(4, dm_len)
        with DM(ctx, dm_attrs) as dm:
            with PD(ctx) as pd:
                dm_mr = DMMR(pd, dm_mr_len, e.IBV_ACCESS_ZERO_BASED, dm=dm,
                             offset=0)
```

##### CQ
The following snippets show how to create CQs using pyverbs. Pyverbs supports
both CQ and extended CQ (CQEX).
As in C, a completion queue can be created with or without a completion
channel, the snippets show that.
CQ's 3rd parameter is cq_context, a user-defined context. We're using None in
our snippets.
```python
import random

from pyverbs.cq import CompChannel, CQ
import pyverbs.device as d

with d.Context(name='mlx5_0') as ctx:
    num_cqes = random.randint(0, 200) # Just arbitrary values. Max value can be
                                      # found in device attributes
    comp_vector = 0 # An arbitrary value. comp_vector is limited by the
                    # context's num_comp_vectors
    if random.choice([True, False]):
        with CompChannel(ctx) as cc:
            cq = CQ(ctx, num_cqes, None, cc, comp_vector)
    else:
        cq = CQ(ctx, num_cqes, None, None, comp_vector)
    print(cq)
CQ
Handle                : 0
CQEs                  : 63
```

```python
import random

from pyverbs.cq import CqInitAttrEx, CQEX
import pyverbs.device as d
import pyverbs.enums as e

with d.Context(name='mlx5_0') as ctx:
    num_cqe = random.randint(0, 200)
    wc_flags = e.IBV_WC_EX_WITH_CVLAN
    comp_mask = 0 # Not using flags in this example
    # completion channel is not used in this example
    attrs = CqInitAttrEx(cqe=num_cqe, wc_flags=wc_flags, comp_mask=comp_mask,
                         flags=0)
    print(attrs)
    cq_ex = CQEX(ctx, attrs)
    print(cq_ex)
    Number of CQEs        : 10
WC flags              : IBV_WC_EX_WITH_CVLAN
comp mask             : 0
flags                 : 0

Extended CQ:
Handle                : 0
CQEs                  : 15
```

##### Addressing related objects
The following code demonstrates creation of GlobalRoute, AHAttr and AH objects.
The example creates a global AH so it can also run on RoCE without
modifications.
```python

from pyverbs.addr import GlobalRoute, AHAttr, AH
import pyverbs.device as d
from pyverbs.pd import PD

with d.Context(name='mlx5_0') as ctx:
    port_number = 1
    gid_index = 0  # GID index 0 always exists and valid
    gid = ctx.query_gid(port_number, gid_index)
    gr = GlobalRoute(dgid=gid, sgid_index=gid_index)
    ah_attr = AHAttr(gr=gr, is_global=1, port_num=port_number)
    print(ah_attr)
    with PD(ctx) as pd:
        ah = AH(pd, attr=ah_attr)
DGID                  : fe80:0000:0000:0000:9a03:9bff:fe00:e4bf
flow label            : 0
sgid index            : 0
hop limit             : 1
traffic class         : 0
```

##### QP
The following snippets will demonstrate creation of a QP and a simple post_send
operation. For more complex examples, please see pyverbs/examples section.
```python
from pyverbs.qp import QPCap, QPInitAttr, QPAttr, QP
from pyverbs.addr import GlobalRoute
from pyverbs.addr import AH, AHAttr
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.pd import PD
from pyverbs.cq import CQ
import pyverbs.wr as pwr


ctx = d.Context(name='mlx5_0')
pd = PD(ctx)
cq = CQ(ctx, 100, None, None, 0)
cap = QPCap(100, 10, 1, 1, 0)
qia = QPInitAttr(cap=cap, qp_type = e.IBV_QPT_UD, scq=cq, rcq=cq)
# A UD QP will be in RTS if a QPAttr object is provided
udqp = QP(pd, qia, QPAttr())
port_num = 1
gid_index = 3 # Hard-coded for RoCE v2 interface
gid = ctx.query_gid(port_num, gid_index)
gr = GlobalRoute(dgid=gid, sgid_index=gid_index)
ah_attr = AHAttr(gr=gr, is_global=1, port_num=port_num)
ah=AH(pd, ah_attr)
wr = pwr.SendWR()
wr.set_wr_ud(ah, 0x1101, 0) # in real life, use real values
udqp.post_send(wr)
```
