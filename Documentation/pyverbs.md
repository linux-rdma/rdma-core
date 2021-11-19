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
The user should unbind or close the memory window before being able to
deregister an MR that the MW is bound to.
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
###### Extended QP
An extended QP exposes a new set of QP send operations to the user -
extensibility for new send opcodes, vendor specific send opcodes and even vendor
specific QP types.
Pyverbs now exposes the needed interface to create such a QP.
Note that the IBV_QP_INIT_ATTR_SEND_OPS_FLAGS in the `comp_mask` is mandatory
when using the extended QP's new post send mechanism.
```python
from pyverbs.qp import QPCap, QPInitAttrEx, QPAttr, QPEx
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.pd import PD
from pyverbs.cq import CQ


ctx = d.Context(name='mlx5_0')
pd = PD(ctx)
cq = CQ(ctx, 100)
cap = QPCap(100, 10, 1, 1, 0)
qia = QPInitAttrEx(qp_type=e.IBV_QPT_UD, scq=cq, rcq=cq, cap=cap, pd=pd,
                   comp_mask=e.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS| \
                   e.IBV_QP_INIT_ATTR_PD)
qp = QPEx(ctx, qia)
```

##### XRCD
The following code demonstrates creation of an XRCD object.
```python
from pyverbs.xrcd import XRCD, XRCDInitAttr
import pyverbs.device as d
import pyverbs.enums as e
import stat
import os


ctx = d.Context(name='ibp0s8f0')
xrcd_fd = os.open('/tmp/xrcd', os.O_RDONLY | os.O_CREAT,
                  stat.S_IRUSR | stat.S_IRGRP)
init = XRCDInitAttr(e.IBV_XRCD_INIT_ATTR_FD | e.IBV_XRCD_INIT_ATTR_OFLAGS,
                    os.O_CREAT, xrcd_fd)
xrcd = XRCD(ctx, init)
```

##### SRQ
The following code snippet will demonstrate creation of an XRC SRQ object.
For more complex examples, please see pyverbs/tests/test_odp.
```python
from pyverbs.xrcd import XRCD, XRCDInitAttr
from pyverbs.srq import SRQ, SrqInitAttrEx
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.cq import CQ
from pyverbs.pd import PD
import stat
import os


ctx = d.Context(name='ibp0s8f0')
pd = PD(ctx)
cq = CQ(ctx, 100, None, None, 0)
xrcd_fd = os.open('/tmp/xrcd', os.O_RDONLY | os.O_CREAT,
                  stat.S_IRUSR | stat.S_IRGRP)
init = XRCDInitAttr(e.IBV_XRCD_INIT_ATTR_FD | e.IBV_XRCD_INIT_ATTR_OFLAGS,
                    os.O_CREAT, xrcd_fd)
xrcd = XRCD(ctx, init)

srq_attr = SrqInitAttrEx(max_wr=10)
srq_attr.srq_type = e.IBV_SRQT_XRC
srq_attr.pd = pd
srq_attr.xrcd = xrcd
srq_attr.cq = cq
srq_attr.comp_mask = e.IBV_SRQ_INIT_ATTR_TYPE | e.IBV_SRQ_INIT_ATTR_PD | \
                     e.IBV_SRQ_INIT_ATTR_CQ | e.IBV_SRQ_INIT_ATTR_XRCD
srq = SRQ(ctx, srq_attr)


##### Open an mlx5 provider
A provider is essentially a Context with driver-specific extra features. As
such, it inherits from Context. In legcay flow Context iterates over the IB
devices and opens the one matches the name given by the user (name= argument).
When provider attributes are also given (attr=), the Context will assign the
relevant ib_device to its device member, so that the provider will be able to
open the device in its specific way as demonstated below:

```python
import pyverbs.providers.mlx5.mlx5dv as m
from pyverbs.pd import PD
attr = m.Mlx5DVContextAttr()  # Default values are fine
ctx = m.Mlx5Context(attr=attr, name='rocep0s8f0')
# The provider context can be used as a regular Context, e.g.:
pd = PD(ctx)  # Success
```

##### Query an mlx5 provider
After opening an mlx5 provider, users can use the device-specific query for
non-legacy attributes. The following snippet demonstrates how to do that.
```python
import pyverbs.providers.mlx5.mlx5dv as m
ctx = m.Mlx5Context(attr=m.Mlx5DVContextAttr(), name='ibp0s8f0')
mlx5_attrs = ctx.query_mlx5_device()
print(mlx5_attrs)
Version             : 0
Flags               : CQE v1, Support CQE 128B compression, Support CQE 128B padding, Support packet based credit mode (in RC QP)
comp mask           : CQE compression, SW parsing, Striding RQ, Tunnel offloads, Dynamic BF regs, Clock info update, Flow action flags
CQE compression caps:
  max num             : 64
  supported formats   : with hash, with RX checksum CSUM, with stride index
SW parsing caps:
  SW parsing offloads :
  supported QP types  :
Striding RQ caps:
  min single stride log num of bytes: 6
  max single stride log num of bytes: 13
  min single wqe log num of strides: 9
  max single wqe log num of strides: 16
  supported QP types  : Raw Packet
Tunnel offloads caps:
Max dynamic BF registers: 1024
Max clock info update [nsec]: 1099511
Flow action flags   : 0
```

##### Create an mlx5 QP
Using an Mlx5Context object, one can create either a legacy QP (creation
process is the same) or an mlx5 QP. An mlx5 QP is a QP by inheritance but its
constructor receives a keyword argument named `dv_init_attr`. If the user
provides it, the QP will be created using `mlx5dv_create_qp` rather than
`ibv_create_qp_ex`. The following snippet demonstrates how to create both a DC
(dynamically connected) QP and a Raw Packet QP which uses mlx5-specific
capabilities, unavailable using the legacy interface. Currently, pyverbs
supports only creation of a DCI. DCT support will be added in one of the
following PRs.
```python
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr
from pyverbs.providers.mlx5.mlx5dv import Mlx5DVQPInitAttr, Mlx5QP
import pyverbs.providers.mlx5.mlx5_enums as me
from pyverbs.qp import QPInitAttrEx, QPCap
import pyverbs.enums as e
from pyverbs.cq import CQ
from pyverbs.pd import PD

with Mlx5Context(name='rocep0s8f0', attr=Mlx5DVContextAttr()) as ctx:
    with PD(ctx) as pd:
        with CQ(ctx, 100) as cq:
            cap = QPCap(100, 0, 1, 0)
            # Create a DC QP of type DCI
            qia = QPInitAttrEx(cap=cap, pd=pd, scq=cq, qp_type=e.IBV_QPT_DRIVER,
                               comp_mask=e.IBV_QP_INIT_ATTR_PD, rcq=cq)
            attr = Mlx5DVQPInitAttr(comp_mask=me.MLX5DV_QP_INIT_ATTR_MASK_DC)
            attr.dc_type = me.MLX5DV_DCTYPE_DCI

            dci = Mlx5QP(ctx, qia, dv_init_attr=attr)

            # Create a Raw Packet QP using mlx5-specific capabilities
            qia.qp_type = e.IBV_QPT_RAW_PACKET
            attr.comp_mask = me.MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS
            attr.create_flags = me.MLX5DV_QP_CREATE_ALLOW_SCATTER_TO_CQE |\
                                me.MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_UC |\
                                me.MLX5DV_QP_CREATE_TUNNEL_OFFLOADS
            qp = Mlx5QP(ctx, qia, dv_init_attr=attr)
```

##### Create an mlx5 CQ
Mlx5Context also allows users to create an mlx5 specific CQ. The Mlx5CQ inherits
from CQEX, but its constructor receives 3 parameters instead of 2. The 3rd
parameter is a keyword argument named `dv_init_attr`. If provided by the user,
the CQ will be created using `mlx5dv_create_cq`.
The following snippet shows this simple creation process.
```python
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr
from pyverbs.providers.mlx5.mlx5dv import Mlx5DVCQInitAttr, Mlx5CQ
import pyverbs.providers.mlx5.mlx5_enums as me
from pyverbs.cq import CqInitAttrEx

with Mlx5Context(name='rocep0s8f0', attr=Mlx5DVContextAttr()) as ctx:
    cqia = CqInitAttrEx()
    mlx5_cqia = Mlx5DVCQInitAttr(comp_mask=me.MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE,
                                 cqe_comp_res_format=me.MLX5DV_CQE_RES_FORMAT_CSUM)
    cq = Mlx5CQ(ctx, cqia, dv_init_attr=mlx5_cqia)
```

##### CMID
The following code snippet will demonstrate creation of a CMID object, which
represents rdma_cm_id C struct, and establish connection between two peers.
Currently only synchronous control path is supported (rdma_create_ep).
For more complex examples, please see tests/test_rdmacm.
```python
from pyverbs.qp import QPInitAttr, QPCap
from pyverbs.cmid import CMID, AddrInfo
import pyverbs.cm_enums as ce


cap = QPCap(max_recv_wr=1)
qp_init_attr = QPInitAttr(cap=cap)
addr = '11.137.14.124'
port = '7471'

# Passive side

sai = AddrInfo(src=addr, src_service=port, port_space=ce.RDMA_PS_TCP, flags=ce.RAI_PASSIVE)
sid = CMID(creator=sai, qp_init_attr=qp_init_attr)
sid.listen()  # listen for incoming connection requests
new_id = sid.get_request()  # check if there are any connection requests
new_id.accept()  # new_id is connected to remote peer and ready to communicate

# Active side

cai = AddrInfo(src=addr, dst=addr, dst_service=port, port_space=ce.RDMA_PS_TCP)
cid = CMID(creator=cai, qp_init_attr=qp_init_attr)
cid.connect()  # send connection request to passive addr
```

##### ParentDomain
The following code demonstrates the creation of Parent Domain object.
In this example, a simple Python allocator is defined. It uses MemAlloc class to
allocate aligned memory using a C style aligned_alloc.
```python
from pyverbs.pd import PD, ParentDomainInitAttr, ParentDomain, \
    ParentDomainContext
from pyverbs.device import Context
import pyverbs.mem_alloc as mem


def alloc_p_func(pd, context, size, alignment, resource_type):
    p = mem.posix_memalign(size, alignment)
    return p


def free_p_func(pd, context, ptr, resource_type):
    mem.free(ptr)


ctx = Context(name='rocep0s8f0')
pd = PD(ctx)
pd_ctx = ParentDomainContext(pd, alloc_p_func, free_p_func)
pd_attr = ParentDomainInitAttr(pd=pd, pd_context=pd_ctx)
parent_domain = ParentDomain(ctx, attr=pd_attr)
```

##### MLX5 VAR
The following code snippet demonstrates how to allocate an mlx5dv_var then using
it for memory address mapping, then freeing the VAR.
```python
from pyverbs.providers.mlx5.mlx5dv import Mlx5VAR
from pyverbs.device import Context
import mmap

ctx = Context(name='rocep0s8f0')
var = Mlx5VAR(ctx)
var_map = mmap.mmap(fileno=ctx.cmd_fd, length=var.length, offset=var.mmap_off)
# There is no munmap method in mmap Python module, but by closing the mmap
# instance the memory is unmapped.
var_map.close()
var.close()
```

##### MLX5 PP
Packet Pacing (PP) entry can be used for some device commands over the DEVX
interface. It allows a rate-limited flow configuration on SQs.
The following code snippet demonstrates how to allocate an mlx5dv_pp with rate
limit value of 5, then frees the entry.
```python
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, Mlx5PP
import pyverbs.providers.mlx5.mlx5_enums as e

# The device must be opened as DEVX context
mlx5dv_attr = Mlx5DVContextAttr(e.MLX5DV_CONTEXT_FLAGS_DEVX)
ctx = Mlx5Context(attr=mlx5dv_attr, name='rocep0s8f0')
rate_limit_inbox = (5).to_bytes(length=4, byteorder='big', signed=True)
pp = Mlx5PP(ctx, rate_limit_inbox)
pp.close()
```

##### MLX5 UAR
User Access Region (UAR) is part of PCI address space that is mapped for direct
access to the HCA from the CPU.
The UAR is needed for some device commands over the DevX interface.
The following code snippet demonstrates how to allocate and free an
mlx5dv_devx_uar.
```python
from pyverbs.providers.mlx5.mlx5dv import Mlx5UAR
from pyverbs.device import Context

ctx = Context(name='rocep0s8f0')
uar = Mlx5UAR(ctx)
uar.close()
```

##### Import device, PD and MR
Importing a device, PD and MR enables processes to share their context and then
share PDs and MRs that is associated with.
A process creates a device and then uses some of the Linux systems calls to dup
its 'cmd_fd' member which lets other process to obtain ownership.
Once other process obtains the 'cmd_fd' it can import the device, then PD(s) and
MR(s) to share these objects.
Like in C, Pyverbs users are responsible for unimporting the imported objects
(which will also close the Pyverbs instance in our case) after they finish using
them, and they have to sync between the different processes in order to
coordinate the closure of the objects.
Unlike in C, closing the underlying objects is currently supported only via the
"original" object (meaning only by the process that creates them) and not via
the imported object. This limitation is made because currently there's no
reference or relation between different Pyverbs objects in different processes.
But it's doable and might be added in the future.
Here is a demonstration of importing a device, PD and MR in one process.
```python
from pyverbs.device import Context
from pyverbs.pd import PD
from pyverbs.mr import MR
import pyverbs.enums as e
import os

ctx = Context(name='ibp0s8f0')
pd = PD(ctx)
mr = MR(pd, 100, e.IBV_ACCESS_LOCAL_WRITE)
cmd_fd_dup = os.dup(ctx.cmd_fd)
improted_ctx = Context(cmd_fd=cmd_fd_dup)
imported_pd = PD(improted_ctx, handle=pd.handle)
imported_mr = MR(imported_pd, handle=mr.handle)
# MRs can be created as usual on the imported PD
secondary_mr = MR(imported_pd, 100, e.IBV_ACCESS_REMOTE_READ)
# Must manually unimport the imported objects (which close the object and frees
# other resources that use them) before closing the "original" objects.
# This prevents unexpected behaviours caused by the GC.
imported_mr.unimport()
imported_pd.unimport()
```


##### Flow Steering
Flow steering rules define packet matching done by the hardware.
A spec describes packet matching on a specific layer (L2, L3 etc.).
A flow is a collection of specs.
A user QP can attach to flows in order to receive specific packets.

###### Flow and FlowAttr

```python
from pyverbs.qp import QPCap, QPInitAttr, QPAttr, QP
from pyverbs.flow import FlowAttr, Flow
from pyverbs.spec import EthSpec
import pyverbs.device as d
import pyverbs.enums as e
from pyverbs.pd import PD
from pyverbs.cq import CQ


ctx = d.Context(name='rocep0s8f0')
pd = PD(ctx)
cq = CQ(ctx, 100, None, None, 0)
cap = QPCap(100, 10, 1, 1, 0)
qia = QPInitAttr(cap=cap, qp_type = e.IBV_QPT_UD, scq=cq, rcq=cq)
qp = QP(pd, qia, QPAttr())

# Create Eth spec
eth_spec = EthSpec(ether_type=0x800, dst_mac="01:50:56:19:20:a7")
eth_spec.src_mac = "24:8a:07:a5:28:c8"
eth_spec.src_mac_mask = "ff:ff:ff:ff:ff:ff"

# Create Flow
flow_attr = FlowAttr(num_of_specs=1)
flow_attr.specs.append(eth_spec)
flow = Flow(qp, flow_attr)
```

###### Specs
Each spec holds a specific network layer parameters for matching. To enforce
the match, the user sets a mask for each parameter. If the bit is set in the
mask, the corresponding bit in the value should be matched.
Packets coming from the wire are matched against the flow specification. If a
match is found, the associated flow actions are executed on the packet. In
ingress flows, the QP parameter is treated as another action of scattering the
packet to the respected QP.


###### Notes
* When creating specs mask will be set to FF's to all the given values (unless
provided by the user). When editing a spec mask should be specified explicitly.
* If a field is not provided its value and mask will be set to zeros.
* Hardware only supports full / empty masks.
* Ethernet, IPv4, TCP/UDP, IPv6 and ESP specs can be inner (IBV_FLOW_SPEC_INNER),
but set to outer by default.


###### Ethernet spec
Example of creating and editing Ethernet spec
```python
from pyverbs.spec import EthSpec
eth_spec = EthSpec(src_mac="ab:cd:ef:ab:cd:ef", vlan_tag=0x123, is_inner=1)
eth_spec.dst_mac = "de:de:de:00:de:de"
eth_spec.dst_mac_mask = "ff:ff:ff:ff:ff:ff"
eth_spec.ether_type = 0x321
eth_spec.ether_type_mask = 0xffff
# Resulting spec
print(f'{eth_spec}')
```
Below is the output when printing the spec.

    Spec type       : IBV_FLOW_SPEC_INNER IBV_FLOW_SPEC_ETH
    Size            : 40
    Src mac         : ab:cd:ef:ab:cd:ef    mask: ff:ff:ff:ff:ff:ff
    Dst mac         : de:de:de:00:de:de    mask: ff:ff:ff:ff:ff:ff
    Ether type      : 8451                 mask: 65535
    Vlan tag        : 8961                 mask: 65535


##### MLX5 DevX Objects
A DevX object represents some underlay firmware object, the input command to
create it is some raw data given by the user application which should match the
device specification.
Upon successful creation, the output buffer includes the raw data from the device
according to its specification and is stored in the Mlx5DevxObj instance. This
data can be used as part of related firmware commands to this object.
In addition to creation, the user can query/modify and destroy the object.

Although weakrefs and DevX objects closure are added and handled by
Pyverbs, the users must manually close these objects when finished, and
should not let them be handled by the GC, or by closing the Mlx5Context directly,
since there's no guarantee that the DevX objects are closed in the correct order,
because Mlx5DevxObj is a general class that can be any of the device's available
objects.
But Pyverbs does guarantee to close DevX UARs and UMEMs in order, and after
closing the other DevX objects.

The following code snippet shows how to allocate and destroy a PD object over DevX.
```python
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, Mlx5DevxObj
import pyverbs.providers.mlx5.mlx5_enums as dve
import struct

attr = Mlx5DVContextAttr(dve.MLX5DV_CONTEXT_FLAGS_DEVX)
ctx = Mlx5Context(attr, 'rocep8s0f0')
MLX5_CMD_OP_ALLOC_PD = 0x800
MLX5_CMD_OP_ALLOC_PD_OUTLEN = 0x10
cmd_in = struct.pack('!H14s', MLX5_CMD_OP_ALLOC_PD, bytes(0))
pd = Mlx5DevxObj(ctx, cmd_in, MLX5_CMD_OP_ALLOC_PD_OUTLEN)
pd.close()
```
