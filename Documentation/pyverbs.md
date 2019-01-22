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
