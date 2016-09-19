# Introduction

libibverbs is a library that allows programs to use RDMA "verbs" for
direct access to RDMA (currently InfiniBand and iWARP) hardware from
userspace.  For more information on RDMA verbs, see the InfiniBand
Architecture Specification vol. 1, especially chapter 11, and the RDMA
Consortium's RDMA Protocol Verbs Specification.

# Using libibverbs

### Device nodes

The verbs library expects special character device files named
/dev/infiniband/uverbsN to be created.  When you load the kernel
modules, including both the low-level driver for your IB hardware as
well as the ib_uverbs module, you should see one or more uverbsN
entries in /sys/class/infiniband_verbs in addition to the
/dev/infiniband/uverbsN character device files.

To create the appropriate character device files automatically with
udev, a rule like

    KERNEL="uverbs*", NAME="infiniband/%k"

can be used.  This will create device nodes named

    /dev/infiniband/uverbs0

and so on.  Since the RDMA userspace verbs should be safe for use by
non-privileged users, you may want to add an appropriate MODE or GROUP
to your udev rule.

### Permissions

To use IB verbs from userspace, a process must be able to access the
appropriate /dev/infiniband/uverbsN special device file.  You can
check the permissions on this file with the command

	ls -l /dev/infiniband/uverbs*

Make sure that the permissions on these files are such that the
user/group that your verbs program runs as can access the device file.

To use IB verbs from userspace, a process must also have permission to
tell the kernel to lock sufficient memory for all of your registered
memory regions as well as the memory used internally by IB resources
such as queue pairs (QPs) and completion queues (CQs).  To check your
resource limits, use the command

	ulimit -l

(or "limit memorylocked" for csh-like shells).

If you see a small number such as 32 (the units are KB) then you will
need to increase this limit.  This is usually done for ordinary users
via the file /etc/security/limits.conf.  More configuration may be
necessary if you are logging in via OpenSSH and your sshd is
configured to use privilege separation.
