[![Build Status](https://dev.azure.com/ucfconsort/rdma-core/_apis/build/status/linux-rdma.rdma-core?branchName=master)](https://dev.azure.com/ucfconsort/rdma-core/_build/latest?definitionId=2&branchName=master)

# RDMA Core Userspace Libraries and Daemons

This is the userspace components for the Linux Kernel's drivers/infiniband
subsystem. Specifically this contains the userspace libraries for the
following device nodes:

 - /dev/infiniband/uverbsX (libibverbs)
 - /dev/infiniband/rdma_cm (librdmacm)
 - /dev/infiniband/umadX (libibumad)

The userspace component of the libibverbs RDMA kernel drivers are included
under the providers/ directory. Support for the following Kernel RDMA drivers
is included:

 - efa.ko
 - iw_cxgb4.ko
 - hfi1.ko
 - hns-roce.ko
 - i40iw.ko
 - ib_qib.ko
 - mlx4_ib.ko
 - mlx5_ib.ko
 - ib_mthca.ko
 - ocrdma.ko
 - qedr.ko
 - rdma_rxe.ko
 - siw.ko
 - vmw_pvrdma.ko

Additional service daemons are provided for:
 - srp_daemon (ib_srp.ko)
 - iwpmd (for iwarp kernel providers)
 - ibacm (for InfiniBand communication management assistant)

# Building

This project uses a cmake based build system. Quick start:

```sh
$ bash build.sh
```

*build/bin* will contain the sample programs and *build/lib* will contain the
shared libraries. The build is configured to run all the programs 'in-place'
and cannot be installed.

NOTE: It is not currently easy to run from the build directory, the plugins
only load from the system path.

### Debian Derived

```sh
$ apt-get install build-essential cmake gcc libudev-dev libnl-3-dev libnl-route-3-dev ninja-build pkg-config valgrind python3-dev cython3 python3-docutils pandoc
```

### Fedora

```sh
$ dnf install cmake gcc libnl3-devel libudev-devel pkgconfig valgrind-devel ninja-build python3-devel python3-Cython python3-docutils pandoc
```

NOTE: Fedora Core uses the name 'ninja-build' for the 'ninja' command.

### openSUSE

```sh
$ zypper install cmake gcc libnl3-devel libudev-devel ninja pkg-config valgrind-devel python3-devel python3-Cython python3-docutils pandoc
```

## Building on CentOS 6/7, Amazon Linux 1/2

Install required packages:

```sh
$ yum install cmake gcc libnl3-devel libudev-devel make pkgconfig valgrind-devel
```

Developers on CentOS 7 or Amazon Linux 2 are suggested to install more modern
tooling for the best experience.

CentOS 7:

```sh
$ yum install epel-release
$ yum install cmake3 ninja-build pandoc
```

Amazon Linux 2:

```sh
$ amazon-linux-extras install epel
$ yum install cmake3 ninja-build pandoc
```

NOTE: EPEL uses the name 'ninja-build' for the 'ninja' command, and 'cmake3'
for the 'cmake' command.

# Usage

To set up software RDMA on an existing interface with either of the available
drivers, use the following commands, substituting `<DRIVER>` with the name of
the driver of your choice (`rdma_rxe` or `siw`) and `<TYPE>` with the type
corresponding to the driver (`rxe` or `siw`).

```
# modprobe <DRIVER>
# rdma link add <NAME> type <TYPE> netdev <DEVICE>
```

Please note that you need version of `iproute2` recent enough is required for the
command above to work.

You can use either `ibv_devices` or `rdma link` to verify that the device was
successfully added.

# Reporting bugs

Bugs should be reported to the <linux-rdma@vger.kernel.org> mailing list
In your bug report, please include:

 * Information about your system:
   - Linux distribution and version
   - Linux kernel and version
   - InfiniBand hardware and firmware version
   - ... any other relevant information

 * How to reproduce the bug.

 * If the bug is a crash, the exact output printed out when the crash
   occurred, including any kernel messages produced.

# Submitting patches

Patches should also be submitted to the <linux-rdma@vger.kernel.org>
mailing list.  Please use unified diff form (the -u option to GNU diff),
and include a good description of what your patch does and why it should
be applied.  If your patch fixes a bug, please make sure to describe the
bug and how your fix works.

Make sure that your contribution can be licensed under the same
license as the original code you are patching, and that you have all
necessary permissions to release your work.

## Azure Pipelines CI

Submitted patches must pass the Azure Pipelines CI automatic builds without
warnings.  A build similar to AZP can be run locally using docker and the
'buildlib/cbuild' script.

```sh
$ buildlib/cbuild build-images azp
$ buildlib/cbuild pkg azp
```
