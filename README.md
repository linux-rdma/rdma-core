[![Build Status](https://travis-ci.org/linux-rdma/rdma-core.svg?branch=master)](https://travis-ci.org/linux-rdma/rdma-core)

# RDMA Core Userspace Libraries and Daemons

This is the userspace components for the Linux Kernel's drivers/infiniband
subsystem. Specifically this contains the userspace libraries for the
following device nodes:

 - /dev/infiniband/uverbsX (libibverbs)
 - /dev/infiniband/rdma_cm (librdmacm)
 - /dev/infiniband/umadX (libibumad)
 - /dev/infiniband/ucmX (libibcm, deprecated)

The userspace component of the libibverbs RDMA kernel drivers are included
under the providers/ directory. Support for the following Kernel RDMA drivers
is included:

 - iw_cxgb3.ko
 - iw_cxgb4.ko
 - hfi1.ko
 - i40iw.ko
 - ib_qib.ko
 - mlx4_ib.ko
 - mlx5_ib.ko
 - ib_mthca.ko
 - iw_nes.ko
 - ocrdma.ko
 - qedr.ko
 - rdma_rxe.ko

Additional service daemons are provided for:
 - srp_daemon (ib_srp.ko)
 - iwpmd (for iwarp kernel providers)

# Building

This project uses a cmake based build system. Quick start:

```sh
$ bash build.sh
```

*build/bin* will contain the sample programs and *build/lib* will contain the
shared libraries.

NOTE: It is not currently easy to run from the build directory, the plugins
only load from the system path.

### Debian Derived

```sh
$ apt-get install build-essential cmake gcc libudev-dev libnl-3-dev libnl-route-3-dev ninja-build pkg-config valgrind
```

### Fedora

```sh
$ dnf install cmake gcc libnl3-devel systemd-devel pkgconfig valgrind-devel ninja-build
```

NOTE: Fedora Core uses the name 'ninja-build' for the ninja command.

### OpenSuSE

```sh
$ zypper install cmake gcc libnl3-devel ninja pkg-config valgrind-devel
```

## Building on CentOS 6/7

Install required packages:

```sh
$ yum install cmake gcc libnl3-devel make pkgconfig valgrind-devel
```

Developers are suggested to install more modern tooling for the best experience.

```sh
$ yum install epel-release
$ yum install cmake3 unzip
$ curl -OL https://github.com/ninja-build/ninja/releases/download/v1.7.1/ninja-linux.zip
$ unzip ninja-linux.zip
$ install -m755 ninja /usr/local/bin/ninja
```

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
