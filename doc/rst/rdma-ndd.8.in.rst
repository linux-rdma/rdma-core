========
RDMA-NDD
========

------------------------------------------
RDMA device Node Description update daemon
------------------------------------------

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: OpenIB Diagnostics


SYNOPSIS
========

rdma-ndd <options>

DESCRIPTION
===========

rdma-ndd is a system daemon which watches for rdma device changes and/or
hostname changes and updates the Node Description of the rdma devices based on
those changes.


DETAILS
=======

Full operation of this deamon requires kernels which support polling of the
procfs hostname file as well as libudev.

If your system does not support either of these features, the daemon will set
the Node Descriptions at start up and then sleep forever.


Node Description format
-----------------------

The deamon uses the nd_format configuration option within the ibdiags.conf
file.  %h and %d can be used as wildcards in that string to specify the dynamic
use of <hostname> and <device> respectively.

NOTE: At startup and on new device detection the Node Description is always
written to ensure the SM and this daemon are in sync.  Subsequent events will
only write the Node Description on a device if it has changed.


OPTIONS
=======

**--retry_timer, -t**
Length of time to sleep when system errors occur when attempting to poll and or read the hostname from the system.

**--retry_count, -r**
Number of times to attempt to retry setting of the node description on failure.  Default 0

**--foreground, -f**
Run in the foreground instead of as a daemon

**--pidfile <pidfile>**
specify a pid file (daemon mode only)


Configuration flags
-------------------

.. include:: common/opt_z-config.rst

Debugging flags
---------------

.. include:: common/opt_h.rst
.. include:: common/opt_V.rst



FILES
=====

.. include:: common/sec_config-file.rst


AUTHOR
======

Ira Weiny
        < ira.weiny@intel.com >
