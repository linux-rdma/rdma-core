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

Full operation of this daemon requires kernels which support polling of the
procfs hostname file as well as libudev.

If your system does not support either of these features, the daemon will set
the Node Descriptions at start up and then sleep forever.


Node Description configuration
------------------------------

The daemon uses the environment variable RDMA_NDD_ND_FORMAT to set the node
description.  The following wild cards can be specified for more dynamic
control.

%h -- replace with the current hostname (not including domain)

%d -- replace with the device name (for example mlx4_0, qib0, etc.)

If not specified the default is "%h %d".

NOTE: At startup, and on new device detection, the Node Description is always
written to ensure the SM and rdma-ndd are in sync.  Subsequent events will only
write the Node Description on a device if it has changed.

Using systemd
-------------

Setting the environment variable for the daemon is normally be done via a
systemd drop in unit.  For example the following could be added to a file named
/etc/systemd/system/rdma-ndd.service.d/nd-format.conf to use only the
hostname as your node description.

[Service]
Environment="RDMA_NDD_ND_FORMAT=%%h"

NOTE: Systemd requires an extra '%'.


OPTIONS
=======

**-f, --foreground**
Run in the foreground instead of as a daemon

**-d, --debugging**
Log additional debugging information to syslog

**--systemd**
Enable systemd integration.


AUTHOR
======

Ira Weiny
        < ira.weiny@intel.com >
