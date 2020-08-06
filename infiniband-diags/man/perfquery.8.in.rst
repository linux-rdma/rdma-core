=========
perfquery
=========

-----------------------------------------------
query InfiniBand port counters on a single port
-----------------------------------------------

:Date: 2017-08-21
:Manual section: 8
:Manual group: Open IB Diagnostics

SYNOPSIS
========

perfquery [options] [<lid|guid> [[port(s)] [reset_mask]]]

DESCRIPTION
===========

perfquery uses PerfMgt GMPs to obtain the PortCounters (basic performance and
error counters), PortExtendedCounters, PortXmitDataSL, PortRcvDataSL,
PortRcvErrorDetails, PortXmitDiscardDetails, PortExtendedSpeedsCounters, or
PortSamplesControl from the PMA at the node/port specified. Optionally shows
aggregated counters for all ports of node.  Finally it can, reset after read,
or just reset the counters.

Note: In PortCounters, PortCountersExtended, PortXmitDataSL, and PortRcvDataSL,
components that represent Data (e.g. PortXmitData and PortRcvData) indicate
octets divided by 4 rather than just octets.

Note: Inputting a port of 255 indicates an operation be performed on all ports.

Note: For PortCounters, ExtendedCounters, and resets, multiple ports can be
specified by either a comma separated list or a port range.  See examples below.


OPTIONS
=======

**-x, --extended**
	show extended port counters rather than (basic) port counters.
	Note that extended port counters attribute is optional.

**-X, --xmtsl**
	show transmit data SL counter. This is an optional counter for QoS.

**-S, --rcvsl**
	show receive data SL counter. This is an optional counter for QoS.

**-D, --xmtdisc**
	show transmit discard details. This is an optional counter.

**-E, --rcverr**
	show receive error details. This is an optional counter.

**-D, --xmtdisc**
	show transmit discard details. This is an optional counter.

**-T, --extended_speeds**
	show extended speeds port counters. This is an optional counter.

**--oprcvcounters**
	show Rcv Counters per Op code. This is an optional counter.

**--flowctlcounters**
	show flow control counters. This is an optional counter.

**--vloppackets**
	show packets received per Op code per VL. This is an optional counter.

**--vlopdata**
	show data received per Op code per VL. This is an optional counter.

**--vlxmitflowctlerrors**
	show flow control update errors per VL. This is an optional counter.

**--vlxmitcounters**
	show ticks waiting to transmit counters per VL. This is an optional counter.

**--swportvlcong**
	show sw port VL congestion. This is an optional counter.

**--rcvcc**
	show Rcv congestion control counters. This is an optional counter.

**--slrcvfecn**
	show SL Rcv FECN counters. This is an optional counter.

**--slrcvbecn**
	show SL Rcv BECN counters. This is an optional counter.

**--xmitcc**
	show Xmit congestion control counters. This is an optional counter.

**--vlxmittimecc**
	show VL Xmit Time congestion control counters. This is an optional counter.

**-c, --smplctl**
	show port samples control.

**-a, --all_ports**
	show aggregated counters for all ports of the destination lid, reset
	all counters for all ports, or if multiple ports are specified, aggregate
	the counters of the specified ports.  If the destination lid does not support
	the AllPortSelect flag, all ports will be iterated through to emulate
	AllPortSelect behavior.

**-l, --loop_ports**
	If all ports are selected by the user (either through the **-a** option
	or port 255) or multiple ports are specified iterate through each port rather
	than doing than aggregate operation.

**-r, --reset_after_read**
	reset counters after read

**-R, --Reset_only**
	only reset counters


Addressing Flags
----------------

.. include:: common/opt_G.rst
.. include:: common/opt_L.rst
.. include:: common/opt_s.rst


Port Selection flags
--------------------

.. include:: common/opt_C.rst
.. include:: common/opt_P.rst
.. include:: common/sec_portselection.rst


Debugging flags
---------------

.. include:: common/opt_d.rst
.. include:: common/opt_e.rst
.. include:: common/opt_h.rst
.. include:: common/opt_v.rst
.. include:: common/opt_V.rst


Configuration flags
-------------------

.. include:: common/opt_t.rst
.. include:: common/opt_y.rst
.. include:: common/opt_z-config.rst


FILES
=====

.. include:: common/sec_config-file.rst

EXAMPLES
========

::

	perfquery                # read local port performance counters
	perfquery 32 1           # read performance counters from lid 32, port 1
	perfquery -x 32 1        # read extended performance counters from lid 32, port 1
	perfquery -a 32          # read perf counters from lid 32, all ports
	perfquery -r 32 1        # read performance counters and reset
	perfquery -x -r 32 1     # read extended performance counters and reset
	perfquery -R 0x20 1      # reset performance counters of port 1 only
	perfquery -x -R 0x20 1   # reset extended performance counters of port 1 only
	perfquery -R -a 32       # reset performance counters of all ports
	perfquery -R 32 2 0x0fff # reset only error counters of port 2
	perfquery -R 32 2 0xf000 # reset only non-error counters of port 2
	perfquery -a 32 1-10     # read performance counters from lid 32, port 1-10, aggregate output
	perfquery -l 32 1-10     # read performance counters from lid 32, port 1-10, output each port
	perfquery -a 32 1,4,8    # read performance counters from lid 32, port 1, 4, and 8, aggregate output
	perfquery -l 32 1,4,8    # read performance counters from lid 32, port 1, 4, and 8, output each port

AUTHOR
======

Hal Rosenstock
	< hal.rosenstock@gmail.com >
