=============
IBQUERYERRORS
=============

---------------------------------
query and report IB port counters
---------------------------------

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: OpenIB Diagnostics


SYNOPSIS
========

ibqueryerrors [options]

DESCRIPTION
===========

The default behavior is to report the port error counters which exceed a
threshold for each port in the fabric.  The default threshold is zero (0).
Error fields can also be suppressed entirely.

In addition to reporting errors on every port.  ibqueryerrors can report the
port transmit and receive data as well as report full link information to the
remote port if available.

OPTIONS
=======

**-s, --suppress <err1,err2,...>**
Suppress the errors listed in the comma separated list provided.

**-c, --suppress-common**
Suppress some of the common "side effect" counters.  These counters usually do
not indicate an error condition and can be usually be safely ignored.

**-r, --report-port**
Report the port information.  This includes LID, port, external port (if
applicable), link speed setting, remote GUID, remote port, remote external port
(if applicable), and remote node description information.

**--data**
Include the optional transmit and receive data counters.

**--threshold-file <filename>**
Specify an alternate threshold file.  The default is @IBDIAG_CONFIG_PATH@/error_thresholds

**--switch**  print data for switch's only

**--ca**  print data for CA's only

**--skip-sl**  Use the default sl for queries. This is not recommended when
using a QoS aware routing engine as it can cause a credit deadlock.

**--router**  print data for routers only

**--clear-errors -k** Clear error counters after read.

**--clear-counts -K** Clear data counters after read.

**CAUTION** clearing data or error counters will occur regardless of if they
are printed or not.  See **--counters** and **--data** for details on
controling which counters are printed.

**--details** include receive error and transmit discard details

**--counters** print data counters only


Partial Scan flags
------------------

The node to start a partial scan can be specified with the following addresses.

.. include:: common/opt_G_with_param.rst
.. include:: common/opt_D_with_param.rst

**Note:** For switches results are printed for all ports not just switch port 0.

**-S <port_guid>** same as "-G". (provided only for backward compatibility)


Cache File flags
----------------

.. include:: common/opt_load-cache.rst




Port Selection flags
--------------------

.. include:: common/opt_C.rst
.. include:: common/opt_P.rst
.. include:: common/sec_portselection.rst

Configuration flags
-------------------

.. include:: common/opt_z-config.rst
.. include:: common/opt_o-outstanding_smps.rst
.. include:: common/opt_node_name_map.rst
.. include:: common/opt_t.rst
.. include:: common/opt_y.rst

Debugging flags
---------------

.. include:: common/opt_d.rst
.. include:: common/opt_e.rst
.. include:: common/opt_h.rst
.. include:: common/opt_v.rst
.. include:: common/opt_V.rst

**-R**  (This option is obsolete and does nothing)

EXIT STATUS
===========

**-1** if scan fails.

**0** if scan succeeds without errors beyond thresholds

**1** if errors are found beyond thresholds or inconsistencies are found in check mode.

FILES
=====

ERROR THRESHOLD
---------------

@IBDIAG_CONFIG_PATH@/error_thresholds

Define threshold values for errors.  File format is simple "name=val".
Comments begin with '#'

**Example:**

::

	# Define thresholds for error counters
	SymbolErrorCounter=10
	LinkErrorRecoveryCounter=10
	VL15Dropped=100


.. include:: common/sec_config-file.rst

.. include:: common/sec_node-name-map.rst

AUTHOR
======

Ira Weiny
        < ira.weiny@intel.com >
