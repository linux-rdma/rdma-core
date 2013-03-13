================
IBFINDNODESUSING
================

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: Open IB Diagnostics

-------------------------------------------------------------------------------
find a list of end nodes which are routed through the specified switch and port
-------------------------------------------------------------------------------


SYNOPSIS
========

ibfindnodesusing.pl [options] <switch_guid|switch_name> <port>

DESCRIPTION
===========

ibfindnodesusing.pl uses ibroute and detects the current nodes which are routed
through both directions of the link specified.  The link is specified by one
switch port end; the script finds the remote end automatically.


OPTIONS
=======

**-h**
        show help

**-R**
        Recalculate the ibnetdiscover information, ie do not use the cached
        information.  This option is slower but should be used if the diag
        tools have not been used for some time or if there are other reasons to
        believe that the fabric has changed.

**-C <ca_name>**    use the specified ca_name.

**-P <ca_port>**    use the specified ca_port.


FILES
=====

.. include:: common/sec_config-file.rst
.. include:: common/sec_node-name-map.rst

AUTHOR
======

Ira Weiny
        < ira.weiny@intel.com >
