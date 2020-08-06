================
infiniband-diags
================

----------------------------------
Diagnostics for InfiniBand Fabrics
----------------------------------

:Date: 2017-08-21
:Manual section: 8
:Manual group: Open IB Diagnostics

DESCRIPTION
===========

infiniband-diags is a set of utilities designed to help configure, debug, and
maintain infiniband fabrics.  Many tools and utilities are provided.  Some with
similar functionality.

The base utilities use directed route MAD's to perform their operations.  They
may therefore work even in unconfigured subnets.  Other, higher level
utilities, require LID routed MAD's and to some extent SA/SM access.


THE USE OF SMPs (QP0)
=====================

Many of the tools in this package rely on the use of SMPs via QP0 to acquire
data directly from the SMA.  While this mode of operation is not technically in
compliance with the InfiniBand specification, practical experience has found
that this level of diagnostics is valuable when working with a fabric which is
broken or only partially configured.  For this reason many of these tools may
require the use of an MKey or operation from Virtual Machines may be restricted
for security reasons.


COMMON OPTIONS
==============

Most OpenIB diagnostics take some of the following common flags. The exact list
of supported flags per utility can be found in the documentation for those
commands.


Addressing Flags
----------------

The -D and -G option have two forms:

.. include:: common/opt_D.rst
.. include:: common/opt_D_with_param.rst
.. include:: common/opt_G.rst
.. include:: common/opt_G_with_param.rst

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
.. include:: common/opt_o-outstanding_smps.rst
.. include:: common/opt_node_name_map.rst
.. include:: common/opt_z-config.rst



COMMON FILES
============

The following config files are common amongst many of the utilities.

.. include:: common/sec_config-file.rst

.. include:: common/sec_node-name-map.rst
.. include:: common/sec_topology-file.rst



Utilities list
==============

Basic fabric connectivity
-------------------------

	See: ibnetdiscover, iblinkinfo

Node information
----------------

	See: ibnodes, ibswitches, ibhosts, ibrouters

Port information
----------------

	See: ibportstate, ibaddr

Switch Forwarding Table info
----------------------------

	See: ibtracert, ibroute, dump_lfts, dump_mfts, check_lft_balance, ibfindnodesusing

Performance counters
--------------------

	See: ibqueryerrors, perfquery

Local HCA info
--------------

	See: ibstat, ibstatus

Connectivity check
------------------

	See: ibping, ibsysstat

Low level query tools
---------------------

	See: smpquery, smpdump, saquery, sminfo

Fabric verification tools
-------------------------

        See: ibidsverify


Backwards compatibility scripts
===============================

The following scripts have been identified as redundant and/or lower performing
as compared to the above scripts.  They are provided as legacy scripts when
--enable-compat-utils is specified at build time.

ibcheckerrors, ibclearcounters, ibclearerrors, ibdatacounters
ibchecknet, ibchecknode, ibcheckport, ibcheckportstate,
ibcheckportwidth, ibcheckstate, ibcheckwidth, ibswportwatch,
ibprintca, ibprintrt, ibprintswitch, set_nodedesc.sh


AUTHORS
=======

Ira Weiny
        < ira.weiny@intel.com >
