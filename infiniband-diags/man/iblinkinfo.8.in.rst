==========
IBLINKINFO
==========

--------------------------------------------
report link info for all links in the fabric
--------------------------------------------

:Date: 2018-07-09
:Manual section: 8
:Manual group: OpenIB Diagnostics


SYNOPSIS
========

iblinkinfo <options>

DESCRIPTION
===========

iblinkinfo reports link info for each port in an IB fabric, node by node.
Optionally, iblinkinfo can do partial scans and limit its output to parts of a
fabric.

OPTIONS
=======

**--down, -d**
Print only nodes which have a port in the "Down" state.

**--line, -l**
Print all information for each link on one line. Default is to print a header
with the node information and then a list for each port (useful for
grep'ing output).


**--additional, -p**
Print additional port settings (<LifeTime>,<HoqLife>,<VLStallCount>)

**--switches-only**
Show only switches in output.

**--cas-only**
Show only CAs in output.


Partial Scan flags
------------------

The node to start a partial scan can be specified with the following addresses.

.. include:: common/opt_G_with_param.rst
.. include:: common/opt_D_with_param.rst

**Note:** For switches results are printed for all ports not just switch port 0.

**--switch, -S <port_guid>** same as "-G". (provided only for backward compatibility)

How much of the scan to be printed can be controlled with the following.

**--all, -a**
Print all nodes found in a partial fabric scan.  Normally a
partial fabric scan will return only the node specified.  This option will
print the other nodes found as well.

**--hops, -n <hops>**
Specify the number of hops away from a specified node to scan.  This is useful
to expand a partial fabric scan beyond the node specified.


Cache File flags
----------------

.. include:: common/opt_load-cache.rst
.. include:: common/opt_diff.rst

**--diffcheck <key(s)>**
Specify what diff checks should be done in the **--diff** option above.  Comma
separate multiple diff check key(s).  The available diff checks are: **port** =
port connections, **state** = port state, **lid** = lids, **nodedesc** = node
descriptions.  Note that **port**, **lid**, and **nodedesc** are checked only
for the node types that are specified (e.g.  **switches-only**, **cas-only**).
If **port** is specified alongside **lid** or **nodedesc**, remote port lids
and node descriptions will also be compared.


**--filterdownports <filename>**
Filter downports indicated in a ibnetdiscover cache.  If a port was previously
indicated as down in the specified cache, and is still down, do not output it in the
resulting output.  This option may be particularly useful for environments
where switches are not fully populated, thus much of the default iblinkinfo
info is considered useless.  See **ibnetdiscover** for information on caching
ibnetdiscover output.


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

.. include:: common/opt_e.rst
.. include:: common/opt_h.rst
.. include:: common/opt_v.rst
.. include:: common/opt_V.rst

EXIT STATUS
===========

0 on success, -1 on failure to scan the fabric, 1 if check mode is used and
inconsistencies are found.

FILES
=====

.. include:: common/sec_config-file.rst

.. include:: common/sec_node-name-map.rst


AUTHOR
======

Ira Weiny
        < ira.weiny@intel.com >
