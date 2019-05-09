=======
ibroute
=======

-----------------------------------------
query InfiniBand switch forwarding tables
-----------------------------------------

:Date: 2017-08-21
:Manual section: 8
:Manual group: Open IB Diagnostics

SYNOPSIS
========

ibroute [options] [<dest dr_path|lid|guid> [<startlid> [<endlid>]]]

DESCRIPTION
===========

ibroute uses SMPs to display the forwarding tables (unicast
(LinearForwardingTable or LFT) or multicast (MulticastForwardingTable or MFT))
for the specified switch LID and the optional lid (mlid) range.
The default range is all valid entries in the range 1...FDBTop.

OPTIONS
=======

**-a, --all**
        show all lids in range, even invalid entries

**-n, --no_dests**
        do not try to resolve destinations

**-M, --Multicast**
        show multicast forwarding tables
        In this case, the range parameters are specifying the mlid range.


Addressing Flags
----------------

.. include:: common/opt_D.rst
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
.. include:: common/opt_node_name_map.rst
.. include:: common/opt_z-config.rst

FILES
=====

.. include:: common/sec_config-file.rst

.. include:: common/sec_node-name-map.rst

EXAMPLES
========

Unicast examples

::
        ibroute 4               # dump all lids with valid out ports of switch with lid 4
        ibroute -a 4            # same, but dump all lids, even with invalid out ports
        ibroute -n 4            # simple dump format - no destination resolution
        ibroute 4 10            # dump lids starting from 10 (up to FDBTop)
        ibroute 4 0x10 0x20     # dump lid range
        ibroute -G 0x08f1040023 # resolve switch by GUID
        ibroute -D 0,1          # resolve switch by direct path

Multicast examples

::
        ibroute -M 4                # dump all non empty mlids of switch with lid 4
        ibroute -M 4 0xc010 0xc020  # same, but with range
        ibroute -M -n 4             # simple dump format

SEE ALSO
========

ibtracert (8)

AUTHOR
======

Hal Rosenstock
        < halr@voltaire.com >
