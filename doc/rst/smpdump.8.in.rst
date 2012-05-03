=======
SMPDUMP
=======

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: Open IB Diagnostics

--------------------------------------------
dump InfiniBand subnet management attributes
--------------------------------------------


SYNOPSIS
========

smpdump [options] <dlid|dr_path> <attribute> [attribute_modifier]

DESCRIPTION
===========

smpdump is a general purpose SMP utility which gets SM attributes from a
specified SMA. The result is dumped in hex by default.

OPTIONS
=======

**dlid|drpath**
        LID or DR path to SMA

**attribute**
        IBA attribute ID for SM attribute

**attribute_modifier**
        IBA modifier for SM attribute

**-s, --string**
        Print strings in packet if possible


Addressing Flags
----------------

.. include:: common/opt_D.rst
.. include:: common/opt_L.rst


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
.. include:: common/opt_z-config.rst


FILES
=====

.. include:: common/sec_config-file.rst


EXAMPLES
========

Direct Routed Examples

::
        smpdump -D 0,1,2,3,5 16 # NODE DESC
        smpdump -D 0,1,2 0x15 2 # PORT INFO, port 2

LID Routed Examples

::
        smpdump 3 0x15 2        # PORT INFO, lid 3 port 2
        smpdump 0xa0 0x11       # NODE INFO, lid 0xa0

SEE ALSO
========

smpquery (8)


AUTHOR
======

Hal Rosenstock
        < halr@voltaire.com >
