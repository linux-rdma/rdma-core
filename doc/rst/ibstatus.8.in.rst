========
IBSTATUS
========

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: Open IB Diagnostics

------------------------------------------
query basic status of InfiniBand device(s)
------------------------------------------


SYNOPSIS
========

ibstatus [\-h] [devname[:port]]...

DESCRIPTION
===========

ibstatus is a script which displays basic information obtained from the local
IB driver. Output includes LID, SMLID, port state, link width active, and port
physical state.

OPTIONS
=======

.. include:: common/opt_h.rst

**devname**
        InfiniBand device name

**portnum**
        port number of InfiniBand device

EXAMPLES
========

::
        ibstatus                    # display status of all IB ports
        ibstatus mthca1             # status of mthca1 ports
        ibstatus mthca1:1 mthca0:2  # show status of specified ports

SEE ALSO
========

**ibstat (8)**

AUTHOR
======

Hal Rosenstock
        < halr@voltaire.com >
