======
IBSTAT
======

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: Open IB Diagnostics

------------------------------------------
query basic status of InfiniBand device(s)
------------------------------------------


SYNOPSIS
========

ibstat [options] <ca_name> [portnum]

DESCRIPTION
===========

ibstat is a binary which displays basic information obtained from the local
IB driver. Output includes LID, SMLID, port state, link width active, and port
physical state.

It is similar to the ibstatus utility but implemented as a binary rather
than a script. It has options to list CAs and/or ports and displays more
information than ibstatus.

OPTIONS
=======

**-l, --list_of_cas**
        list all IB devices

**-s, --short**
        short output

**-p, --port_list**
        show port list

**ca_name**
        InfiniBand device name

**portnum**
        port number of InfiniBand device



Debugging flags
---------------

.. include:: common/opt_d.rst
.. include:: common/opt_h.rst
.. include:: common/opt_v.rst
.. include:: common/opt_V.rst


Configuration flags
-------------------

.. include:: common/opt_z-config.rst



EXAMPLES
========

::
        ibstat            # display status of all ports on all IB devices
        ibstat -l         # list all IB devices
        ibstat -p         # show port guids
        ibstat mthca0 2   # show status of port 2 of 'mthca0'

SEE ALSO
========
ibstatus (8)

AUTHOR
======

Hal Rosenstock
        < halr@voltaire.com >
