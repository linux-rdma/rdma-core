=================
check_lft_balance
=================

--------------------------------------------------
check InfiniBand unicast forwarding tables balance
--------------------------------------------------

:Date: 2017-08-21
:Manual section: 8
:Manual group: Open IB Diagnostics

SYNOPSIS
========

check_lft_balance.sh [-hRv]


DESCRIPTION
===========

check_lft_balance.sh is a script which checks for balancing in Infiniband
unicast forwarding tables.  It analyzes the output of
**dump_lfts(8)** and **iblinkinfo(8)**

OPTIONS
=======

**-h**
        show help

**-R**
        Recalculate dump_lfts information, ie do not use the cached
        information.  This option is slower but should be used if the diag
        tools have not been used for some time or if there are other reasons to
        believe that the fabric has changed.

**-v**
        verbose output

SEE ALSO
========

**dump_lfts(8)**
**iblinkinfo(8)**

AUTHORS
=======

Albert Chu
        < chu11@llnl.gov >
