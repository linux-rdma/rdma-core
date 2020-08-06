===========
ibcacheedit
===========

---------------------------
edit an ibnetdiscover cache
---------------------------

:Date: 2017-08-21
:Manual section: 8
:Manual group: Open IB Diagnostics

SYNOPSIS
========

ibcacheedit [options] <orig.cache> <new.cache>

DESCRIPTION
===========

ibcacheedit allows users to edit an ibnetdiscover cache created through the
**--cache** option in **ibnetdiscover(8)** .

OPTIONS
=======

**--switchguid BEFOREGUID:AFTERGUID**
        Specify a switchguid that should be changed.  The before and after guid
        should be separated by a colon.  On switches, port guids are identical
        to the switch guid, so port guids will be adjusted as well on switches.

**--caguid BEFOREGUID:AFTERGUID**
        Specify a caguid that should be changed.  The before and after guid
        should be separated by a colon.

**--sysimgguid BEFOREGUID:AFTERGUID**
        Specify a sysimgguid that should be changed.  The before and after guid
        should be spearated by a colon.

**--portguid NODEGUID:BEFOREGUID:AFTERGUID**
        Specify a portguid that should be changed.  The nodeguid of the port
        (e.g. switchguid or caguid) should be specified first, followed by a
        colon, the before port guid, another colon, then the after port guid.
        On switches, port guids are identical to the switch guid, so the switch
        guid will be adjusted as well on switches.

Debugging flags
---------------

.. include:: common/opt_h.rst
.. include:: common/opt_V.rst


AUTHORS
=======

Albert Chu
        < chu11@llnl.gov >
