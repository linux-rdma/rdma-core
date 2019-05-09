=======
saquery
=======

-------------------------------------------------
query InfiniBand subnet administration attributes
-------------------------------------------------

:Date: 2017-08-21
:Manual section: 8
:Manual group: Open IB Diagnostics

SYNOPSIS
========

saquery [options] [<name> | <lid> | <guid>]

DESCRIPTION
===========

saquery issues the selected SA query. Node records are queried by default.

OPTIONS
=======

**-p**
        get PathRecord info

**-N**
        get NodeRecord info

**-D, --list**
        get NodeDescriptions of CAs only

**-S**
        get ServiceRecord info

**-I**
        get InformInfoRecord (subscription) info

**-L**
        return the Lids of the name specified

**-l**
        return the unique Lid of the name specified

**-G**
        return the Guids of the name specified

**-O**
        return the name for the Lid specified

**-U**
        return the name for the Guid specified

**-c**
        get the SA's class port info

**-s**
        return the PortInfoRecords with isSM or isSMdisabled capability mask bit on

**-g**
        get multicast group info

**-m**
        get multicast member info.  If a group is specified, limit the output
        to the group specified and print one line containing only the GUID and
        node description for each entry. Example: saquery -m 0xc000

**-x**
        get LinkRecord info

**--src-to-dst <src:dst>**
        get a PathRecord for <src:dst>
        where src and dst are either node names or LIDs

**--sgid-to-dgid <sgid:dgid>**
        get a PathRecord for **sgid** to **dgid**
        where both GIDs are in an IPv6 format acceptable to **inet_pton (3)**

**--smkey <val>**
        use SM_Key value for the query. Will be used only with "trusted"
        queries.  If non-numeric value (like 'x') is specified then saquery
	will prompt for a value.
	Default (when not specified here or in
	@IBDIAG_CONFIG_PATH@/ibdiag.conf) is to use SM_Key == 0 (or
	\"untrusted\")

.. include:: common/opt_K.rst

**--slid <lid>** Source LID (PathRecord)

**--dlid <lid>** Destination LID (PathRecord)

**--mlid <lid>** Multicast LID (MCMemberRecord)

**--sgid <gid>** Source GID (IPv6 format) (PathRecord)

**--dgid <gid>** Destination GID (IPv6 format) (PathRecord)

**--gid <gid>** Port GID (MCMemberRecord)

**--mgid <gid>** Multicast GID (MCMemberRecord)

**--reversible** Reversible path (PathRecord)

**--numb_path** Number of paths (PathRecord)

**--pkey** P_Key (PathRecord, MCMemberRecord). If non-numeric value (like 'x')
        is specified then saquery will prompt for a value

**--qos_class** QoS Class (PathRecord)

**--sl** Service level (PathRecord, MCMemberRecord)

**--mtu** MTU and selector (PathRecord, MCMemberRecord)

**--rate** Rate and selector (PathRecord, MCMemberRecord)

**--pkt_lifetime** Packet lifetime and selector (PathRecord, MCMemberRecord)

**--qkey** Q_Key (MCMemberRecord). If non-numeric value (like 'x') is specified
        then saquery will prompt for a value

**--tclass** Traffic Class (PathRecord, MCMemberRecord)

**--flow_label** Flow Label (PathRecord, MCMemberRecord)

**--hop_limit** Hop limit (PathRecord, MCMemberRecord)

**--scope** Scope (MCMemberRecord)

**--join_state** Join state (MCMemberRecord)

**--proxy_join** Proxy join (MCMemberRecord)

**--service_id** ServiceID (PathRecord)

Supported query names (and aliases):

::

        ClassPortInfo (CPI)
        NodeRecord (NR) [lid]
        PortInfoRecord (PIR) [[lid]/[port]/[options]]
        SL2VLTableRecord (SL2VL) [[lid]/[in_port]/[out_port]]
        PKeyTableRecord (PKTR) [[lid]/[port]/[block]]
        VLArbitrationTableRecord (VLAR) [[lid]/[port]/[block]]
        InformInfoRecord (IIR)
        LinkRecord (LR) [[from_lid]/[from_port]] [[to_lid]/[to_port]]
        ServiceRecord (SR)
        PathRecord (PR)
        MCMemberRecord (MCMR)
        LFTRecord (LFTR) [[lid]/[block]]
        MFTRecord (MFTR) [[mlid]/[position]/[block]]
        GUIDInfoRecord (GIR) [[lid]/[block]]
        SwitchInfoRecord (SWIR) [lid]
        SMInfoRecord (SMIR) [lid]



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

.. include:: common/sec_config-file.rst

.. include:: common/sec_node-name-map.rst



DEPENDENCIES
============

OpenSM (or other running SM/SA), libosmcomp, libibumad, libibmad

AUTHORS
=======

Ira Weiny
        < ira.weiny@intel.com >

Hal Rosenstock
        < halr@mellanox.com >
