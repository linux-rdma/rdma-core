.. Common text to describe the Topology file.

TOPOLOGY FILE FORMAT
--------------------

The topology file format is human readable and largely intuitive.
Most identifiers are given textual names like vendor ID (vendid), device ID
(device ID), GUIDs of various types (sysimgguid, caguid, switchguid, etc.).
PortGUIDs are shown in parentheses ().  For switches, this is shown on the
switchguid line.  For CA and router ports, it is shown on the connectivity
lines.  The IB node is identified followed by the number of ports and a quoted
the node GUID.  On the right of this line is a comment (#) followed by the
NodeDescription in quotes.  If the node is a switch, this line also contains
whether switch port 0 is base or enhanced, and the LID and LMC of port 0.
Subsequent lines pertaining to this node show the connectivity.   On the
left is the port number of the current node.  On the right is the peer node
(node at other end of link). It is identified in quotes with nodetype
followed by - followed by NodeGUID with the port number in square brackets.
Further on the right is a comment (#).  What follows the comment is
dependent on the node type.  If it it a switch node, it is followed by
the NodeDescription in quotes and the LID of the peer node.  If it is a
CA or router node, it is followed by the local LID and LMC and then
followed by the NodeDescription in quotes and the LID of the peer node.
The active link width and speed are then appended to the end of this
output line.

An example of this is:

::

   #
   # Topology file: generated on Tue Jun  5 14:15:10 2007
   #
   # Max of 3 hops discovered
   # Initiated from node 0008f10403960558 port 0008f10403960559
   
   Non-Chassis Nodes
   
   vendid=0x8f1
   devid=0x5a06
   sysimgguid=0x5442ba00003000
   switchguid=0x5442ba00003080(5442ba00003080)
   Switch  24 "S-005442ba00003080"         # "ISR9024 Voltaire" base port 0 lid 6 lmc 0
   [22]    "H-0008f10403961354"[1](8f10403961355)         # "MT23108 InfiniHost Mellanox Technologies" lid 4 4xSDR
   [10]    "S-0008f10400410015"[1]         # "SW-6IB4 Voltaire" lid 3 4xSDR
   [8]     "H-0008f10403960558"[2](8f1040396055a)         # "MT23108 InfiniHost Mellanox Technologies" lid 14 4xSDR
   [6]     "S-0008f10400410015"[3]         # "SW-6IB4 Voltaire" lid 3 4xSDR
   [12]    "H-0008f10403960558"[1](8f10403960559)         # "MT23108 InfiniHost Mellanox Technologies" lid 10 4xSDR
   
   vendid=0x8f1
   devid=0x5a05
   switchguid=0x8f10400410015(8f10400410015)
   Switch  8 "S-0008f10400410015"          # "SW-6IB4 Voltaire" base port 0 lid 3 lmc 0
   [6]     "H-0008f10403960984"[1](8f10403960985)         # "MT23108 InfiniHost Mellanox Technologies" lid 16 4xSDR
   [4]     "H-005442b100004900"[1](5442b100004901)        # "MT23108 InfiniHost Mellanox Technologies" lid 12 4xSDR
   [1]     "S-005442ba00003080"[10]                # "ISR9024 Voltaire" lid 6 1xSDR
   [3]     "S-005442ba00003080"[6]         # "ISR9024 Voltaire" lid 6 4xSDR
   
   vendid=0x2c9
   devid=0x5a44
   caguid=0x8f10403960984
   Ca      2 "H-0008f10403960984"          # "MT23108 InfiniHost Mellanox Technologies"
   [1](8f10403960985)     "S-0008f10400410015"[6]         # lid 16 lmc 1 "SW-6IB4 Voltaire" lid 3 4xSDR
   
   vendid=0x2c9
   devid=0x5a44
   caguid=0x5442b100004900
   Ca      2 "H-005442b100004900"          # "MT23108 InfiniHost Mellanox Technologies"
   [1](5442b100004901)     "S-0008f10400410015"[4]         # lid 12 lmc 1 "SW-6IB4 Voltaire" lid 3 4xSDR
   
   vendid=0x2c9
   devid=0x5a44
   caguid=0x8f10403961354
   Ca      2 "H-0008f10403961354"          # "MT23108 InfiniHost Mellanox Technologies"
   [1](8f10403961355)     "S-005442ba00003080"[22]                # lid 4 lmc 1 "ISR9024 Voltaire" lid 6 4xSDR
   
   vendid=0x2c9
   devid=0x5a44
   caguid=0x8f10403960558
   Ca      2 "H-0008f10403960558"          # "MT23108 InfiniHost Mellanox Technologies"
   [2](8f1040396055a)     "S-005442ba00003080"[8]         # lid 14 lmc 1 "ISR9024 Voltaire" lid 6 4xSDR
   [1](8f10403960559)     "S-005442ba00003080"[12]                # lid 10 lmc 1 "ISR9024 Voltaire" lid 6 1xSDR


When grouping is used, IB nodes are organized into chassis which are
numbered. Nodes which cannot be determined to be in a chassis are
displayed as "Non-Chassis Nodes".  External ports are also shown on the
connectivity lines.

