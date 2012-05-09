.. Explanation of local port selection

Local port Selection
--------------------

Multiple port/Multiple CA support: when no IB device or port is specified
(see the "local umad parameters" below), the libibumad library
selects the port to use by the following criteria:

	1. the first port that is ACTIVE.
	2. if not found, the first port that is UP (physical link up).

	If a port and/or CA name is specified, the libibumad library attempts
	to fulfill the user request, and will fail if it is not possible.

	For example:

        ::

	    ibaddr                 # use the first port (criteria #1 above)
	    ibaddr -C mthca1       # pick the best port from "mthca1" only.
	    ibaddr -P 2            # use the second (active/up) port from the first available IB device.
	    ibaddr -C mthca0 -P 2  # use the specified port only.

