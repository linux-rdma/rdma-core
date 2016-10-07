# The Assistant for InfiniBand Communication Management (IB ACM)

The IB ACM library implements and provides a framework for name, address, and
route resolution services over InfiniBand.  The IB ACM provides information
needed to establish a connection, but does not implement the CM protocol.

IB ACM services are used by librdmacm to implement the rdma_resolve_addr,
rdma_resolve_route, and rdma_getaddrinfo routines.

The IB ACM is focused on being scalable and efficient.  The current
implementation limits network traffic, SA interactions, and centralized
services.  ACM supports multiple resolution protocols in order to handle
different fabric topologies.

This release is limited in its handling of dynamic changes.

The IB ACM package is comprised of two components: the ibacm service
and a test/configuration utility - ib_acme.

# Details

### ib_acme

The ib_acme program serves a dual role.  It acts as a utility to test
ibacm operation and help verify if the ibacm service and selected
protocol is usable for a given cluster configuration.   Additionally,
it automatically generates ibacm configuration files to assist with
or eliminate manual setup.


### acm configuration files

The ibacm service relies on two configuration files.

The acm_addr.cfg file contains name and address mappings for each IB
<device, port, pkey> endpoint.  Although the names in the acm_addr.cfg
file can be anything, ib_acme maps the host name and IP addresses to
the IB endpoints.

The acm_opts.cfg file provides a set of configurable options for the
ibacm service, such as timeout, number of retries, logging level, etc.
ib_acme generates the acm_opts.cfg file using static information.  A
future enhancement would adjust options based on the current system
and cluster size.

### ibacm

The ibacm service is responsible for resolving names and addresses to
InfiniBand path information and caching such data. It is implemented as a
daemon that execute with administrative privileges.

The ibacm implements a client interface over TCP sockets, which is
abstracted by the librdmacm library.  One or more back-end protocols are
used by the ibacm service to satisfy user requests.  Although the
ibacm supports standard SA path record queries on the back-end, it
provides an experimental multicast resolution protocol in hope of
achieving greater scalability.  The latter is not usable on all fabric
topologies, specifically ones that may not have reversible paths.
Users should use the ib_acme utility to verify that multicast protocol
is usable before running other applications.

Conceptually, the ibacm service implements an ARP like protocol and either
uses IB multicast records to construct path record data or queries the
SA directly, depending on the selected route protocol.  By default, the
ibacm services uses and caches SA path record queries.

Specifically, all IB endpoints join a number of multicast groups.
Multicast groups differ based on rates, mtu, sl, etc., and are prioritized.
All participating endpoints must be able to communicate on the lowest
priority multicast group.  The ibacm assigns one or more names/addresses
to each IB endpoint using the acm_addr.cfg file.  Clients provide source
and destination names or addresses as input to the service, and receive
as output path record data.

The service maps a client's source name/address to a local IB endpoint.
If a client does not provide a source address, then the ibacm service
will select one based on the destination and local routing tables.  If the
destination name/address is not cached locally, it sends a multicast
request out on the lowest priority multicast group on the local endpoint.
The request carries a list of multicast groups that the sender can use.
The recipient of the request selects the highest priority multicast group
that it can use as well and returns that information directly to the sender.
The request data is cached by all endpoints that receive the multicast
request message.  The source endpoint also caches the response and uses
the multicast group that was selected to construct or obtain path record
data, which is returned to the client.

The current implementation of the IB ACM has several additional restrictions:
- The ibacm is limited in its handling of dynamic changes;
  the ibacm should be stopped and restarted if a cluster is reconfigured.
- Support for IPv6 has not been verified.
- The number of addresses that can be assigned to a single endpoint is
  limited to 4.
- The number of multicast groups that an endpoint can support is limited to 2.

The ibacm contains several internal caches.  These include  caches  for
GID  and  LID  destination  addresses.   These caches can be optionally
preloaded.  ibacm supports the OpenSM dump_pr plugin "full" PathRecord
format which is used to preload these caches.  The file format is specified
in the ibacm_opts.cfg file via the route_preload setting which should
be set to opensm_full_v1 for this file format.  Default format is
none which does not preload these caches.  See dump_pr.notes.txt in dump_pr
for more information on the opensm_full_v1 file format and how to configure
OpenSM to generate this file.

Additionally, the name, IPv4, and IPv6 caches can be be preloaded by using
the addr_preload option.  The default is none which does not preload these
caches.  To preload these caches, set this option to acm_hosts and
configure the addr_data_file appropriately.
