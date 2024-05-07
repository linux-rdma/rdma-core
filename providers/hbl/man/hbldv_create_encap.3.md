---
layout: page
title: hbldv_create_encap
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_create_encap - Allocates an encapsulation resource

hbldv_destroy_encap - Free an encapsulation resource

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

struct hbldv_encap *hbldv_create_encap(struct ibv_context *context,
				       struct hbldv_encap_attr *encap_attr);

int hbldv_destroy_encap(struct hbldv_encap *hbl_encap);
```

# DESCRIPTION

Allows the user to encapsulate the RDMA packets with a user defined header.

# ARGUMENTS

*context*
:	RDMA device context to work on.

## *attr*
:	input parameters to allocate encapsulation resource

```c
struct hbldv_encap_attr {
	uint64_t tnl_hdr_ptr;
	uint32_t tnl_hdr_size;
	uint32_t ipv4_addr;
	uint32_t port_num;
	union {
		uint16_t udp_dst_port;
		uint16_t ip_proto;
	};
	enum hbldv_encap_type encap_type;
};
```

*tnl_hdr_ptr*
:	Pointer to the tunnel encapsulation header. i.e. specific tunnel header
	data to be used in the encapsulation by the HW.

*tnl_hdr_size*
:	Tunnel encapsulation header size.

*ipv4_addr*
:	Source IP address, set regardless of encapsulation type.

*port_num*
:	Port number.

*udp_dst_port*
:	The UDP destination-port. Valid for L4 tunnel.

*ip_proto*
:	IP protocol to use. Valid for L3 tunnel.

*encap_type*
:	Encapsulation type:

	HBLDV_ENCAP_TYPE_NO_ENC
		No Tunneling.

	HBLDV_ENCAP_TYPE_ENC_OVER_IPV4
		Tunnel RDMA packets through L3 layer.

	HBLDV_ENCAP_TYPE_ENC_OVER_UDP
		Tunnel RDMA packets through L4 layer.

## *hbl_encap*
	Encapsulation resource in action.

```c
struct hbldv_encap {
	uint32_t encap_num;
};
```

*encap_num*
:	HW encapsulation number.

# NOTES

On success the API returns an encapsulation ID, which needs to be used for a
particular QP using the **hbldv_modify_qp()**.

# RETURN VALUE

**hbldv_create_encap()** returns a pointer to a new *struct hbldv_encap* on
success or NULL on failure.

**hbldv_destroy_encap()** returns 0 on success or errno on failure.


# SEE ALSO

**hbldv**(7), **hbldv_modify_qp**(3)

# AUTHOR

Abhilash K V <kvabhilash@habana.ai>
