/*
 * Copyright (c) 2014 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenFabrics.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(ACM_PROV_H)
#define ACM_PROV_H

#include <infiniband/acm.h>

struct acm_device {
	struct ibv_context 	*verbs;
	uint64_t		dev_guid;
};

struct acm_port {
	struct acm_device 	*dev;
	uint8_t			port_num;
};

struct acm_endpoint {
	struct acm_port 	*port;
	uint16_t		pkey;
};

struct acm_address {
	struct acm_endpoint	*endpoint;
	void			*prov_addr;
	union acm_ep_info	info;
	char			*id_string;
	uint16_t		type;
};

struct acm_provider {
	int	(*open_device)(const struct acm_device *device, 
			void **dev_context);
	void	(*close_device)(void *dev_context);
	int	(*open_port)(const struct acm_port *port, 
			void *dev_context, void **port_context);
	void	(*close_port)(void *port_context);
	int	(*open_endpoint)(const struct acm_endpoint *endpoint, 
			void *port_context, void **ep_context);
	void	(*close_endpoint)(void *ep_context);
	int	(*resolve)(void *ep_context, struct acm_msg *msg, uint64_t id);
	int	(*query)(void *ep_context, struct acm_msg *msg, uint64_t id);
	int	(*handle_event)(void *port_context, enum ibv_event_type type);
};

#endif /* ACM_PROV_H */
