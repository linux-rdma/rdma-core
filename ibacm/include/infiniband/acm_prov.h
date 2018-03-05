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
#include <infiniband/umad.h>
#include <infiniband/umad_sa.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ACM_PROV_VERSION          1

struct acm_device {
	struct ibv_context 	*verbs;
	__be64			dev_guid;
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
	union acm_ep_info	info;
	char			*id_string;
	uint16_t		type;
};

struct acm_provider {
	size_t    size; 
	uint32_t  version;
	const char *name;
	int	(*open_device)(const struct acm_device *device, 
			void **dev_context);
	void	(*close_device)(void *dev_context);
	int	(*open_port)(const struct acm_port *port, 
			void *dev_context, void **port_context);
	void	(*close_port)(void *port_context);
	int	(*open_endpoint)(const struct acm_endpoint *endpoint, 
			void *port_context, void **ep_context);
	void	(*close_endpoint)(void *ep_context);
	int	(*add_address)(const struct acm_address *addr, void *ep_context,
			void **addr_context);
	void	(*remove_address)(void *addr_context);
	int	(*resolve)(void *addr_context, struct acm_msg *msg, uint64_t id);
	int	(*query)(void *addr_context, struct acm_msg *msg, uint64_t id);
	int	(*handle_event)(void *port_context, enum ibv_event_type type);
	void	(*query_perf)(void *ep_context, uint64_t *values, uint8_t *cnt);
};

int provider_query(struct acm_provider **info, uint32_t *version);

/* Functions exported from core */
#define acm_log(level, format, ...) \
	acm_write(level, "%s: "format, __func__, ## __VA_ARGS__)
extern void acm_write(int level, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
extern void acm_format_name(int level, char *name, size_t name_size,
	uint8_t addr_type, const uint8_t *addr, size_t addr_size);

extern int ib_any_gid(union ibv_gid *gid);
extern uint8_t acm_gid_index(struct acm_port *port, union ibv_gid *gid);
extern int acm_get_gid(struct acm_port *port, int index, union ibv_gid *gid);
extern __be64 acm_path_comp_mask(struct ibv_path_record *path);

extern int acm_resolve_response(uint64_t id, struct acm_msg *msg);
extern int acm_query_response(uint64_t id, struct acm_msg *msg);

extern enum ibv_rate acm_get_rate(uint8_t width, uint8_t speed);
extern enum ibv_mtu acm_convert_mtu(int mtu);
extern enum ibv_rate acm_convert_rate(int rate);

struct acm_sa_mad {
	void			*context;
	struct ib_user_mad	umad;
	struct umad_sa_packet	sa_mad; /* must follow umad and be 64-bit aligned */
};

extern struct acm_sa_mad *
acm_alloc_sa_mad(const struct acm_endpoint *endpoint, void *context,
		 void (*handler)(struct acm_sa_mad *));
extern void acm_free_sa_mad(struct acm_sa_mad *mad);
extern int acm_send_sa_mad(struct acm_sa_mad *mad);

extern const char *acm_get_opts_file(void);
extern void acm_increment_counter(int type);

#ifdef __cplusplus
}
#endif

#endif /* ACM_PROV_H */
