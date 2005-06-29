/*
 * Copyright (c) 2004,2005 Voltaire Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id$
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/poll.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <dirent.h>
#include <stdlib.h>

#include "umad.h"

#define IB_OPENIB_OUI                 (0x001405)

typedef struct ib_user_mad {
	uint32_t agent_id;
	uint32_t status;
	uint32_t timeout_ms;
	uint32_t retries;
	ib_mad_addr_t addr;
	uint8_t  data[0];
} ib_user_mad_t;

typedef struct ib_user_mad_reg_req {
	uint32_t id;
	uint32_t method_mask[4];
	uint8_t  qpn;
	uint8_t  mgmt_class;
	uint8_t  mgmt_class_version;
	uint8_t  oui[3];
	uint8_t  rmpp_version;
} ib_user_mad_reg_req_t;

#define TRACE	if (umaddebug)	WARN
#define DEBUG	if (umaddebug)	WARN

int umaddebug = 0;

#define UMAD_DEV_NAME_SZ	32
#define UMAD_DEV_FILE_SZ	256

static char *def_hca_name = "mthca0";
static int def_hca_port = 1;

typedef struct Port {
	char dev_file[UMAD_DEV_FILE_SZ];
	char dev_name[UMAD_DEV_NAME_SZ];
	int dev_port;
	int dev_fd;
	int id;
} Port;

static Port ports[UMAD_MAX_PORTS];

/*************************************
 * Port
 */
static Port *
port_alloc(int portid, char *dev, int portnum)
{
	Port *port = ports + portid;

	if (portid < 0 || portid >= UMAD_MAX_PORTS) {
		WARN("bad umad portid %d", portid);
		return 0;
	}

	if (port->dev_name[0]) {
		WARN("umad port id %d is already allocated for %s %d",
			portid, port->dev_name, port->dev_port);
		return 0;
	}

	strncpy(port->dev_name, dev, UMAD_CA_NAME_LEN);
	port->dev_port = portnum;
	port->id = portid;

	return port;
}

static Port *
port_get(int portid)
{
	Port *port = ports + portid;

	if (portid < 0 || portid >= UMAD_MAX_PORTS)
		return 0;

	if (port->dev_name[0] == 0)
		return 0;

	return port;
}

static void
port_free(Port *port)
{
	memset(port, 0, sizeof *port);
}

static int
find_cached_ca(char *ca_name, umad_ca_t *ca)
{
	return 0;	/* caching not implemented yet */
}

static int
put_ca(umad_ca_t *ca)
{
	return 0;	/* caching not implemented yet */
}

static int
release_port(umad_port_t *port)
{
	return 0;	/* nothing yet */
}

static int
get_port(char *ca_name, char *dir_name, int portnum, umad_port_t *port)
{
	char port_dir[256];
	uint8_t gid[16];

	strncpy(port->ca_name, ca_name, sizeof port->ca_name - 1);
	port->portnum = portnum;

	snprintf(port_dir, sizeof port_dir - 1, "%s/%d", dir_name, portnum);
	port_dir[sizeof port_dir - 1] = 0;

	if (sys_read_uint(port_dir, SYS_PORT_LMC, &port->lmc) < 0)
		goto clean;
	if (sys_read_uint(port_dir, SYS_PORT_SMLID, &port->sm_lid) < 0)
		goto clean;
	if (sys_read_uint(port_dir, SYS_PORT_SMSL, &port->sm_sl) < 0)
		goto clean;
	if (sys_read_uint(port_dir, SYS_PORT_LID, &port->base_lid) < 0)
		goto clean;
	if (sys_read_uint(port_dir, SYS_PORT_STATE, &port->state) < 0)
		goto clean;
	if (sys_read_uint(port_dir, SYS_PORT_PHY_STATE, &port->phys_state) < 0)
		goto clean;
	if (sys_read_uint(port_dir, SYS_PORT_RATE, &port->rate) < 0)
		goto clean;
	if (sys_read_uint64(port_dir, SYS_PORT_CAPMASK, &port->capmask) < 0)
		goto clean;

	port->capmask = htonl(port->capmask);

	if (sys_read_gid(port_dir, SYS_PORT_GID, gid) < 0)
		goto clean;

	memcpy(&port->gid_prefix, gid, sizeof port->gid_prefix);
	memcpy(&port->port_guid, gid + 8, sizeof port->port_guid);

	/* FIXME: handle pkeys and gids */
	return 0;
clean:
	free(port);
	return -EIO;
}

static int
release_ca(umad_ca_t *ca)
{
	int i;

	for (i = 0; i <= ca->numports; i++) {
		if (!ca->ports[i])
			continue;
		release_port(ca->ports[i]);
		free(ca->ports[i]);
		ca->ports[i] = 0;
	}
	return 0;
}

/*
 * if *port > 0 checks ca[port] state. Otherwise set *port to
 * the first port that is active, and if such is not found, to
 * the first port that is (physically) up. Otherwise return -1;
 */
static int
resolve_ca_port(char *ca_name, int *port)
{
	umad_ca_t ca;
	int active = -1, up = -1;
	int i;

	TRACE("checking ca '%s'", ca_name);

	if (umad_get_ca(ca_name, &ca) < 0)
		return -1;

	if (ca.node_type == 2) {
		*port = 0;	/* switch sma port 0 */
		return 1;
	}

	if (*port > 0) {	/* user wants user gets */
		if (*port > ca.numports)
			return -1;
		if (!ca.ports[*port])
			return -1;
		if (ca.ports[*port]->state == 4)
			return 1;
		if (ca.ports[*port]->phys_state == 5)
			return 0;
		return -1;
	}

	for (i = 0; i <= ca.numports; i++) {
		DEBUG("checking port %d", i);
		if (!ca.ports[i])
			continue;
		if (up < 0 && ca.ports[i]->phys_state == 5)
			up = *port = i;
		if (ca.ports[i]->state == 4) {
			active = *port = i;
			DEBUG("found active port %d", i);
			break;
		}
	}

	release_ca(&ca);

	if (active >= 0)
		return 1;
	if (up >= 0)
		return 0;
	return -1;
}

static char *
resolve_ca_name(char *ca_name, int *best_port)
{
	static char names[20][UMAD_CA_NAME_LEN];
	int phys_found = -1, port_found = 0, port, port_type;
	int caidx, n;

	if (ca_name && (!best_port || *best_port))
		return ca_name;

	if (ca_name) {
		if (resolve_ca_port(ca_name, best_port) < 0)
			return 0;
		return ca_name;
	}
		
	/* find first existing HCA with Active port */
	if ((n = umad_get_cas_names((void *)names, UMAD_CA_NAME_LEN)) < 0)
		return 0;

	for (caidx = 0; caidx < n; caidx++) {
		TRACE("checking ca '%s'", names[caidx]);
	
		port = *best_port;
		if ((port_type = resolve_ca_port(names[caidx], &port)) < 0)
			continue;

		DEBUG("found ca %s with port %d type %d",
			names[caidx], port, port_type);

		if (port_type > 0) {
			if (best_port)
				*best_port = port;
			DEBUG("found ca %s with active port %d",
			      names[caidx], port);
			return (char *)(names + caidx);
		}

		if (phys_found == -1) {
			phys_found = caidx;
			port_found = port;
		}
	}

	DEBUG("phys found %d on %s port %d",
		phys_found, phys_found >=0 ? names[phys_found] : 0, port_found);
	if (phys_found >= 0) {
		if (best_port)
			*best_port = port_found;
		return names[phys_found];
	}

	if (best_port)
		*best_port = def_hca_port;
	return def_hca_name;
}

static int
get_ca(char *ca_name, umad_ca_t *ca)
{
	DIR *dir;
	char dir_name[256];
	struct dirent **namelist;
	int r, i, ret;
	int portnum;

	strncpy(ca->ca_name, ca_name, sizeof ca->ca_name);
	 
	snprintf(dir_name, sizeof dir_name - 1, "%s/%s", SYS_INFINIBAND,
		 ca->ca_name);
	dir_name[sizeof dir_name - 1] = 0;

	if ((r = sys_read_uint(dir_name, SYS_NODE_TYPE, &ca->node_type)) < 0)
		return r;
	if ((r = sys_read_string(dir_name, SYS_CA_FW_VERS, ca->fw_ver,
				 sizeof ca->fw_ver)) < 0)
		return r;
	if ((r = sys_read_string(dir_name, SYS_CA_HW_VERS, ca->hw_ver,
				 sizeof ca->hw_ver)) < 0)
		return r;
	if ((r = sys_read_string(dir_name, SYS_CA_TYPE, ca->ca_type,
				 sizeof ca->ca_type)) < 0)
		return r;
	if ((r = sys_read_guid(dir_name, SYS_CA_NODE_GUID, &ca->node_guid)) < 0)
		return r;
	if ((r = sys_read_guid(dir_name, SYS_CA_SYS_GUID, &ca->system_guid)) < 0)
		return r;

	snprintf(dir_name, sizeof dir_name - 1, "%s/%s/%s",
		SYS_INFINIBAND, ca->ca_name, SYS_CA_PORTS_DIR);
	dir_name[sizeof dir_name - 1] = 0;

	if (!(dir = opendir(dir_name)))
		return -ENOENT;

	if ((r = scandir(dir_name, &namelist, 0, alphasort)) < 0) {
		ret = errno < 0 ? errno : -EIO;
		goto error;
	}

	ret = 0;
	ca->numports = 0;
	memset(ca->ports, 0, sizeof ca->ports);
	for (i = 0; i < r; i++) {
		portnum = 0;
		if (!strcmp(".", namelist[i]->d_name) ||
		    !strcmp("..", namelist[i]->d_name))
			continue;
		if (strcmp("0", namelist[i]->d_name) &&
		    ((portnum = atoi(namelist[i]->d_name)) <= 0 ||
		     portnum >= UMAD_CA_MAX_PORTS)) {
			ret = -EIO;
			goto clean;
		}
		if (!(ca->ports[portnum] = calloc(1, sizeof(*ca->ports[portnum])))) {
			ret = -ENOMEM;
			goto clean;
		}
		if (get_port(ca_name, dir_name, portnum, ca->ports[portnum]) < 0) {
			ret = -EIO;
			goto clean;
		}
		if (ca->numports < portnum)
			ca->numports = portnum;
	}

	for (i = 0; i < r; i++)
		free(namelist[i]);
	free(namelist);

	closedir(dir);
	put_ca(ca);
	return 0;

clean:
	for (i = 0; i < r; i++)
		free(namelist[i]);
	free(namelist);
error:
	closedir(dir);
	release_ca(ca);

	return ret;
}

static int
umad_id_to_dev(int umad_id, char *dev, int *port)
{
	char path[256];
	int r;

	snprintf(path, sizeof path - 1, SYS_INFINIBAND_MAD "/umad%d/", umad_id);

	if ((r = sys_read_string(path, SYS_IB_MAD_DEV, dev, UMAD_CA_NAME_LEN)) < 0)
		return r;

	if ((r = sys_read_uint(path, SYS_IB_MAD_PORT, port)) < 0)
		return r;

	return 0;
}

static int
dev_to_umad_id(char *dev, int port)
{
	char umad_dev[UMAD_CA_NAME_LEN];
	uint umad_port;
	int id;

	for (id = 0; id < UMAD_MAX_PORTS; id++) {
		if (umad_id_to_dev(id, umad_dev, &umad_port) < 0)
			continue;
		if (strncmp(dev, umad_dev, UMAD_CA_NAME_LEN))
			continue;
		if (port != umad_port)
			continue;

		DEBUG("mapped %s %d to %d", dev, port, id);
		return id;
	}

	return -1;	/* not found */
}

/*******************************
 * Public interface
 */

int
umad_init(void)
{
	int abi_version;

	TRACE("");
	if (sys_read_uint(IB_UMAD_ABI_DIR, IB_UMAD_ABI_FILE, &abi_version) < 0) {
		WARN("can't read ABI version from %s/%s (%m): is ib_umad module loaded?",
			IB_UMAD_ABI_DIR, IB_UMAD_ABI_FILE);
		return -1;
	}
	if (abi_version != IB_UMAD_ABI_VERSION) {
		WARN("wrong ABI version: %s/%s is %d but library ABI is %d",
			IB_UMAD_ABI_DIR, IB_UMAD_ABI_FILE, abi_version, IB_UMAD_ABI_VERSION);
		return -1;
	}
	return 0;
}

int
umad_done(void)
{
	TRACE("");
	/* FIXME - verify that all ports are closed */
	return 0;
}

int
umad_get_cas_names(char cas[][UMAD_CA_NAME_LEN], int max)
{
	struct dirent **namelist;
	int n, i, j = 0;

	TRACE("max %d", max);

	n = scandir(SYS_INFINIBAND, &namelist, 0, alphasort);
	if (n > 0) {
		for (i = 0; i < n; i++) {
			if (!strcmp(namelist[i]->d_name, ".") || 
			    !strcmp(namelist[i]->d_name, "..")) {
			} else 
				strncpy(cas[j++], namelist[i]->d_name,
					UMAD_CA_NAME_LEN);
			free(namelist[i]);
		}
		DEBUG("return %d cas", j);
	} else {
		/* Is this still needed ? */
		strncpy((char *)cas, def_hca_name, UMAD_CA_NAME_LEN);
		DEBUG("return 1 ca");
		j = 1;
	}
	if (n >= 0)
		free(namelist);
	return j;
}

int
umad_get_ca_portguids(char *ca_name, uint64_t *portguids, int max)
{
	umad_ca_t ca;
	int ports = 0, i;

	TRACE("ca name %s max port guids", ca_name, max);
	if (!(ca_name = resolve_ca_name(ca_name, 0)))
		return -ENODEV;

	if (umad_get_ca(ca_name, &ca) < 0)
		return -1;

	if (ca.numports + 1 > max)
		return -ENOMEM;

	for (i = 0; i <= ca.numports; i++)
		portguids[ports++] = ca.ports[i] ? ca.ports[i]->port_guid : 0;

	release_ca(&ca);
	DEBUG("%s: %d ports", ca_name, ports);

	return ports;
}

int
umad_open_port(char *ca_name, int portnum)
{
	uint umad_id;
	Port *port;

	TRACE("ca %s port %d", ca_name, portnum);

	if (!(ca_name = resolve_ca_name(ca_name, &portnum)))
		return -ENODEV;

	DEBUG("opening %s port %d", ca_name, portnum);

	if ((umad_id = dev_to_umad_id(ca_name, portnum)) < 0)
		return -EINVAL;

	if (!(port = port_alloc(umad_id, ca_name, portnum)))
		return -EINVAL;

	snprintf(port->dev_file, sizeof port->dev_file - 1, "%s/umad%d",
		 UMAD_DEV_DIR , umad_id);

	if ((port->dev_fd = open(port->dev_file, O_RDWR|O_NONBLOCK)) < 0) {
		DEBUG("open %s failed", port->dev_file);
		return -EIO;
	}

	DEBUG("opened %s fd %d portid %d", port->dev_file, port->dev_fd, port->id);
	return port->id;
}

int
umad_get_ca(char *ca_name, umad_ca_t *ca)
{
	int r;

	TRACE("ca_name %s", ca_name);
	if (!(ca_name = resolve_ca_name(ca_name, 0)))
		return -ENODEV;

	if (find_cached_ca(ca_name, ca) > 0)
		return 0;

	if ((r = get_ca(ca_name, ca)) < 0)
		return r;

	DEBUG("opened %s", ca_name);
	return 0;
}

int
umad_release_ca(umad_ca_t *ca)
{
	int r;

	TRACE("ca_name %s", ca->ca_name);
	if (!ca)
		return -ENODEV;

	if ((r = release_ca(ca)) < 0)
		return r;

	DEBUG("releasing %s", ca->ca_name);
	return 0;	
}

int
umad_get_port(char *ca_name, int portnum, umad_port_t *port)
{
	char dir_name[256];

	TRACE("ca_name %s portnum %d", ca_name, portnum);

	if (!(ca_name = resolve_ca_name(ca_name, &portnum)))
		return -ENODEV;

	snprintf(dir_name, sizeof dir_name - 1, "%s/%s/%s",
		SYS_INFINIBAND, ca_name, SYS_CA_PORTS_DIR);

	return get_port(ca_name, dir_name, portnum, port);
}

int
umad_release_port(umad_port_t *port)
{
	int r;

	TRACE("port %s:%d", port->ca_name, port->portnum);
	if (!port)
		return -ENODEV;

	if ((r = release_port(port)) < 0)
		return r;

	DEBUG("releasing %s:%d", port->ca_name, port->portnum);
	return 0;	
}

int
umad_close_port(int portid)
{
	Port *port;

	TRACE("portid %d", portid);
	if (!(port = port_get(portid)))
		return -EINVAL;

	close(port->dev_fd);
	
	port_free(port);

	DEBUG("closed %s fd %d", port->dev_file, port->dev_fd);
	return 0;
}

void *
umad_get_mad(void *umad)
{
	TRACE("umad %p", umad);
	return ((struct ib_user_mad *)umad)->data;
}

int
umad_size(void)
{
	return sizeof (struct ib_user_mad);
}

int
umad_set_grh(void *umad, void *grh)
{
	struct ib_user_mad *mad = umad;

	mad->addr.grh_present = 0;		/* FIXME - GRH support */
	return 0;
}

int
umad_set_pkey(void *umad, int pkey)
{
#if 0
	mad->addr.pkey = 0;		/* FIXME - PKEY support */
#endif
	return 0;
}

int
umad_set_addr(void *umad, int dlid, int dqp, int sl, int qkey)
{
	struct ib_user_mad *mad = umad;

	TRACE("umad %p dlid %d dqp %d sl %d, qkey %x",
	      umad, dlid, dqp, sl, qkey);
	mad->addr.qpn = htonl(dqp);
	mad->addr.lid = htons(dlid);
	mad->addr.qkey = htonl(qkey);
	mad->addr.sl = sl;

	return 0;
}

int
umad_set_addr_net(void *umad, int dlid, int dqp, int sl, int qkey)
{
	struct ib_user_mad *mad = umad;

	TRACE("umad %p dlid %d dqp %d sl, qkey %x",
	      umad, htons(dlid), htonl(dqp), sl, htonl(qkey));
	mad->addr.qpn = dqp;
	mad->addr.lid = dlid;
	mad->addr.qkey = qkey;
	mad->addr.sl = sl;

	return 0;
}

int
umad_send(int portid, int agentid, void *umad, int length,
	  int timeout_ms, int retries)
{
	struct ib_user_mad *mad = umad;
	Port *port;
	int n;

	TRACE("portid %d agentid %d umad %p timeout %u",
	      portid, agentid, umad, timeout_ms);
	errno = 0;
	if (!(port = port_get(portid))) {
		if (!errno)
			errno = EINVAL;
		return -EINVAL;
	}

	mad->timeout_ms = timeout_ms;
	mad->retries = retries;
	mad->agent_id = agentid;

	if (umaddebug > 1)
		umad_dump(mad);

	n = write(port->dev_fd, mad, length + sizeof *mad);
	if (n == length + sizeof *mad)
		return 0;

	DEBUG("write returned %d != sizeof umad %d + length %d (%m)",
	      n, sizeof *mad, length);
	if (!errno)
		errno = EIO;
	return -EIO;
}

static int
dev_poll(int fd, int timeout_ms)
{
	struct pollfd ufds;
	int n;

	ufds.fd     = fd;
	ufds.events = POLLIN;

	if ((n = poll(&ufds, 1, timeout_ms)) == 1)
		return 0;

	if (n == 0)
		return -ETIMEDOUT;

	return -EIO;
}

int
umad_recv(int portid, void *umad, int *length, int timeout_ms)
{
	struct ib_user_mad *mad = umad;
	Port *port;
	int n;

	errno = 0;
	TRACE("portid %d umad %p timeout %u", portid, umad, timeout_ms);
	if (!length) {
		errno = EINVAL;
		return -EINVAL;
	}
		
	if (!(port = port_get(portid))) {
		if (!errno)
			errno = EINVAL;
		return -EINVAL;
	}

	if (timeout_ms && (n = dev_poll(port->dev_fd, timeout_ms)) < 0) {
		if (!errno)
			errno = -n;
		return n;
	}

	if ((n = read(port->dev_fd, umad, sizeof *mad + *length)) ==
	     sizeof *mad + *length) {
		DEBUG("mad received by agent %d", mad->agent_id);
		return mad->agent_id;
	}

	if (n == -EWOULDBLOCK) {
		if (!errno)
			errno = EWOULDBLOCK;
		return n;
	}

	DEBUG("read returned %d != sizeof umad %d + length %d (%m)",
	      n, sizeof *mad, *length);
	if (!errno)	
		errno = EIO;
	return -EIO;
}

int
umad_poll(int portid, int timeout_ms)
{
	Port *port;

	TRACE("portid %d timeout %u", portid, timeout_ms);
	if (!(port = port_get(portid)))
		return -EINVAL;

	return dev_poll(port->dev_fd, timeout_ms);
}

int
umad_get_fd(int portid)
{
	Port *port;

	TRACE("portid %d", portid);
	if (!(port = port_get(portid)))
		return -EINVAL;

	return port->dev_fd;
}

int
umad_register_oui(int portid, int mgmt_class, uint8_t rmpp_version,
		  uint8_t oui[3], uint32_t method_mask[4])
{
	struct ib_user_mad_reg_req req;
	Port *port;

	TRACE("portid %d mgmt_class %u rmpp_version %d oui 0x%x%x%x method_mask %p",
		portid, mgmt_class, (int)rmpp_version, (int)oui[0], (int)oui[1],
		(int)oui[2], method_mask);

	if (!(port = port_get(portid)))
		return -EINVAL;

	if (mgmt_class < 0x30 || mgmt_class > 0x4f) {
		DEBUG("mgmt class %d not in vendor range 2", mgmt_class);
		return -EINVAL;
	}

	req.qpn = 1;
	req.mgmt_class = mgmt_class;
	req.mgmt_class_version = 1;
	memcpy(req.oui, oui, sizeof req.oui);
	req.rmpp_version = rmpp_version;

	if ((void *)method_mask != 0)
		memcpy(req.method_mask, method_mask, sizeof req.method_mask);
	else
		memset(req.method_mask, 0, sizeof req.method_mask);

	if (!ioctl(port->dev_fd, IB_USER_MAD_REGISTER_AGENT, (void *)&req)) {
		DEBUG("portid %d registered to use agent %d qp %d class 0x%x oui 0x%x",
			portid, req.id, req.qpn, oui);
		return req.id; 		/* return agentid */
	}
	
	DEBUG("portid %d registering qp %d class %s version %d oui 0x%x failed: %m",
		portid, req.qpn, req.mgmt_class, req.mgmt_class_version, oui);
	return -EPERM;	
}

int
umad_register(int portid, int mgmt_class, int mgmt_version,
	      uint8_t rmpp_version, uint32_t method_mask[4])
{
	struct ib_user_mad_reg_req req;
	Port *port;
	uint32_t oui = htonl(IB_OPENIB_OUI);
	int qp;

	TRACE("portid %d mgmt_class %u mgmt_version %u rmpp_version %d method_mask %p",
		portid, mgmt_class, mgmt_version, rmpp_version, method_mask);

	if (!(port = port_get(portid)))
		return -EINVAL;

	req.qpn = qp = (mgmt_class == 0x1 || mgmt_class == 0x81) ? 0 : 1;
	req.mgmt_class = mgmt_class;
	req.mgmt_class_version = mgmt_version;
	req.rmpp_version = rmpp_version;

	if ((void *)method_mask != 0)
		memcpy(req.method_mask, method_mask, sizeof req.method_mask);
	else
		memset(req.method_mask, 0, sizeof req.method_mask);

	memcpy(&req.oui, (char *)&oui + 1, sizeof req.oui); 

	if (!ioctl(port->dev_fd, IB_USER_MAD_REGISTER_AGENT, (void *)&req)) {
		DEBUG("portid %d registered to use agent %d qp %d",
		      portid, req.id, qp);
		return req.id; 		/* return agentid */
	}
	
	DEBUG("portid %d registering qp %d class %s version %d failed: %m",
		portid, qp, mgmt_class, mgmt_version);
	return -EPERM;	
}

int
umad_unregister(int portid, int agentid)
{
	Port *port;

	TRACE("portid %d unregisters agent %d", agentid);

	if (!(port = port_get(portid)))
		return -EINVAL;

	return ioctl(port->dev_fd, IB_USER_MAD_UNREGISTER_AGENT, &agentid);
}

int
umad_status(void *umad)
{
	struct ib_user_mad *mad = umad;

	return mad->status;
}

ib_mad_addr_t *
umad_get_mad_addr(void *umad)
{
	struct ib_user_mad *mad = umad;

	return &mad->addr;
}

int
umad_debug(int level)
{
	if (level >= 0)
		umaddebug = level;
	return umaddebug;
}

void
umad_addr_dump(ib_mad_addr_t *addr)
{
#define HEX(x)  ((x) < 10 ? '0' + (x) : 'a' + ((x) -10))
	char gid_str[64];
	int i;

	for (i = 0; i < sizeof addr->gid; i++) {
		gid_str[i*2] = HEX(addr->gid[i] >> 4);
		gid_str[i*2+1] = HEX(addr->gid[i] & 0xf);
	}
	gid_str[i*2] = 0;
	WARN("qpn %d qkey 0x%x lid 0x%x sl %d\n"
		"grh_present %d gid_index %d hop_limit %d traffic_class %d flow_label 0x%x\n"
		"Gid 0x%s",
		ntohl(addr->qpn), ntohl(addr->qkey), ntohs(addr->lid), addr->sl,
		addr->grh_present, (int)addr->gid_index, (int)addr->hop_limit,
		(int)addr->traffic_class, addr->flow_label, gid_str);
}

void
umad_dump(void *umad)
{
	struct ib_user_mad * mad = umad;

	WARN("agent id %d status %x timeout %d",
	     mad->agent_id, mad->status, mad->timeout_ms);
	umad_addr_dump(&mad->addr);
}

