/*
 * srp-dm - discover SRP targets over IB
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * $Id$
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <endian.h>
#include <byteswap.h>
#include <errno.h>
#include <getopt.h>

#include "ib_user_mad.h"
#include "srp-dm.h"

static const uint8_t topspin_oui[3] = { 0x00, 0x05, 0xad };

static char *umad_dev   = "/dev/infiniband/umad0";
static char *port_sysfs_path;
static int   timeout_ms = 25000;
static uint16_t sm_lid;
static uint32_t tid = 1;

static int cmd     = 0;
static int verbose = 0;

#define pr_human(arg...)			\
	do {					\
		if (!cmd)			\
			printf(arg);		\
	} while (0)

#define pr_cmd(arg...)				\
	do {					\
		if (cmd)			\
			printf(arg);		\
	} while (0)

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t ntohll(uint64_t x) { return x; }
static inline uint64_t htonll(uint64_t x) { return x; }
#endif

static char *sysfs_path = "/sys";

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s [-vc] [-d <umad device>]\n", argv0);
}

static int read_file(const char *dir, const char *file, char *buf, size_t size)
{
	char *path;
	int fd;
	int len;

	asprintf(&path, "%s/%s", dir, file);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, size);

	close(fd);
	free(path);

	if (len > 0 && buf[len - 1] == '\n') {
		--len;
		buf[len] = '\0';
	}

	return len;
}


static int setup_port_sysfs_path(void) {
	char *env;
	char class_dev_path[256];
	char ibport[16];
	char ibdev[16];
	char *umad_dev_name;

	env = getenv("SYSFS_PATH");
	if (env) {
		int len;

		sysfs_path = strndup(env, 256);
		len = strlen(sysfs_path);
		while (len > 0 && sysfs_path[len - 1] == '/') {
			--len;
			sysfs_path[len] = '\0';
		}
	}

	umad_dev_name = rindex(umad_dev, '/');
	if (!umad_dev_name) {
		fprintf(stderr, "Couldn't find device name in '%s'\n", umad_dev_name);
		return -1;
	}

	snprintf(class_dev_path, sizeof class_dev_path,
		 "%s/class/infiniband_mad/%s", sysfs_path, umad_dev_name);

	if (read_file(class_dev_path, "ibdev", ibdev, sizeof ibdev) < 0) {
		fprintf(stderr, "Couldn't read ibdev attribute\n");
		return -1;
	}
		
	if (read_file(class_dev_path, "port", ibport, sizeof ibport) < 0) {
		fprintf(stderr, "Couldn't read port attribute\n");
		return -1;
	}

	asprintf(&port_sysfs_path, "%s/class/infiniband/%s/ports/%s",
		 sysfs_path, ibdev, ibport);

	return 0;
}

static int create_agent(int fd, uint32_t agent[2])
{
	struct ib_user_mad_reg_req req;
	memset(&req, 0, sizeof req);

	if (ioctl(fd, IB_USER_MAD_REGISTER_AGENT, &req)) {
		perror("ioctl");
		return -1;
	}
	agent[0] = req.id;

	req.qpn          = 1;
	req.rmpp_version = 1;

	if (ioctl(fd, IB_USER_MAD_REGISTER_AGENT, &req)) {
		perror("ioctl");
		return -1;
	}
	agent[1] = req.id;

	return 0;
}

static void init_srp_dm_mad(struct ib_user_mad *out_mad, uint32_t agent,
			    uint16_t dlid, uint16_t attr_id, uint32_t attr_mod)
{
	struct srp_dm_mad *out_dm_mad;

	memset(out_mad, 0, sizeof *out_mad);

	out_mad->hdr.id         = agent;
	out_mad->hdr.timeout_ms = timeout_ms;
	out_mad->hdr.qpn        = htonl(1);
	out_mad->hdr.qkey       = htonl(0x80010000);
	out_mad->hdr.lid        = htons(dlid);

	out_dm_mad = (void *) out_mad->data;

	out_dm_mad->base_version  = 1;
	out_dm_mad->mgmt_class    = SRP_MGMT_CLASS_DM;
	out_dm_mad->class_version = 1;
	out_dm_mad->method 	  = SRP_DM_METHOD_GET;
	out_dm_mad->attr_id       = htons(attr_id);
	out_dm_mad->attr_mod      = htonl(attr_mod);

	((uint32_t *) &out_dm_mad->tid)[1] = tid++;
}

static int set_class_port_info(int fd, uint32_t agent[2], uint16_t dlid)
{
	struct ib_user_mad		in_mad, out_mad;
	struct srp_dm_mad	       *out_dm_mad, *in_dm_mad;
	struct srp_dm_class_port_info  *cpi;
	char val[64];
	int i;

	init_srp_dm_mad(&out_mad, agent[1], dlid, SRP_DM_ATTR_CLASS_PORT_INFO, 0);

	out_dm_mad          = (void *) out_mad.data;
	out_dm_mad->method = SRP_DM_METHOD_SET;

	cpi                = (void *) out_dm_mad->data;

	if (read_file(port_sysfs_path, "lid", val, sizeof val) < 0) {
		fprintf(stderr, "Couldn't read LID\n");
		return -1;
	}

	cpi->trap_lid = htons(strtol(val, NULL, 0));

	if (read_file(port_sysfs_path, "gids/0", val, sizeof val) < 0) {
		fprintf(stderr, "Couldn't read GID[0]\n");
		return -1;
	}

	for (i = 0; i < 8; ++i) {
		((uint16_t *) cpi->trap_gid)[i] = htons(strtol(val + i * 5, NULL, 16));
	}

again:
	if (write(fd, &out_mad, sizeof out_mad) != sizeof out_mad) {
		perror("write");
		return -1;
	}

	if (read(fd, &in_mad, sizeof in_mad) != sizeof in_mad) {
		if (in_mad.hdr.status == ETIMEDOUT)
			goto again;
		fprintf(stderr, "%s/%d: ", __func__, __LINE__);
		perror("read");
		return -1;
	}

	in_dm_mad = (void *) in_mad.data;
	if (in_dm_mad->status) {
		fprintf(stderr, "Class Port Info query returned status 0x%04x\n",
			ntohs(in_dm_mad->status));
		return -1;
	}

	return 0;
}

static int get_iou_info(int fd, uint32_t agent[2], uint16_t dlid,
			struct srp_dm_iou_info *iou_info)
{
	struct ib_user_mad		in_mad, out_mad;
	struct srp_dm_mad	       *in_dm_mad;

	init_srp_dm_mad(&out_mad, agent[1], dlid, SRP_DM_ATTR_IO_UNIT_INFO, 0);

again:
	if (write(fd, &out_mad, sizeof out_mad) != sizeof out_mad) {
		perror("write");
		return -1;
	}

	if (read(fd, &in_mad, sizeof in_mad) != sizeof in_mad) {
		if (in_mad.hdr.status == ETIMEDOUT)
			goto again;
		fprintf(stderr, "%s/%d: ", __func__, __LINE__);
		perror("read");
		return -1;
	}

	in_dm_mad = (void *) in_mad.data;
	if (in_dm_mad->status) {
		fprintf(stderr, "IO Unit Info query returned status 0x%04x\n",
			ntohs(in_dm_mad->status));
		return -1;
	}

	memcpy(iou_info, in_dm_mad->data, sizeof *iou_info);

	return 0;
}

static int get_ioc_prof(int fd, uint32_t agent[2], uint16_t dlid, int ioc,
			struct srp_dm_ioc_prof *ioc_prof)
{
	struct ib_user_mad		in_mad, out_mad;
	struct srp_dm_mad	       *in_dm_mad;

	init_srp_dm_mad(&out_mad, agent[1], dlid, SRP_DM_ATTR_IO_CONTROLLER_PROFILE, ioc);

again:
	if (write(fd, &out_mad, sizeof out_mad) != sizeof out_mad) {
		perror("write");
		return -1;
	}

	if (read(fd, &in_mad, sizeof in_mad) != sizeof in_mad) {
		if (in_mad.hdr.status == ETIMEDOUT)
			goto again;
		fprintf(stderr, "%s/%d: ", __func__, __LINE__);
		perror("read");
		return -1;
	}

	if (in_mad.hdr.status != 0) {
		fprintf(stderr, "IO Controller Profile query timed out\n");
		return -1;
	}

	in_dm_mad = (void *) in_mad.data;
	if (in_dm_mad->status) {
		fprintf(stderr, "IO Controller Profile query returned status 0x%04x\n",
			ntohs(in_dm_mad->status));
		return -1;
	}

	memcpy(ioc_prof, in_dm_mad->data, sizeof *ioc_prof);

	return 0;
}

static int get_svc_entries(int fd, uint32_t agent[2], uint16_t dlid, int ioc,
			   int start, int end, struct srp_dm_svc_entries *svc_entries)
{
	struct ib_user_mad		in_mad, out_mad;
	struct srp_dm_mad	       *in_dm_mad;

	init_srp_dm_mad(&out_mad, agent[1], dlid, SRP_DM_ATTR_SERVICE_ENTRIES,
			(ioc << 16) | (end << 8) | start);

again:
	if (write(fd, &out_mad, sizeof out_mad) != sizeof out_mad) {
		perror("write");
		return -1;
	}

	if (read(fd, &in_mad, sizeof in_mad) != sizeof in_mad) {
		if (in_mad.hdr.status == ETIMEDOUT)
			goto again;
		fprintf(stderr, "%s/%d: ", __func__, __LINE__);
		perror("read");
		return -1;
	}

	if (in_mad.hdr.status != 0) {
		fprintf(stderr, "Service Entries query timed out\n");
		return -1;
	}

	in_dm_mad = (void *) in_mad.data;
	if (in_dm_mad->status) {
		fprintf(stderr, "Service Entries query returned status 0x%04x\n",
			ntohs(in_dm_mad->status));
		return -1;
	}

	memcpy(svc_entries, in_dm_mad->data, sizeof *svc_entries);

	return 0;
}

static int do_port(int fd, uint32_t agent[2], uint16_t dlid, uint64_t subnet_prefix,
		   uint64_t guid)
{
	struct srp_dm_iou_info		iou_info;
	struct srp_dm_ioc_prof		ioc_prof;
	struct srp_dm_svc_entries	svc_entries;
	int				i, j, k;

	if (!memcmp(&guid, topspin_oui, 3) &&
	    set_class_port_info(fd, agent, dlid))
		fprintf(stderr, "Warning: set of ClassPortInfo failed\n");

	if (get_iou_info(fd, agent, dlid, &iou_info))
		return 1;

	pr_human("IO Unit Info:\n");
	pr_human("    port LID:        %04x\n", dlid);
	pr_human("    port GID:        %016llx%016llx\n",
		 (unsigned long long) subnet_prefix, (unsigned long long) guid);
	pr_human("    change ID:       %04x\n", ntohs(iou_info.change_id));
	pr_human("    max controllers: 0x%02x\n", iou_info.max_controllers);

	if (verbose > 0) 
		for (i = 0; i < iou_info.max_controllers; ++i) {
			pr_human("    controller[%3d]: ", i + 1);
			switch ((iou_info.controller_list[i / 2] >>
				 (4 * (1 - i % 2))) & 0xf) {
			case SRP_DM_NO_IOC:      pr_human("not installed\n"); break;
			case SRP_DM_IOC_PRESENT: pr_human("present\n");       break;
			case SRP_DM_NO_SLOT:     pr_human("no slot\n");       break;
			default:                 pr_human("<unknown>\n");     break;
			}
		}

	for (i = 0; i < iou_info.max_controllers; ++i) {
		if (((iou_info.controller_list[i / 2] >> (4 * (1 - i % 2))) & 0xf) ==
		    SRP_DM_IOC_PRESENT) {
			pr_human("\n");

			if (get_ioc_prof(fd, agent, dlid, i + 1, &ioc_prof))
				continue;

			pr_human("    controller[%3d]\n", i + 1);

			pr_human("        GUID:      %016llx\n",
				 (unsigned long long) ntohll(ioc_prof.guid));
			pr_human("        vendor ID: %06x\n", ntohl(ioc_prof.vendor_id) >> 8);
			pr_human("        device ID: %06x\n", ntohl(ioc_prof.device_id));
			pr_human("        ID:        %s\n", ioc_prof.id);
			pr_human("        service entries: %d\n", ioc_prof.service_entries);

			for (j = 0; j < ioc_prof.service_entries; j += 4) {
				int n;

				n = j + 3;
				if (n >= ioc_prof.service_entries)
					n = ioc_prof.service_entries - 1;

				if (get_svc_entries(fd, agent, dlid, i + 1,
						    j, n, &svc_entries))
					continue;

				for (k = 0; k <= n - j; ++k) {
					char id_ext[17];

					if (sscanf(svc_entries.service[k].name,
						   "SRP.T10:%16s",
						   id_ext) != 1)
						continue;

					pr_human("            service[%3d]: %016llx / %s\n",
						 j + k,
						 (unsigned long long) ntohll(svc_entries.service[k].id),
						 svc_entries.service[k].name);

					pr_cmd("id_ext=%s,"
					       "ioc_guid=%016llx,"
					       "dgid=%016llx%016llx,"
					       "pkey=ffff,"
					       "service_id=%016llx\n",
					       id_ext,
					       (unsigned long long) ntohll(ioc_prof.guid),
					       (unsigned long long) subnet_prefix,
					       (unsigned long long) guid,
					       (unsigned long long) ntohll(svc_entries.service[k].id));
				}
			}
		}
	}

	pr_human("\n");

	return 0;
}

static int get_port_info(int fd, uint32_t agent[2], uint16_t dlid,
			 uint64_t *subnet_prefix, int *isdm)
{
	struct ib_user_mad		out_mad, in_mad;
	struct srp_dm_rmpp_sa_mad      *out_sa_mad, *in_sa_mad;
	struct srp_dm_mad	       *in_dm_mad;
	struct srp_sa_port_info_rec    *port_info;

	in_sa_mad  = (void *) in_mad.data;
	in_dm_mad  = (void *) in_mad.data;
	out_sa_mad = (void *) out_mad.data;

	init_srp_dm_mad(&out_mad, agent[1], sm_lid, SRP_SA_ATTR_PORT_INFO, 0);

	out_sa_mad->mgmt_class 	  = SRP_MGMT_CLASS_SA;
	out_sa_mad->class_version = 2;
	out_sa_mad->comp_mask     = htonll(1); /* LID */
	port_info                 = (void *) out_sa_mad->data;
	port_info->endport_lid	  = htons(dlid);

again:
	if (write(fd, &out_mad, sizeof out_mad) != sizeof out_mad) {
		perror("write");
		return -1;
	}

	if (read(fd, &in_mad, sizeof in_mad) != sizeof in_mad) {
		if (in_mad.hdr.status == ETIMEDOUT)
			goto again;

		fprintf(stderr, "%s/%d: ", __func__, __LINE__);
		perror("read");
		return -1;
	}

	port_info = (void *) in_sa_mad->data;
	*subnet_prefix = ntohll(port_info->subnet_prefix);
	*isdm          = !!(ntohl(port_info->capability_mask) & (1 << 19));

	return 0;
}

static int get_port_list(int fd, uint32_t agent[2])
{
	struct ib_user_mad		out_mad, *in_mad;
	struct srp_dm_rmpp_sa_mad      *out_sa_mad, *in_sa_mad;
	struct srp_sa_node_rec	       *node;
	ssize_t len;
	char val[64];
	int size;
	int i;
	uint64_t subnet_prefix;
	int isdm;

	if (read_file(port_sysfs_path, "sm_lid", val, sizeof val) < 0) {
		fprintf(stderr, "Couldn't read SM LID\n");
		return -1;
	}

	sm_lid = strtol(val, NULL, 0);

	in_mad    = alloca(1 << 18);

	in_sa_mad  = (void *) in_mad->data;
	out_sa_mad = (void *) out_mad.data;

	init_srp_dm_mad(&out_mad, agent[1], sm_lid, SRP_SA_ATTR_NODE, 0);

	out_sa_mad->mgmt_class 	  = SRP_MGMT_CLASS_SA;
	out_sa_mad->method     	  = SRP_SA_METHOD_GET_TABLE;
	out_sa_mad->class_version = 2;
	out_sa_mad->comp_mask     = htonll(1ul << 4); /* node type */
	out_sa_mad->rmpp_version  = 1;
	out_sa_mad->rmpp_type     = 1;
	node                      = (void *) out_sa_mad->data;
	node->type		  = 1; /* CA */

again:
	if (write(fd, &out_mad, sizeof out_mad) != sizeof out_mad) {
		perror("write");
		return -1;
	}

	len = read(fd, in_mad, 1 << 18);
	if (len < 0) {
		fprintf(stderr, "%s/%d: ", __func__, __LINE__);
		perror("read");
		return -1;
	}

	if (in_mad->hdr.status == ETIMEDOUT)
		goto again;

	size = ntohs(in_sa_mad->attr_offset) * 8;

	for (i = 0; (i + 1) * size <= len - 56 - 36; ++i) {
		node = (void *) in_sa_mad->data + i * size;

		if (get_port_info(fd, agent, ntohs(node->lid),
				  &subnet_prefix, &isdm))
			continue;

		if (!isdm)
			continue;

		do_port(fd, agent, ntohs(node->lid),
			subnet_prefix, ntohll(node->port_guid));
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int		fd;
	uint32_t	agent[0];
	char	       *cmd_name = strdup(argv[0]);

	while (1) {
		int c;

		c = getopt(argc, argv, "cvd:");
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			umad_dev = optarg;
			break;
		case 'c':
			++cmd;
			break;
		case 'v':
			++verbose;
			break;
		default:
			usage(cmd_name);
			return 1;
		}
	}

	fd = open(umad_dev, O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	if (setup_port_sysfs_path())
		return 1;

	if (create_agent(fd, agent))
		return 1;

	get_port_list(fd, agent);

	return 0;
}
