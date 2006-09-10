/*
 * srp_daemon - discover SRP targets over IB
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2006 Mellanox Technologies Ltd.  All rights reserved.
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
 * $Author: ishai Rabinovitz [ishai@mellanox.co.il]$
 * Based on Roland Dreier's initial code [rdreier@cisco.com]
 *
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
#include <dirent.h>
#include <pthread.h>
#include <string.h>
#include <infiniband/umad.h>
#include <infiniband/common.h>
#include "srp_ib_types.h"

#include "srp_daemon.h"

#define IBDEV_STR_SIZE 16
#define IBPORT_STR_SIZE 16

const int MAX_ID_EXT_STRING_LENGTH = 17;

typedef struct {
	struct ib_user_mad hdr;
	char filler[MAD_BLOCK_SIZE];
} srp_ib_user_mad_t;

#define get_data_ptr(mad) ((void *) ((mad).hdr.data))

static char *sysfs_path = "/sys";

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s [-vVceo] [-d <umad device> | -i <infiniband device> [-p <port_num>]] [-t <timoeout (ms)>] [-r <retries>] [-R <Rescan time>]\n", argv0);
	fprintf(stderr, "-v 			Verbose\n");
	fprintf(stderr, "-V 			debug Verbose\n");
	fprintf(stderr, "-c 			prints connection Commands\n");
	fprintf(stderr, "-a 			show All - prints also targets that are already connected\n");
	fprintf(stderr, "-e 			Executes connection commands\n");
	fprintf(stderr, "-o 			runs only Once and stop\n");
	fprintf(stderr, "-d <umad device>	use umad Device \n");
	fprintf(stderr, "-i <infiniband device>	use Infiniband device \n");
	fprintf(stderr, "-p <port_num>		use Port num \n");
	fprintf(stderr, "-R <Rescan time>	perform complete Rescan every <Rescan time> seconds\n");
	fprintf(stderr, "-t <timoeout>		Timeout for mad response in milisec \n");
	fprintf(stderr, "-r <retries>		number of send Retries for each mad\n");
	fprintf(stderr, "\nExample: srp_daemon -e -i mthca0 -p 1 -R 60\n");
}

static int 
check_equal_uint64(char *dir_name, char *attr, uint64_t val)
{
uint64_t attr_value;

	if (sys_read_uint64(dir_name, attr, &attr_value))
		return 0;

	return attr_value == val;
}


int recalc(struct umad_resources *umad_res);

void pr_cmd(char *target_str, int not_connected)
{
	int ret;

	if (config->cmd)
		printf("%s", target_str);

	if (config->execute && not_connected) {
		int fd = open(config->add_target_file, O_WRONLY);
		if (fd < 0) {
			pr_err("unable to open %s, maybe ib_srp is not loaded\n", config->add_target_file);
			return;
		}
		ret = write(fd, target_str, strlen(target_str));
		pr_debug("Adding target returned %d\n", ret);
		close(fd);
	}
}


static int check_not_equal_str(char *dir_name, char *attr, char *value)
{
	const int MAX_ATTR_STRING_LENGTH=64;

 	char attr_value[MAX_ATTR_STRING_LENGTH];
	int len = strlen(value);

	if (len > MAX_ATTR_STRING_LENGTH) {
		pr_err("string %s is too long\n", value);
		return 1;
	}

	if (sys_read_string(dir_name, attr, attr_value, MAX_ATTR_STRING_LENGTH))
		return 0;
	if (strncmp(attr_value, value, len))
		return 1;

	return 0;
}

static int check_not_equal_int(char *dir_name, char *attr, int value)
{
	const int MAX_ATTR_STRING_LENGTH=64;

	char attr_value[MAX_ATTR_STRING_LENGTH];

	if (sys_read_string(dir_name, attr, attr_value, MAX_ATTR_STRING_LENGTH))
		return 0;
	if (value != atoi(attr_value))
		return 1;

	return 0;
}

static void add_non_exist_traget(char *id_ext, struct srp_dm_ioc_prof ioc_prof, 
				 uint64_t subnet_prefix, uint64_t h_guid, 
				 uint64_t h_service_id)
{
	const int MAX_SCSI_HOST_DIR_NAME_LENGTH = 50;
	char scsi_host_dir[MAX_SCSI_HOST_DIR_NAME_LENGTH];
	DIR *dir;
	struct dirent *subdir;
	char *subdir_name_ptr;
	int prefix_len;
	uint8_t dgid_val[16];
	const int MAX_TRAGET_CONFIG_STR_STRING = 255;
	char target_config_str[MAX_TRAGET_CONFIG_STR_STRING];
	int len, len_left;
	int not_connected = 1;

	pr_debug("Found an SRP traget - check if it is already connected\n");

	strcpy(scsi_host_dir, "/sys/class/scsi_host/");
	dir=opendir(scsi_host_dir);
	if (!dir) {
		perror("opendir - /sys/class/scsi_host/");
		return;
	}
	prefix_len = strlen(scsi_host_dir);
	subdir_name_ptr = scsi_host_dir + prefix_len;

	subdir = (void *) 1; /* Dummy value to enter the loop */
	while (subdir) {
	        subdir = readdir(dir);
		
		if (!subdir)
			continue;

		if (subdir->d_name[0] == '.')
			continue;

		strncpy(subdir_name_ptr, subdir->d_name,
			MAX_SCSI_HOST_DIR_NAME_LENGTH - prefix_len);
		if (!check_equal_uint64(scsi_host_dir, "id_ext", 
				        strtoull(id_ext, 0, 16)))
			continue;
		if (!check_equal_uint64(scsi_host_dir, "service_id",
					h_service_id))
			continue;
		if (!check_equal_uint64(scsi_host_dir, "ioc_guid",
					ntohll(ioc_prof.guid)))
			continue;
		if (sys_read_gid(scsi_host_dir, "dgid", dgid_val))
			continue;
		if (htonll(subnet_prefix) != *((uint64_t *) dgid_val))
			continue;
		if (htonll(h_guid) != *((uint64_t *) (dgid_val+8)))
			continue;

		/* If there is no local_ib_device in the scsi host dir (old kernel module), assumes it is equal */
		if (check_not_equal_str(scsi_host_dir, "local_ib_device", config->dev_name))
			continue;

		/* If there is no local_ib_port in the scsi host dir (old kernel module), assumes it is equal */
		if (check_not_equal_int(scsi_host_dir, "local_ib_port", config->port_num))
			continue;

		/* there is a match - this target is already connected */
		if (config->all) {
			not_connected = 0;
			break;
		}

		pr_debug("This target is alerady connected - skip\n");
		closedir(dir);

		return;

	}

	len = snprintf(target_config_str, MAX_TRAGET_CONFIG_STR_STRING, "id_ext=%s,"
		"ioc_guid=%016llx,"
		"dgid=%016llx%016llx,"
		"pkey=ffff,"
		"service_id=%016llx",
		id_ext,
		(unsigned long long) ntohll(ioc_prof.guid),
		(unsigned long long) subnet_prefix,
		(unsigned long long) h_guid,
		(unsigned long long) h_service_id);
	if (len >= MAX_TRAGET_CONFIG_STR_STRING) {
		pr_err("Target conifg string is too long, ignoring target\n");
		closedir(dir);
		return;
	}

	if (ioc_prof.io_class != htons(SRP_REV16A_IB_IO_CLASS)) {
		len_left = MAX_TRAGET_CONFIG_STR_STRING - len;
		len += snprintf(target_config_str+len, 
				MAX_TRAGET_CONFIG_STR_STRING - len,
				",io_class=%04hx", ntohs(ioc_prof.io_class));

		if (len >= MAX_TRAGET_CONFIG_STR_STRING) {
			pr_err("Target conifg string is too long, ignoring target\n");
			closedir(dir);
			return;
		}
	}

	target_config_str[len] = '\n';
	target_config_str[len+1] = '\0';

	pr_cmd(target_config_str, not_connected);

	closedir(dir);
	
}

int send_and_get(int portid, int agent, srp_ib_user_mad_t *out_mad,
		 srp_ib_user_mad_t *in_mad, int in_mad_size)
{
	struct srp_dm_mad *out_dm_mad = (void *) out_mad->hdr.data;
	struct srp_dm_mad *in_dm_mad = (void *) in_mad->hdr.data;
	int i, len;
	int in_agent;
	int ret;
	static uint32_t tid = 1;

	for (i = 0; i < config->mad_retries; ++i) {
		((uint32_t *) &out_dm_mad->tid)[1] = ++tid;

		ret = umad_send(portid, agent,
			        (struct ib_user_mad *) out_mad, MAD_BLOCK_SIZE,
				config->timeout, 0);
		if (ret < 0) {
			pr_err("umad_send to %u failed\n", 
				(uint16_t) ntohs(out_mad->hdr.addr.lid));
			return ret;
		}

		do {
			len = in_mad_size ? in_mad_size : MAD_BLOCK_SIZE;
			in_agent = umad_recv(portid, (struct ib_user_mad *) in_mad, 
					     &len, config->timeout);
			if (in_agent < 0) {
				pr_err("umad_recv from %u failed - %d\n", 
					(uint16_t) ntohs(out_mad->hdr.addr.lid), 
					in_agent);
				return in_agent;
			}
			if (in_agent != agent) {
				pr_debug("umad_recv returned different agent\n");
				continue;
			}

			ret = umad_status((struct ib_user_mad *) in_mad);
			if (ret) {
				pr_err(
					"bad MAD status (%u) from lid %d\n", 
					ret, (uint16_t) ntohs(out_mad->hdr.addr.lid));
				return -ret;
			} 

			if (tid != ((uint32_t *) &in_dm_mad->tid)[1])
				pr_debug("umad_recv returned different transaction id sent %d got %d\n", 
					 tid, ((uint32_t *) &in_dm_mad->tid)[1]);

		} while (tid > ((uint32_t *) &in_dm_mad->tid)[1]);

		if (len > 0)
			return len;
	}

	return -1;
}

static void initialize_sysfs()
{
	char *env;

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
}

static int translate_umad_to_ibdev_and_port(char *umad_dev, char **ibdev,
					    char **ibport) 
{
	char *class_dev_path;
	char *umad_dev_name;
	int ret;

	umad_dev_name = rindex(umad_dev, '/');
	if (!umad_dev_name) {
		pr_err("Couldn't find device name in '%s'\n",
			umad_dev_name);
		return -1;
	}

	ret = asprintf(&class_dev_path, "%s/class/infiniband_mad/%s", sysfs_path,
		       umad_dev_name);
	
	if (ret < 0) {
 		pr_err("out of memory\n");
		return -ENOMEM;
	}

	*ibdev = malloc(IBDEV_STR_SIZE);
	if (!*ibdev) {
 		pr_err("out of memory\n");
		ret = -ENOMEM;
		goto end;
	}

	if (sys_read_string(class_dev_path, "ibdev", *ibdev, 
			    IBDEV_STR_SIZE) < 0) {
		pr_err("Couldn't read ibdev attribute\n");
		ret = -1;
		goto end;
	}

	*ibport = malloc(IBPORT_STR_SIZE);
	if (!*ibport) {
		pr_err("out of memory\n");
		ret = -ENOMEM;
		goto end;
	}
	if (sys_read_string(class_dev_path, "port", *ibport, IBPORT_STR_SIZE) < 0) {
		pr_err("Couldn't read port attribute\n");
		ret = -1;
		goto end;
	}

	ret = 0;

end:
	free(class_dev_path);		
	return ret;
}

static void init_srp_mad(srp_ib_user_mad_t *out_umad, int agent, 
			 uint16_t h_dlid, uint16_t h_attr_id, uint32_t h_attr_mod)
{
	struct srp_dm_mad *out_mad;

	memset(out_umad, 0, sizeof *out_umad);

	out_umad->hdr.agent_id   = agent;
	out_umad->hdr.addr.qpn   = htonl(1);
	out_umad->hdr.addr.qkey  = htonl(0x80010000);
	out_umad->hdr.addr.lid   = htons(h_dlid);

	out_mad = (void *) out_umad->hdr.data;

	out_mad->base_version  = 1;
	out_mad->method        = SRP_MAD_METHOD_GET;
	out_mad->attr_id       = htons(h_attr_id);
	out_mad->attr_mod      = htonl(h_attr_mod);
}

static void init_srp_dm_mad(srp_ib_user_mad_t *out_mad, int agent, uint16_t h_dlid,
			    uint16_t h_attr_id, uint32_t h_attr_mod)
{
	ib_sa_mad_t *out_dm_mad = get_data_ptr(*out_mad);

	init_srp_mad(out_mad, agent, h_dlid, h_attr_id, h_attr_mod);
	out_dm_mad->mgmt_class = SRP_MGMT_CLASS_DM;
	out_dm_mad->class_ver  = 1;
}

static void init_srp_sa_mad(srp_ib_user_mad_t *out_mad, int agent, uint16_t h_dlid,
			    uint16_t h_attr_id, uint32_t h_attr_mod)
{
	ib_sa_mad_t *out_sa_mad = get_data_ptr(*out_mad);

	init_srp_mad(out_mad, agent, h_dlid, h_attr_id, h_attr_mod);
	out_sa_mad->mgmt_class = SRP_MGMT_CLASS_SA;
	out_sa_mad->class_ver  = SRP_MGMT_CLASS_SA_VERSION;
}

static int check_sm_cap(struct umad_resources *umad_res, int *mask_match)
{
	srp_ib_user_mad_t		out_mad, in_mad;
	struct srp_dm_rmpp_sa_mad      *in_sa_mad;
	struct srp_class_port_info     *cpi;
	int				ret;

	in_sa_mad  = get_data_ptr(in_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        SRP_MAD_ATTR_CLASS_PORT_INFO, 0);

	ret = send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0);
	if (ret < 0)
		return ret;

	cpi = (void *) in_sa_mad->data;

	*mask_match = !!(ntohs(cpi->cap_mask) & SRP_SM_SUPPORTS_MASK_MATCH);

	return 0;
}

static int set_class_port_info(struct umad_resources *umad_res, uint16_t dlid)
{
	srp_ib_user_mad_t		in_mad, out_mad;
	struct srp_dm_mad	       *out_dm_mad, *in_dm_mad;
	struct srp_class_port_info     *cpi;
	char val[64];
	int i;

	init_srp_dm_mad(&out_mad, umad_res->agent, dlid, SRP_MAD_ATTR_CLASS_PORT_INFO, 0);

	out_dm_mad = get_data_ptr(out_mad);
	out_dm_mad->method = SRP_MAD_METHOD_SET;

	cpi                = (void *) out_dm_mad->data;

	if (sys_read_string(umad_res->port_sysfs_path, "lid", val, sizeof val) < 0) {
		pr_err("Couldn't read LID\n");
		return -1;
	}

	cpi->trap_lid = htons(strtol(val, NULL, 0));

	if (sys_read_string(umad_res->port_sysfs_path, "gids/0", val, sizeof val) < 0) {
		pr_err("Couldn't read GID[0]\n");
		return -1;
	}

	for (i = 0; i < 8; ++i)
		((uint16_t *) cpi->trap_gid)[i] = htons(strtol(val + i * 5, NULL, 16));

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	in_dm_mad = get_data_ptr(in_mad);
	if (in_dm_mad->status) {
		pr_err("Class Port Info set returned status 0x%04x\n",
			ntohs(in_dm_mad->status));
		return -1;
	}

	return 0;
}

static int get_iou_info(struct umad_resources *umad_res, uint16_t dlid,
			struct srp_dm_iou_info *iou_info)
{
	srp_ib_user_mad_t		in_mad, out_mad;
	struct srp_dm_mad	       *in_dm_mad;

	init_srp_dm_mad(&out_mad, umad_res->agent, dlid, SRP_DM_ATTR_IO_UNIT_INFO, 0);

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	in_dm_mad = get_data_ptr(in_mad);
	if (in_dm_mad->status) {
		pr_err("IO Unit Info query returned status 0x%04x\n",
			ntohs(in_dm_mad->status));
		return -1;
	}

	memcpy(iou_info, in_dm_mad->data, sizeof *iou_info);
/*
	pr_debug("iou_info->max_controllers is %d\n", iou_info->max_controllers);
*/
	return 0;
}

static int get_ioc_prof(struct umad_resources *umad_res, uint16_t h_dlid, int ioc,
			struct srp_dm_ioc_prof *ioc_prof)
{
	srp_ib_user_mad_t		in_mad, out_mad;
	struct srp_dm_mad	       *in_dm_mad;

	init_srp_dm_mad(&out_mad, umad_res->agent, h_dlid, SRP_DM_ATTR_IO_CONTROLLER_PROFILE, ioc);

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	in_dm_mad = get_data_ptr(in_mad);
	if (in_dm_mad->status) {
		pr_err("IO Controller Profile query returned status 0x%04x for %d\n",
			ntohs(in_dm_mad->status), ioc);
		return -1;
	}

	memcpy(ioc_prof, in_dm_mad->data, sizeof *ioc_prof);

	return 0;
}

static int get_svc_entries(struct umad_resources *umad_res, uint16_t dlid, int ioc,
			   int start, int end, struct srp_dm_svc_entries *svc_entries)
{
	srp_ib_user_mad_t		in_mad, out_mad;
	struct srp_dm_mad	       *in_dm_mad;

	init_srp_dm_mad(&out_mad, umad_res->agent, dlid, SRP_DM_ATTR_SERVICE_ENTRIES,
			(ioc << 16) | (end << 8) | start);

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	in_dm_mad = get_data_ptr(in_mad);
	if (in_dm_mad->status) {
		pr_err("Service Entries query returned status 0x%04x\n",
			ntohs(in_dm_mad->status));
		return -1;
	}

	memcpy(svc_entries, in_dm_mad->data, sizeof *svc_entries);

	return 0;
}

static int do_port(struct umad_resources *umad_res, uint16_t dlid, uint64_t subnet_prefix,
		   uint64_t h_guid)
{
	struct srp_dm_iou_info		iou_info;
	struct srp_dm_ioc_prof		ioc_prof;
	struct srp_dm_svc_entries	svc_entries;
	int				i, j, k, ret;

	static const uint64_t topspin_oui = 0x0005ad0000000000ull;
	static const uint64_t oui_mask    = 0xffffff0000000000ull;

 	pr_debug("enter do_port\n");
	if ((h_guid & oui_mask) == topspin_oui &&
	    set_class_port_info(umad_res, dlid))
		pr_err("Warning: set of ClassPortInfo failed\n");

	ret = get_iou_info(umad_res, dlid, &iou_info);
	if (ret < 0)
		return ret;

	pr_human("IO Unit Info:\n");
	pr_human("    port LID:        %04x\n", dlid);
	pr_human("    port GID:        %016llx%016llx\n",
		 (unsigned long long) subnet_prefix, (unsigned long long) h_guid);
	pr_human("    change ID:       %04x\n", ntohs(iou_info.change_id));
	pr_human("    max controllers: 0x%02x\n", iou_info.max_controllers);

	if (config->verbose > 0)
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

			if (get_ioc_prof(umad_res, dlid, i + 1, &ioc_prof))
				continue;

			pr_human("    controller[%3d]\n", i + 1);

			pr_human("        GUID:      %016llx\n",
				 (unsigned long long) ntohll(ioc_prof.guid));
			pr_human("        vendor ID: %06x\n", ntohl(ioc_prof.vendor_id) >> 8);
			pr_human("        device ID: %06x\n", ntohl(ioc_prof.device_id));
			pr_human("        IO class : %04hx\n", ntohs(ioc_prof.io_class));
			pr_human("        ID:        %s\n", ioc_prof.id);
			pr_human("        service entries: %d\n", ioc_prof.service_entries);

			for (j = 0; j < ioc_prof.service_entries; j += 4) {
				int n;

				n = j + 3;
				if (n >= ioc_prof.service_entries)
					n = ioc_prof.service_entries - 1;

				if (get_svc_entries(umad_res, dlid, i + 1,
						    j, n, &svc_entries))
					continue;

				for (k = 0; k <= n - j; ++k) {
					char id_ext[MAX_ID_EXT_STRING_LENGTH];

					if (sscanf(svc_entries.service[k].name,
						   "SRP.T10:%16s",
						   id_ext) != 1)
						continue;

					pr_human("            service[%3d]: %016llx / %s\n",
						 j + k,
						 (unsigned long long) ntohll(svc_entries.service[k].id),
						 svc_entries.service[k].name);

					add_non_exist_traget(id_ext, ioc_prof, subnet_prefix, h_guid,
							     ntohll(svc_entries.service[k].id));
				}
			}
		}
	}

	pr_human("\n");

	return 0;
}

int get_node(struct umad_resources *umad_res, uint16_t dlid, uint64_t *guid)
{
	srp_ib_user_mad_t		out_mad, in_mad;
	struct srp_dm_rmpp_sa_mad      *out_sa_mad, *in_sa_mad;
	struct srp_sa_node_rec	       *node;

	in_sa_mad = get_data_ptr(in_mad);
	out_sa_mad = get_data_ptr(out_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        SRP_SA_ATTR_NODE, 0);

	out_sa_mad->comp_mask     = htonll(1); /* LID */
	node			  = (void *) out_sa_mad->data;
	node->lid		  = htons(dlid);

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	node  = (void *) in_sa_mad->data;
	*guid = ntohll(node->port_guid);

	return 0;
}

static int get_port_info(struct umad_resources *umad_res, uint16_t dlid,
			 uint64_t *subnet_prefix, int *isdm)
{
	srp_ib_user_mad_t		out_mad, in_mad;
	struct srp_dm_rmpp_sa_mad      *out_sa_mad, *in_sa_mad;
	struct srp_sa_port_info_rec    *port_info;

	in_sa_mad = get_data_ptr(in_mad);
	out_sa_mad = get_data_ptr(out_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        SRP_SA_ATTR_PORT_INFO, 0);

	out_sa_mad->comp_mask     = htonll(1); /* LID */
	port_info                 = (void *) out_sa_mad->data;
	port_info->endport_lid	  = htons(dlid);

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	port_info = (void *) in_sa_mad->data;
	*subnet_prefix = ntohll(port_info->subnet_prefix);
	*isdm          = !!(ntohl(port_info->capability_mask) & SRP_IS_DM);

	return 0;
}

static int do_dm_port_list(struct umad_resources *umad_res)
{
	uint8_t                         in_mad_buf[node_table_response_size];
	srp_ib_user_mad_t		out_mad;
	struct ib_user_mad	       *in_mad;
	struct srp_dm_rmpp_sa_mad      *out_sa_mad, *in_sa_mad;
	struct srp_sa_port_info_rec    *port_info;
	ssize_t len;
	int size;
	int i;
	uint64_t guid;

	in_mad     = (void *) in_mad_buf;
	in_sa_mad  = (void *) in_mad->data;
	out_sa_mad = get_data_ptr(out_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        SRP_SA_ATTR_PORT_INFO, SRP_SM_CAP_MASK_MATCH_ATTR_MOD);

	out_sa_mad->method     	   = SRP_SA_METHOD_GET_TABLE;
	out_sa_mad->comp_mask      = htonll(1 << 7); /* Capability mask */
	out_sa_mad->rmpp_version   = 1;
	out_sa_mad->rmpp_type      = 1;
	port_info		   = (void *) out_sa_mad->data;
	port_info->capability_mask = htonl(SRP_IS_DM); /* IsDM */

	len = send_and_get(umad_res->portid, umad_res->agent, &out_mad, (srp_ib_user_mad_t *) in_mad, node_table_response_size);
	if (len < 0)
		return len;

	size = ib_get_attr_size(in_sa_mad->attr_offset);

	for (i = 0; (i + 1) * size <= len - MAD_RMPP_HDR_SIZE; ++i) {
		port_info = (void *) in_sa_mad->data + i * size;

		if (get_node(umad_res, ntohs(port_info->endport_lid), &guid))
			continue;

		(void) do_port(umad_res, ntohs(port_info->endport_lid),
			       ntohll(port_info->subnet_prefix), guid);
	}

	return 0;
}

void handle_port(struct umad_resources *umad_res, uint16_t lid, uint64_t h_guid)
{
	uint64_t subnet_prefix;
	int isdm;

 	pr_debug("enter handle_port for lid %d\n", lid);
	if (get_port_info(umad_res, lid, &subnet_prefix, &isdm))
		return;

	if (!isdm)
		return;

	(void) do_port(umad_res, lid, subnet_prefix, h_guid);
}


static int do_full_port_list(struct umad_resources *umad_res)
{
	uint8_t                         in_mad_buf[node_table_response_size];
	srp_ib_user_mad_t		out_mad;
	struct ib_user_mad	       *in_mad;
	struct srp_dm_rmpp_sa_mad      *out_sa_mad, *in_sa_mad;
	struct srp_sa_node_rec	       *node;
	ssize_t len;
	int size;
	int i;

	in_mad     = (void *) in_mad_buf;
	in_sa_mad  = (void *) in_mad->data;
	out_sa_mad = get_data_ptr(out_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        SRP_SA_ATTR_NODE, 0);

	out_sa_mad->method     	  = SRP_SA_METHOD_GET_TABLE;
	out_sa_mad->comp_mask     = 0; /* Get all end ports */
	out_sa_mad->rmpp_version  = 1;
	out_sa_mad->rmpp_type     = 1;

	len = send_and_get(umad_res->portid, umad_res->agent, &out_mad, (srp_ib_user_mad_t *) in_mad, node_table_response_size);
	if (len < 0)
		return len;

	size = ntohs(in_sa_mad->attr_offset) * 8;

	for (i = 0; (i + 1) * size <= len - MAD_RMPP_HDR_SIZE; ++i) {
		node = (void *) in_sa_mad->data + i * size;

		(void) handle_port(umad_res, ntohs(node->lid), 
			    ntohll(node->port_guid));
	}

	return 0;
}

struct config_t *config;

static void print_config(struct config_t *conf)
{
	printf(" configuration report\n");
	printf(" ------------------------------------------------\n");
	printf(" Current pid                		: %u\n", getpid());
	printf(" Device name                		: \"%s\"\n", conf->dev_name);
	printf(" IB port                    		: %u\n", conf->port_num);
	printf(" Mad Retries                		: %d\n", conf->mad_retries);
	printf(" Number of outstanding WR   		: %u\n", conf->num_of_oust);
	printf(" Mad timeout (msec)	     		: %u\n", conf->timeout);
	printf(" Prints add target command  		: %d\n", conf->cmd);
 	printf(" Executes add target command		: %d\n", conf->execute);
 	printf(" Print also connected targets 		: %d\n", conf->all);
 	printf(" Report current tragets and stop 	: %d\n", conf->once);
	if (conf->recalc_time)
		printf(" Performs full target rescan every %d seconds\n", conf->recalc_time);
	else
		printf(" No full target rescan\n");
	printf(" ------------------------------------------------\n");
}		

static int get_config(struct config_t *conf, int argc, char *argv[])
{
	/* set defaults */
	char* umad_dev   = "/dev/infiniband/umad0";
	char *ibport;
	int ret;
	int len;

	conf->port_num		= 1;
	conf->num_of_oust	= 10;
	conf->dev_name	 	= NULL;
	conf->cmd	 	= 0;
	conf->once	 	= 0;
	conf->execute	 	= 0;
	conf->all	 	= 0;
	conf->verbose	 	= 0;
	conf->debug_verbose    	= 0;
	conf->timeout	 	= 5000;
	conf->mad_retries 	= 3;
	conf->recalc_time 	= 0;
	conf->add_target_file   = NULL;

	while (1) {
		int c;

		c = getopt(argc, argv, "caveod:i:p:t:r:R:Vh");
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			umad_dev = optarg;
			break;
		case 'i':		  
			len = strlen(optarg)+1;
			conf->dev_name = malloc(len);
			if (!conf->dev_name) {
				pr_err("Fail to alloc space for dev_name\n");
				return -ENOMEM;
			}
			strncpy(conf->dev_name, optarg, len);
			break;
		case 'p':
			conf->port_num = atoi(optarg);
			if (conf->port_num == 0) {
				pr_err("Bad port number %s\n", optarg);
				return -1;
			}
			break;
		case 'c':
			++conf->cmd;
			break;
		case 'o':
			++conf->once;
			break;
		case 'a':
			++conf->all;
			break;
		case 'e':
			++conf->execute;
			break;
		case 'v':
			++conf->verbose;
			break;
		case 'V':
			++conf->debug_verbose;
			break;
		case 't':
			conf->timeout = atoi(optarg);
			if (conf->timeout == 0) {
				pr_err("Bad timeout - %s\n", optarg);
				return -1;
			}
			break;
		case 'r':
			conf->mad_retries = atoi(optarg);
			if (conf->mad_retries == 0) {
				pr_err("Bad number of retries - %s\n", optarg);
				return -1;
			}
			break;
		case 'R':
			conf->recalc_time = atoi(optarg);
			if (conf->recalc_time == 0) {
				pr_err("Bad Rescan time window - %s\n", optarg);
				return -1;
			}
			break;
		case 'h':
		default:
			usage(argv[0]);
			return -1;
		}
	}

	initialize_sysfs();

	if (conf->dev_name == NULL) {
		if (translate_umad_to_ibdev_and_port(umad_dev, &conf->dev_name, &ibport)) {
			pr_err(
				"Fail to translate umad to ibdev and port\n");
			return -1;
		}
		conf->port_num = atoi(ibport);
		if (conf->port_num == 0) {
			pr_err("Bad port number %s\n", ibport);
			free(conf->dev_name);
			free(ibport);
			return -1;
		}
		free(ibport);
	}
	ret = asprintf(&conf->add_target_file,
		       "%s/class/infiniband_srp/srp-%s-%d/add_target", sysfs_path,
		       conf->dev_name, conf->port_num);
	if (ret < 0) {
		pr_err("error while allocating add_target\n");
		return ret;
	}
		 
	return 0;
}

static void config_destroy(struct config_t *conf)
{
	if (conf->dev_name)
		free(conf->dev_name);

	if (conf->add_target_file)
		free(conf->add_target_file);
}

static void umad_resources_init(struct umad_resources *umad_res)
{
	umad_res->portid = -1;
	umad_res->agent = -1;
	umad_res->agent = -1;
	umad_res->port_sysfs_path = NULL;
}

static void umad_resources_destroy(struct umad_resources *umad_res)
{
	if (umad_res->port_sysfs_path)
		free(umad_res->port_sysfs_path);

	if (umad_res->agent != -1)
		umad_unregister(umad_res->portid, umad_res->agent);

	if (umad_res->agent != -1)
		umad_unregister(umad_res->portid, umad_res->agent);

	umad_done();
}

static int umad_resources_create(struct umad_resources *umad_res)
{

	int ret;

	ret = asprintf(&umad_res->port_sysfs_path, "%s/class/infiniband/%s/ports/%d",
		       sysfs_path, config->dev_name, config->port_num);

	if (ret == -1) {
		umad_res->port_sysfs_path = NULL;
		return -ENOMEM;
	}

	umad_res->portid = umad_open_port(config->dev_name, config->port_num);
	if (umad_res->portid < 0) {
		pr_err(
			"umad_open_port failed for device %s port %d\n", 
			config->dev_name, config->port_num);
		return -ENXIO;
	}

	umad_res->agent = umad_register(umad_res->portid, SRP_MGMT_CLASS_SA, 
					   SRP_MGMT_CLASS_SA_VERSION, 
					   SRP_SA_RMPP_VERSION, 0); 
	if (umad_res->agent < 0) {
		pr_err("umad_register failed\n");
		return umad_res->agent;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	pthread_t 		thread[3];
	int			ret;
	struct resources	res;
	int                     thread_id[3];
	uint16_t 		lid; 
	ib_gid_t 		gid; 

	res.umad_res = malloc(sizeof(struct umad_resources));
	if (!res.umad_res) {
 		pr_err("out of memory\n");
		return ENOMEM;
	}	  
	res.ud_res = malloc(sizeof(struct ud_resources));
	if (!res.ud_res) {
 		pr_err("out of memory\n");
		ret = ENOMEM;
		goto free_umad;
	}	  

	res.sync_res = malloc(sizeof(struct sync_resources));
	if (!res.sync_res) {
 		pr_err("out of memory\n");
		ret = ENOMEM;
		goto free_res;
	}	  

	config = malloc(sizeof(*config));
	if (!config) {
 		pr_err("out of memory\n");
		ret = ENOMEM;
		goto free_res;
	}

	if (get_config(config, argc, argv)) {
		ret = EINVAL;
		goto free_all;
	}

	if (config->verbose)
		print_config(config);

	ret = umad_init();
	if (ret < 0) {
		pr_err("umad_init failed\n");
		ret = -ret;
		goto clean_config;
	}

	umad_resources_init(res.umad_res);
	ret = umad_resources_create(res.umad_res);
	if (ret)
		goto clean_umad;

	if (config->once) {
		ret = recalc(res.umad_res);
		goto clean_umad;
	}
	  
	ud_resources_init(res.ud_res);
	ret = ud_resources_create(res.ud_res);
	if (ret) 
		goto clean_all;

	ret = sync_resources_init(res.sync_res);
	if (ret) 
		goto clean_all;

	thread_id[0] = pthread_create(&thread[0], NULL, run_thread_get_trap_notices, (void *) &res);
	if (thread_id[0] < 0) {
		ret=thread_id[0];
		goto clean_all;
	}

	thread_id[1] = pthread_create(&thread[1], NULL, run_thread_listen_to_events, (void *) &res);
	if (thread_id[1] < 0) {
		ret=thread_id[0];
		goto clean_all;
	}

	if (config->recalc_time) {
		thread_id[2] = pthread_create(&thread[2], NULL, run_thread_wait_till_timeout, (void *) &res);
		if (thread_id[2] < 0) {
			ret=thread_id[0];
			goto clean_all;
		}
	}

	while (1) {
		pthread_mutex_lock(&res.sync_res->mutex);
		if (res.sync_res->recalc) {
			pthread_mutex_unlock(&res.sync_res->mutex);		  
			pr_debug("Starting a recalculation\n");
			ret = create_ah(res.ud_res);
			if (ret) 
				goto kill_threads;
			
			if (register_to_traps(res.ud_res))
				pr_err("Fail to register to traps, maybe there is no opensm running on fabric\n");

			clear_traps_list(res.sync_res);
			res.sync_res->next_recalc_time = time(NULL) + config->recalc_time;
			res.sync_res->recalc = 0;
			ret = recalc(res.umad_res);
			if (ret) 
				goto kill_threads;
		} else if (pop_from_list(res.sync_res, &lid, &gid)) {
			pthread_mutex_unlock(&res.sync_res->mutex);
			if (lid) {
				uint64_t guid;
				ret = get_node(res.umad_res, lid, &guid);
				if (ret)
					/* unexpected error - do a full rescan */
					res.sync_res->recalc = 1;
				else
					handle_port(res.umad_res, lid, guid);
			} else {
				ret = get_lid(res.umad_res, &gid, &lid);
				if (ret < 0)
					/* unexpected error - do a full rescan */
					res.sync_res->recalc = 1;
				else {
					pr_debug("lid is %d\n", lid);

					srp_sleep(0, 100);
					handle_port(res.umad_res, lid,
						    ntohll(ib_gid_get_guid(&gid)));
				}
			}
		} else {
			pthread_cond_wait(&res.sync_res->cond, &res.sync_res->mutex);
			pthread_mutex_unlock(&res.sync_res->mutex);
		}
	}

	ret = 0;

kill_threads:
	res.sync_res->stop_threads = 1;
	/*
	pthread_join(thread_id[0], (void **)&status);
      	pthread_join(thread_id[1], (void **)&status);
	if (config->recalc_time)
		pthread_join(thread_id[2], (void **)&status);
	*/
clean_all:
	ud_resources_destroy(res.ud_res);
clean_umad:
	umad_resources_destroy(res.umad_res);
clean_config:
	config_destroy(config);
free_all:
	free(config);
free_res:
	free(res.ud_res);
free_umad:
	free(res.umad_res);

	exit(-ret);
}

int recalc(struct umad_resources *umad_res)
{
	int  mask_match;
	char val[6];
	int ret;

	ret = sys_read_string(umad_res->port_sysfs_path, "sm_lid", val, sizeof val); 
	if (ret < 0) {
		pr_err("Couldn't read SM LID\n");
		return ret;
	}

	umad_res->sm_lid = strtol(val, NULL, 0);
	if (umad_res->sm_lid == 0) {
		pr_err("SM LID is 0, maybe no opesm is running\n");
		return -1;
	}

	ret = check_sm_cap(umad_res, &mask_match);
	if (ret < 0)
		return ret;

	if (mask_match) {
		pr_debug("Advanced SM, performing a capability query\n");
		ret = do_dm_port_list(umad_res);
	} else {
		pr_debug("Old SM, performing a full node query\n");
		ret = do_full_port_list(umad_res);
	}

	return ret;
}

int get_lid(struct umad_resources *umad_res, ib_gid_t *gid, uint16_t *lid)
{
	srp_ib_user_mad_t		out_mad, in_mad;
	struct srp_dm_rmpp_sa_mad 	*in_sa_mad  = get_data_ptr(in_mad);
	struct srp_dm_rmpp_sa_mad 	*out_sa_mad = get_data_ptr(out_mad);
	ib_path_rec_t			*path_rec   = (ib_path_rec_t *) out_sa_mad->data;

	memset(&in_mad, 0, sizeof(in_mad));
	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        SRP_SA_ATTR_PATH_REC, 0);

	out_sa_mad->comp_mask = htonll( 4 | 8 | 64 | 512 | 4096 );

	path_rec->sgid = *gid;
	path_rec->dgid = *gid;
	path_rec->num_path = 1;
	path_rec->hop_flow_raw = htonl(1 << 31); /* rawtraffic=1 hoplimit = 0 */

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	path_rec = (ib_path_rec_t *) in_sa_mad->data;

	*lid = ntohs(path_rec->dlid);

	return 0;
}
