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

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/types.h>
#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <dirent.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <sys/syslog.h>
#include <infiniband/umad.h>
#include <infiniband/umad_types.h>
#include <infiniband/umad_sa.h>
#include "srp_ib_types.h"

#include "srp_daemon.h"

#define IBDEV_STR_SIZE 16
#define IBPORT_STR_SIZE 16
#define IGNORE(value) do { if (value) { } } while (0)
#define max_t(type, x, y) ({                    \
	type __max1 = (x);	\
	type __max2 = (y);	\
	__max1 > __max2 ? __max1: __max2; })

#define get_data_ptr(mad) ((void *) ((mad).hdr.data))

enum log_dest { log_to_syslog, log_to_stderr };

static int get_lid(struct umad_resources *umad_res, union umad_gid *gid,
		   uint16_t *lid);

static const int   node_table_response_size = 1 << 18;
static const char *sysfs_path = "/sys";
static enum log_dest s_log_dest = log_to_syslog;
static int wakeup_pipe[2] = { -1, -1 };


void wake_up_main_loop(char ch)
{
	int res;

	assert(wakeup_pipe[1] >= 0);
	res = write(wakeup_pipe[1], &ch, 1);
	IGNORE(res);
}

static void signal_handler(int signo)
{
	wake_up_main_loop(signo);
}

/*
 * Return either the received signal (SIGINT, SIGTERM, ...) or 0 if no signal
 * has been received before the timeout has expired.
 */
static int get_received_signal(time_t tv_sec, suseconds_t tv_usec)
{
	int fd, ret, received_signal = 0;
	fd_set rset;
	struct timeval timeout;
	char buf[16];

	fd = wakeup_pipe[0];
	FD_ZERO(&rset);
	FD_SET(fd, &rset);
	timeout.tv_sec = tv_sec;
	timeout.tv_usec = tv_usec;
	ret = select(fd + 1, &rset, NULL, NULL, &timeout);
	if (ret < 0)
		assert(errno == EINTR);
	while ((ret = read(fd, buf, sizeof(buf))) > 0)
		received_signal = buf[ret - 1];

	return received_signal;
}

static int check_process_uniqueness(struct config_t *conf)
{
	char path[256];
	int fd;

	snprintf(path, sizeof(path), SRP_DEAMON_LOCK_PREFIX "_%s_%d",
		 conf->dev_name, conf->port_num);

	if ((fd = open(path, O_CREAT|O_RDWR,
		       S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR)) < 0) {
		pr_err("cannot open file \"%s\" (errno: %d).\n", path, errno);
		return -1;
	}

	fchmod(fd, S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR|S_IWGRP|S_IWOTH);
	if (0 != lockf(fd, F_TLOCK, 0)) {
		pr_err("failed to lock %s (errno: %d). possibly another "
		       "srp_daemon is locking it\n", path, errno);
		close(fd);
		fd = -1;
	}

	return fd;
}

static int srpd_sys_read_string(const char *dir_name, const char *file_name,
				char *str, int max_len)
{
	char path[256], *s;
	int fd, r;

	snprintf(path, sizeof(path), "%s/%s", dir_name, file_name);

	if ((fd = open(path, O_RDONLY)) < 0)
		return (errno > 0) ? -errno : errno;

	if ((r = read(fd, str, max_len)) < 0) {
		int e = errno;
		close(fd);
		return (e > 0) ? -e : e;
	}

	str[(r < max_len) ? r : max_len - 1] = 0;

	if ((s = strrchr(str, '\n')))
		*s = 0;

	close(fd);
	return 0;
}

static int srpd_sys_read_gid(const char *dir_name, const char *file_name,
			     uint8_t *gid)
{
	char buf[64], *str, *s;
	__be16 *ugid = (__be16 *)gid;
	int r, i;

	if ((r = srpd_sys_read_string(dir_name, file_name, buf, sizeof(buf))) < 0)
		return r;

	for (s = buf, i = 0 ; i < 8; i++) {
		if (!(str = strsep(&s, ": \t\n")))
			return -EINVAL;
		ugid[i] = htobe16(strtoul(str, NULL, 16) & 0xffff);
	}

	return 0;
}

static int srpd_sys_read_uint64(const char *dir_name, const char *file_name,
				uint64_t *u)
{
	char buf[32];
	int r;

	if ((r = srpd_sys_read_string(dir_name, file_name, buf, sizeof(buf))) < 0)
		return r;

	*u = strtoull(buf, NULL, 0);

	return 0;
}




static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s [-vVcaeon] [-d <umad device> | -i <infiniband device> [-p <port_num>]] [-t <timeout (ms)>] [-r <retries>] [-R <rescan time>] [-f <rules file>\n", argv0);
	fprintf(stderr, "-v 			Verbose\n");
	fprintf(stderr, "-V 			debug Verbose\n");
	fprintf(stderr, "-c 			prints connection Commands\n");
	fprintf(stderr, "-a 			show All - prints also targets that are already connected\n");
	fprintf(stderr, "-e 			Executes connection commands\n");
	fprintf(stderr, "-o 			runs only Once and stop\n");
	fprintf(stderr, "-d <umad device>	use umad Device \n");
	fprintf(stderr, "-i <infiniband device>	use InfiniBand device \n");
	fprintf(stderr, "-p <port_num>		use Port num \n");
	fprintf(stderr, "-j <dev>:<port_num>	use the IB dev / port_num combination \n");
	fprintf(stderr, "-R <rescan time>	perform complete Rescan every <rescan time> seconds\n");
	fprintf(stderr, "-T <retry timeout>	Retries to connect to existing target after Timeout of <retry timeout> seconds\n");
	fprintf(stderr, "-l <tl_retry timeout>	Transport retry count before failing IO. should be in range [2..7], (default 2)\n");
	fprintf(stderr, "-f <rules file>	use rules File to set to which target(s) to connect (default: " SRP_DEAMON_CONFIG_FILE ")\n");
	fprintf(stderr, "-t <timeout>		Timeout for mad response in milliseconds\n");
	fprintf(stderr, "-r <retries>		number of send Retries for each mad\n");
	fprintf(stderr, "-n 			New connection command format - use also initiator extension\n");
	fprintf(stderr, "--systemd		Enable systemd integration.\n");
	fprintf(stderr, "\nExample: srp_daemon -e -n -i mthca0 -p 1 -R 60\n");
}

static int
check_equal_uint64(char *dir_name, const char *attr, uint64_t val)
{
	uint64_t attr_value;

	if (srpd_sys_read_uint64(dir_name, attr, &attr_value))
		return 0;

	return attr_value == val;
}

static int
check_equal_uint16(char *dir_name, const char *attr, uint16_t val)
{
	uint64_t attr_value;

	if (srpd_sys_read_uint64(dir_name, attr, &attr_value))
		return 0;

	return val == (attr_value & 0xffff);
}

static int recalc(struct resources *res);

static void pr_cmd(char *target_str, int not_connected)
{
	int ret;

	if (config->cmd)
		printf("%s\n", target_str);

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

void pr_debug(const char *fmt, ...)
{
	va_list args;

	if (!config->debug_verbose)
		return;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

void pr_err(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	switch (s_log_dest) {
	case log_to_syslog:
		vsyslog(LOG_DAEMON | LOG_ERR, fmt, args);
		break;
	case log_to_stderr:
		vfprintf(stderr, fmt, args);
		break;
	}
	va_end(args);
}

static int check_not_equal_str(const char *dir_name, const char *attr,
			       const char *value)
{
	char attr_value[64];
	int len = strlen(value);

	if (len > sizeof(attr_value)) {
		pr_err("string %s is too long\n", value);
		return 1;
	}

	if (srpd_sys_read_string(dir_name, attr, attr_value,
				 sizeof(attr_value)))
		return 0;
	if (strncmp(attr_value, value, len))
		return 1;

	return 0;
}

static int check_not_equal_int(const char *dir_name, const char *attr,
			       int value)
{
	char attr_value[64];

	if (srpd_sys_read_string(dir_name, attr, attr_value,
				 sizeof(attr_value)))
		return 0;
	if (value != atoi(attr_value))
		return 1;

	return 0;
}

static int is_enabled_by_rules_file(struct target_details *target)
{
	int rule;
	struct config_t *conf = config;

	if (NULL == conf->rules) {
		pr_debug("Allowing SRP target with id_ext %s because not using a rules file\n", target->id_ext);
		return 1;
	}

	rule = -1;
	do {
		rule++;
		if (conf->rules[rule].id_ext[0] != '\0' &&
		    strtoull(target->id_ext, NULL, 16) !=
		    strtoull(conf->rules[rule].id_ext, NULL, 16))
			continue;

		if (conf->rules[rule].ioc_guid[0] != '\0' &&
		    be64toh(target->ioc_prof.guid) !=
		    strtoull(conf->rules[rule].ioc_guid, NULL, 16))
			continue;

		if (conf->rules[rule].dgid[0] != '\0') {
			char tmp = conf->rules[rule].dgid[16];
			conf->rules[rule].dgid[16] = '\0';
			if (strtoull(conf->rules[rule].dgid, NULL, 16) !=
			    target->subnet_prefix) {
				conf->rules[rule].dgid[16] = tmp;
				continue;
			}
			conf->rules[rule].dgid[16] = tmp;
			if (strtoull(&conf->rules[rule].dgid[16], NULL, 16) !=
			    target->h_guid)
				continue;
		}

		if (conf->rules[rule].service_id[0] != '\0' &&
		    strtoull(conf->rules[rule].service_id, NULL, 16) !=
	            target->h_service_id)
			continue;

		if (conf->rules[rule].pkey[0] != '\0' &&
		    (uint16_t)strtoul(conf->rules[rule].pkey, NULL, 16) !=
	            target->pkey)
			continue;

		target->options = conf->rules[rule].options;

		pr_debug("SRP target with id_ext %s %s by rules file\n",
				target->id_ext,
				conf->rules[rule].allow ? "allowed" : "disallowed");
		return conf->rules[rule].allow;

	} while (1);
}


static bool use_imm_data(void)
{
	bool ret = false;
	char flag = 0;
	int cnt;
	int fd = open("/sys/module/ib_srp/parameters/use_imm_data", O_RDONLY);

	if (fd < 0)
		return false;
	cnt = read(fd, &flag, 1);
	if (cnt != 1) {
		close(fd);
		return false;
	}

	if (!strncmp(&flag, "Y", 1))
		ret = true;
	close(fd);
	return ret;
}

static bool imm_data_size_gt_send_size(unsigned int send_size)
{
	bool ret = false;
	unsigned int srp_max_imm_data = 0;
	FILE *fp = fopen("/sys/module/ib_srp/parameters/max_imm_data", "r");
	int cnt;

	if (fp == NULL)
		return ret;

	cnt = fscanf(fp, "%d", &srp_max_imm_data);
	if (cnt <= 0) {
		fclose(fp);
		return ret;
	}

	if (srp_max_imm_data > send_size)
		ret = true;

	fclose(fp);
	return ret;
}

static int add_non_exist_target(struct target_details *target)
{
	char scsi_host_dir[256];
	DIR *dir;
	struct dirent *subdir;
	char *subdir_name_ptr;
	int prefix_len;
	union umad_gid dgid_val;
	char target_config_str[255];
	int len;
	int not_connected = 1;
	unsigned int send_size;

	pr_debug("Found an SRP target with id_ext %s - check if it is already connected\n", target->id_ext);

	strcpy(scsi_host_dir, "/sys/class/scsi_host/");
	dir=opendir(scsi_host_dir);
	if (!dir) {
		perror("opendir - /sys/class/scsi_host/");
		return -1;
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
			sizeof(scsi_host_dir) - prefix_len);
		if (!check_equal_uint64(scsi_host_dir, "id_ext",
				        strtoull(target->id_ext, NULL, 16)))
			continue;
		if (!check_equal_uint16(scsi_host_dir, "pkey", target->pkey) &&
		    !config->execute)
			continue;

		if (!check_equal_uint64(scsi_host_dir, "service_id",
					target->h_service_id))
			continue;
		if (!check_equal_uint64(scsi_host_dir, "ioc_guid",
					be64toh(target->ioc_prof.guid)))
			continue;
		if (srpd_sys_read_gid(scsi_host_dir, "orig_dgid",
				      dgid_val.raw)) {
			/*
			 * In case this is an old kernel that does not have
			 * orig_dgid in sysfs, use dgid instead (this is
			 * problematic when there is a dgid redirection
			 * by the CM)
			 */
			if (srpd_sys_read_gid(scsi_host_dir, "dgid",
					      dgid_val.raw))
				continue;
		}
		if (htobe64(target->subnet_prefix) !=
		    dgid_val.global.subnet_prefix)
			continue;
		if (htobe64(target->h_guid) != dgid_val.global.interface_id)
			continue;

		/* If there is no local_ib_device in the scsi host dir (old kernel module), assumes it is equal */
		if (check_not_equal_str(scsi_host_dir, "local_ib_device", config->dev_name))
			continue;

		/* If there is no local_ib_port in the scsi host dir (old kernel module), assumes it is equal */
		if (check_not_equal_int(scsi_host_dir, "local_ib_port", config->port_num))
			continue;

		/* there is a match - this target is already connected */

		/* There is a rare possibility of a race in the following
		   scenario:
			a. A link goes down,
			b. ib_srp decide to remove the corresponding scsi_host.
			c. Before removing it, the link returns
			d. srp_daemon gets trap 64.
			e. srp_daemon thinks that this target is still
			   connected (ib_srp has not removed it yet) so it
			   does not connect to it.
			f. ib_srp continue to remove the scsi_host.
		    As a result there is no connection to a target in the fabric
		    and there will not be a new trap.

		   To solve this race we schedule here another call to check
		   if this target exist in the near future.
		*/



		/* If there is a need to print all we will continue to pr_cmd.
		   not_connected is set to zero to make sure that this target
		   will be printed but not connected.
		*/
		if (config->all) {
			not_connected = 0;
			break;
		}

		pr_debug("This target is already connected - skip\n");
		closedir(dir);

		return 0;

	}

	len = snprintf(target_config_str, sizeof(target_config_str), "id_ext=%s,"
		"ioc_guid=%016llx,"
		"dgid=%016llx%016llx,"
		"pkey=%04x,"
		"service_id=%016llx",
		target->id_ext,
		(unsigned long long) be64toh(target->ioc_prof.guid),
		(unsigned long long) target->subnet_prefix,
		(unsigned long long) target->h_guid,
		target->pkey,
		(unsigned long long) target->h_service_id);
	if (len >= sizeof(target_config_str)) {
		pr_err("Target config string is too long, ignoring target\n");
		closedir(dir);
		return -1;
	}

	if (target->ioc_prof.io_class != htobe16(SRP_REV16A_IB_IO_CLASS)) {
		len += snprintf(target_config_str+len,
				sizeof(target_config_str) - len,
				",io_class=%04hx", be16toh(target->ioc_prof.io_class));

		if (len >= sizeof(target_config_str)) {
			pr_err("Target config string is too long, ignoring target\n");
			closedir(dir);
			return -1;
		}
	}

	if (config->print_initiator_ext) {
		len += snprintf(target_config_str+len,
				sizeof(target_config_str) - len,
				",initiator_ext=%016llx",
				(unsigned long long) target->h_guid);

		if (len >= sizeof(target_config_str)) {
			pr_err("Target config string is too long, ignoring target\n");
			closedir(dir);
			return -1;
		}
	}

	if (config->execute && config->tl_retry_count) {
		len += snprintf(target_config_str + len,
				sizeof(target_config_str) - len,
				",tl_retry_count=%d", config->tl_retry_count);

		if (len >= sizeof(target_config_str)) {
			pr_err("Target config string is too long, ignoring target\n");
			closedir(dir);
			return -1;
		}
	}

	if (target->options) {
		len += snprintf(target_config_str+len,
				sizeof(target_config_str) - len,
				"%s",
				target->options);

		if (len >= sizeof(target_config_str)) {
			pr_err("Target config string is too long, ignoring target\n");
			closedir(dir);
			return -1;
		}
	}

	/*
	 * The SRP initiator stops parsing parameters if it encounters
	 * an unrecognized parameter. Rest parameters will be ignored.
	 * Append 'max_it_iu_size' in the very end of login string to
	 * avoid breaking SRP login.
	 */
	send_size = be32toh(target->ioc_prof.send_size);
	if (use_imm_data() && imm_data_size_gt_send_size(send_size)) {
		len += snprintf(target_config_str+len,
			sizeof(target_config_str) - len,
			",max_it_iu_size=%d", send_size);

		if (len >= sizeof(target_config_str)) {
			pr_err("Target config string is too long, ignoring target\n");
			closedir(dir);
			return -1;
		}
	}

	target_config_str[len] = '\0';

	pr_cmd(target_config_str, not_connected);

	closedir(dir);

	return 1;
}

static int send_and_get(int portid, int agent, struct srp_ib_user_mad *out_mad,
		 struct srp_ib_user_mad *in_mad, int in_mad_size)
{
	struct umad_dm_packet *out_dm_mad = (void *) out_mad->hdr.data;
	struct umad_dm_packet *in_dm_mad = (void *) in_mad->hdr.data;
	int i, len;
	int in_agent;
	int ret;
	static uint32_t tid;
	uint32_t received_tid;

	for (i = 0; i < config->mad_retries; ++i) {
		/* Skip tid 0 because OpenSM ignores it. */
		if (++tid == 0)
			++tid;
		out_dm_mad->mad_hdr.tid = htobe64(tid);

		ret = umad_send(portid, agent, out_mad, MAD_BLOCK_SIZE,
				config->timeout, 0);
		if (ret < 0) {
			pr_err("umad_send to %u failed\n",
				(uint16_t) be16toh(out_mad->hdr.addr.lid));
			return ret;
		}

		do {
recv:
			len = in_mad_size ? in_mad_size : MAD_BLOCK_SIZE;
			in_agent = umad_recv(portid, (struct ib_user_mad *) in_mad,
					     &len, config->timeout);
			if (in_agent < 0) {
				pr_err("umad_recv from %u failed - %d\n",
					(uint16_t) be16toh(out_mad->hdr.addr.lid),
					in_agent);
				return in_agent;
			}
			if (in_agent != agent) {
				pr_debug("umad_recv returned different agent\n");
				goto recv;
			}

			ret = umad_status(in_mad);
			if (ret) {
				pr_err(
					"bad MAD status (%u) from lid %#x\n",
					ret, be16toh(out_mad->hdr.addr.lid));
				return -ret;
			}

			received_tid = be64toh(in_dm_mad->mad_hdr.tid);
			if (tid != received_tid)
				pr_debug("umad_recv returned different transaction id sent %d got %d\n",
					 tid, received_tid);

		} while ((int32_t)(tid - received_tid) > 0);

		if (len > 0)
			return len;
	}

	return -1;
}

static void initialize_sysfs(void)
{
	char *env;

	env = getenv("SYSFS_PATH");
	if (env) {
		int len;
		char *dup;

		sysfs_path = dup = strndup(env, 256);
		len = strlen(dup);
		while (len > 0 && dup[len - 1] == '/') {
			--len;
			dup[len] = '\0';
		}
	}
}

static int translate_umad_to_ibdev_and_port(char *umad_dev, char **ibdev,
					    char **ibport)
{
	char *class_dev_path;
	char *umad_dev_name;
	int ret;

	*ibdev = NULL;
	*ibport = NULL;

	umad_dev_name = rindex(umad_dev, '/');
	if (!umad_dev_name) {
		pr_err("Couldn't find device name in '%s'\n", umad_dev);
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

	if (srpd_sys_read_string(class_dev_path, "ibdev", *ibdev,
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
	if (srpd_sys_read_string(class_dev_path, "port", *ibport, IBPORT_STR_SIZE) < 0) {
		pr_err("Couldn't read port attribute\n");
		ret = -1;
		goto end;
	}

	ret = 0;

end:
	if (ret) {
		free(*ibport);
		free(*ibdev);
		*ibdev = NULL;
	}
	free(class_dev_path);

	return ret;
}

static void init_srp_mad(struct srp_ib_user_mad *out_umad, int agent,
			 uint16_t h_dlid, uint16_t h_attr_id, uint32_t h_attr_mod)
{
	struct umad_dm_packet *out_mad;

	memset(out_umad, 0, sizeof *out_umad);

	out_umad->hdr.agent_id   = agent;
	out_umad->hdr.addr.qpn   = htobe32(1);
	out_umad->hdr.addr.qkey  = htobe32(UMAD_QKEY);
	out_umad->hdr.addr.lid   = htobe16(h_dlid);

	out_mad = (void *) out_umad->hdr.data;

	out_mad->mad_hdr.base_version  = UMAD_BASE_VERSION;
	out_mad->mad_hdr.method        = UMAD_METHOD_GET;
	out_mad->mad_hdr.attr_id       = htobe16(h_attr_id);
	out_mad->mad_hdr.attr_mod      = htobe32(h_attr_mod);
}

static void init_srp_dm_mad(struct srp_ib_user_mad *out_mad, int agent, uint16_t h_dlid,
			    uint16_t h_attr_id, uint32_t h_attr_mod)
{
	struct umad_sa_packet *out_dm_mad = get_data_ptr(*out_mad);

	init_srp_mad(out_mad, agent, h_dlid, h_attr_id, h_attr_mod);
	out_dm_mad->mad_hdr.mgmt_class = UMAD_CLASS_DEVICE_MGMT;
	out_dm_mad->mad_hdr.class_version  = 1;
}

static void init_srp_sa_mad(struct srp_ib_user_mad *out_mad, int agent, uint16_t h_dlid,
			    uint16_t h_attr_id, uint32_t h_attr_mod)
{
	struct umad_sa_packet *out_sa_mad = get_data_ptr(*out_mad);

	init_srp_mad(out_mad, agent, h_dlid, h_attr_id, h_attr_mod);
	out_sa_mad->mad_hdr.mgmt_class = UMAD_CLASS_SUBN_ADM;
	out_sa_mad->mad_hdr.class_version  = UMAD_SA_CLASS_VERSION;
}

static int check_sm_cap(struct umad_resources *umad_res, int *mask_match)
{
	struct srp_ib_user_mad		out_mad, in_mad;
	struct umad_sa_packet	       *in_sa_mad;
	struct umad_class_port_info    *cpi;
	int				ret;

	in_sa_mad  = get_data_ptr(in_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        UMAD_ATTR_CLASS_PORT_INFO, 0);

	ret = send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0);
	if (ret < 0)
		return ret;

	cpi = (void *) in_sa_mad->data;

	*mask_match = !!(be16toh(cpi->cap_mask) & SRP_SM_SUPPORTS_MASK_MATCH);

	return 0;
}

int pkey_index_to_pkey(struct umad_resources *umad_res, int pkey_index,
		       __be16 *pkey)
{
	if (ibv_query_pkey(umad_res->ib_ctx, config->port_num, pkey_index,
			   pkey) < 0)
		return -1;
	if (*pkey)
		pr_debug("discover Targets for P_key %04x (index %d)\n",
			 *pkey, pkey_index);
	return 0;
}

static int pkey_to_pkey_index(struct umad_resources *umad_res, uint16_t h_pkey,
			      uint16_t *pkey_index)
{
	int res = ibv_get_pkey_index(umad_res->ib_ctx, config->port_num,
				     htobe16(h_pkey));
	if (res >= 0)
		*pkey_index = res;
	return res;
}

static int set_class_port_info(struct umad_resources *umad_res, uint16_t dlid, uint16_t h_pkey)
{
	struct srp_ib_user_mad		in_mad, out_mad;
	struct umad_dm_packet	       *out_dm_mad, *in_dm_mad;
	struct umad_class_port_info    *cpi;
	char val[64];
	int i;

	init_srp_dm_mad(&out_mad, umad_res->agent, dlid, UMAD_ATTR_CLASS_PORT_INFO, 0);

	if (pkey_to_pkey_index(umad_res, h_pkey, &out_mad.hdr.addr.pkey_index)
	    < 0) {
		pr_err("set_class_port_info: Unable to find pkey_index for pkey %#x\n", h_pkey);
		return -1;
	}

	out_dm_mad = get_data_ptr(out_mad);
	out_dm_mad->mad_hdr.method = UMAD_METHOD_SET;

	cpi                = (void *) out_dm_mad->data;

	if (srpd_sys_read_string(umad_res->port_sysfs_path, "lid", val, sizeof val) < 0) {
		pr_err("Couldn't read LID\n");
		return -1;
	}

	cpi->trap_lid = htobe16(strtol(val, NULL, 0));

	if (srpd_sys_read_string(umad_res->port_sysfs_path, "gids/0", val, sizeof val) < 0) {
		pr_err("Couldn't read GID[0]\n");
		return -1;
	}

	for (i = 0; i < 8; ++i)
		cpi->trapgid.raw_be16[i] = htobe16(strtol(val + i * 5, NULL, 16));

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	in_dm_mad = get_data_ptr(in_mad);
	if (in_dm_mad->mad_hdr.status) {
		pr_err("Class Port Info set returned status 0x%04x\n",
			be16toh(in_dm_mad->mad_hdr.status));
		return -1;
	}

	return 0;
}

static int get_iou_info(struct umad_resources *umad_res, uint16_t dlid,
			uint16_t h_pkey, struct srp_dm_iou_info *iou_info)
{
	struct srp_ib_user_mad		in_mad, out_mad;
	struct umad_dm_packet	       *in_dm_mad;

	init_srp_dm_mad(&out_mad, umad_res->agent, dlid, SRP_DM_ATTR_IO_UNIT_INFO, 0);
	if (pkey_to_pkey_index(umad_res, h_pkey, &out_mad.hdr.addr.pkey_index)
	    < 0) {
		pr_err("get_iou_info: Unable to find pkey_index for pkey %#x\n", h_pkey);
		return -1;
	}

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	in_dm_mad = get_data_ptr(in_mad);
	if (in_dm_mad->mad_hdr.status) {
		pr_err("IO Unit Info query returned status 0x%04x\n",
			be16toh(in_dm_mad->mad_hdr.status));
		return -1;
	}

	memcpy(iou_info, in_dm_mad->data, sizeof *iou_info);
/*
	pr_debug("iou_info->max_controllers is %d\n", iou_info->max_controllers);
*/
	return 0;
}

static int get_ioc_prof(struct umad_resources *umad_res, uint16_t h_dlid, uint16_t h_pkey, int ioc,
			struct srp_dm_ioc_prof *ioc_prof)
{
	struct srp_ib_user_mad		in_mad, out_mad;
	struct umad_dm_packet	       *in_dm_mad;

	init_srp_dm_mad(&out_mad, umad_res->agent, h_dlid, SRP_DM_ATTR_IO_CONTROLLER_PROFILE, ioc);

	if (pkey_to_pkey_index(umad_res, h_pkey, &out_mad.hdr.addr.pkey_index)
	    < 0) {
		pr_err("get_ioc_prof: Unable to find pkey_index for pkey %#x\n",
		       h_pkey);
		return -1;
	}

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	in_dm_mad = get_data_ptr(in_mad);
	if (in_dm_mad->mad_hdr.status) {
		pr_err("IO Controller Profile query returned status 0x%04x for %d\n",
			be16toh(in_dm_mad->mad_hdr.status), ioc);
		return -1;
	}

	memcpy(ioc_prof, in_dm_mad->data, sizeof *ioc_prof);

	return 0;
}

static int get_svc_entries(struct umad_resources *umad_res, uint16_t dlid, uint16_t h_pkey, int ioc,
			   int start, int end, struct srp_dm_svc_entries *svc_entries)
{
	struct srp_ib_user_mad		in_mad, out_mad;
	struct umad_dm_packet	       *in_dm_mad;

	init_srp_dm_mad(&out_mad, umad_res->agent, dlid, SRP_DM_ATTR_SERVICE_ENTRIES,
			(ioc << 16) | (end << 8) | start);

	if (pkey_to_pkey_index(umad_res, h_pkey, &out_mad.hdr.addr.pkey_index)
	    < 0) {
		pr_err("get_svc_entries: Unable to find pkey_index for pkey %#x\n",
		       h_pkey);
		return -1;
	}

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	in_dm_mad = get_data_ptr(in_mad);
	if (in_dm_mad->mad_hdr.status) {
		pr_err("Service Entries query returned status 0x%04x\n",
			be16toh(in_dm_mad->mad_hdr.status));
		return -1;
	}

	memcpy(svc_entries, in_dm_mad->data, sizeof *svc_entries);

	return 0;
}

static int do_port(struct resources *res, uint16_t pkey, uint16_t dlid,
		   uint64_t subnet_prefix, uint64_t h_guid)
{
	struct umad_resources 	       *umad_res = res->umad_res;
	struct srp_dm_iou_info		iou_info;
	struct srp_dm_svc_entries	svc_entries;
	int				i, j, k, ret;

	static const uint64_t topspin_oui = 0x0005ad0000000000ull;
	static const uint64_t oui_mask    = 0xffffff0000000000ull;

	struct target_details *target = (struct target_details *)
		malloc(sizeof(struct target_details));

	target->subnet_prefix = subnet_prefix;
	target->h_guid = h_guid;
	target->options = NULL;

 	pr_debug("enter do_port\n");
	if ((target->h_guid & oui_mask) == topspin_oui &&
	    set_class_port_info(umad_res, dlid, pkey))
		pr_err("Warning: set of ClassPortInfo failed\n");

	ret = get_iou_info(umad_res, dlid, pkey, &iou_info);
	if (ret < 0) {
		pr_err("failed to get iou info for dlid %#x\n", dlid);
		goto out;
	}

	pr_human("IO Unit Info:\n");
	pr_human("    port LID:        %04x\n", dlid);
	pr_human("    port GID:        %016llx%016llx\n",
		 (unsigned long long) target->subnet_prefix,
		 (unsigned long long) target->h_guid);
	pr_human("    change ID:       %04x\n", be16toh(iou_info.change_id));
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

			if (get_ioc_prof(umad_res, dlid, pkey, i + 1, &target->ioc_prof))
				continue;

			pr_human("    controller[%3d]\n", i + 1);

			pr_human("        GUID:      %016llx\n",
				 (unsigned long long) be64toh(target->ioc_prof.guid));
			pr_human("        vendor ID: %06x\n", be32toh(target->ioc_prof.vendor_id) >> 8);
			pr_human("        device ID: %06x\n", be32toh(target->ioc_prof.device_id));
			pr_human("        IO class : %04hx\n", be16toh(target->ioc_prof.io_class));
			pr_human("        Maximum size of Send Messages in bytes: %d\n",
				 be32toh(target->ioc_prof.send_size));
			pr_human("        ID:        %s\n", target->ioc_prof.id);
			pr_human("        service entries: %d\n", target->ioc_prof.service_entries);

			for (j = 0; j < target->ioc_prof.service_entries; j += 4) {
				int n;

				n = j + 3;
				if (n >= target->ioc_prof.service_entries)
					n = target->ioc_prof.service_entries - 1;

				if (get_svc_entries(umad_res, dlid, pkey, i + 1,
						    j, n, &svc_entries))
					continue;

				for (k = 0; k <= n - j; ++k) {

					if (sscanf(svc_entries.service[k].name,
						   "SRP.T10:%16s",
						   target->id_ext) != 1)
						continue;

					pr_human("            service[%3d]: %016llx / %s\n",
						 j + k,
						 (unsigned long long) be64toh(svc_entries.service[k].id),
						 svc_entries.service[k].name);

					target->h_service_id = be64toh(svc_entries.service[k].id);
					target->pkey = pkey;
					if (is_enabled_by_rules_file(target)) {
						if (!add_non_exist_target(target) && !config->once) {
							target->retry_time =
								time(NULL) + config->retry_timeout;
							push_to_retry_list(res->sync_res, target);
						}
					}
				}
			}
		}
	}

	pr_human("\n");

out:
	free(target);
	return ret;
}

int get_node(struct umad_resources *umad_res, uint16_t dlid, uint64_t *guid)
{
	struct srp_ib_user_mad		out_mad, in_mad;
	struct umad_sa_packet	       *out_sa_mad, *in_sa_mad;
	struct srp_sa_node_rec	       *node;

	in_sa_mad = get_data_ptr(in_mad);
	out_sa_mad = get_data_ptr(out_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        UMAD_SA_ATTR_NODE_REC, 0);

	out_sa_mad->comp_mask     = htobe64(1); /* LID */
	node			  = (void *) out_sa_mad->data;
	node->lid		  = htobe16(dlid);

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	node  = (void *) in_sa_mad->data;
	*guid = be64toh(node->port_guid);

	return 0;
}

static int get_port_info(struct umad_resources *umad_res, uint16_t dlid,
			 uint64_t *subnet_prefix, int *isdm)
{
	struct srp_ib_user_mad		out_mad, in_mad;
	struct umad_sa_packet	       *out_sa_mad, *in_sa_mad;
	struct srp_sa_port_info_rec    *port_info;

	in_sa_mad = get_data_ptr(in_mad);
	out_sa_mad = get_data_ptr(out_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        UMAD_SA_ATTR_PORT_INFO_REC, 0);

	out_sa_mad->comp_mask     = htobe64(1); /* LID */
	port_info                 = (void *) out_sa_mad->data;
	port_info->endport_lid	  = htobe16(dlid);

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	port_info = (void *) in_sa_mad->data;
	*subnet_prefix = be64toh(port_info->subnet_prefix);
	*isdm          = !!(be32toh(port_info->capability_mask) & SRP_IS_DM);

	return 0;
}

static int get_shared_pkeys(struct resources *res,
			    uint16_t dest_port_lid,
			    uint16_t *pkeys)
{
	struct umad_resources          *umad_res = res->umad_res;
	uint8_t                        *in_mad_buf;
	struct srp_ib_user_mad		out_mad;
	struct ib_user_mad	       *in_mad;
	struct umad_sa_packet	       *out_sa_mad, *in_sa_mad;
	struct ib_path_rec	       *path_rec;
	ssize_t len;
	int i, num_pkeys = 0;
	__be16 pkey;
	uint16_t local_port_lid = get_port_lid(res->ud_res->ib_ctx,
					       config->port_num, NULL);

	in_mad_buf = malloc(sizeof(struct ib_user_mad) +
			    node_table_response_size);
	if (!in_mad_buf)
		return -ENOMEM;

	in_mad = (void *)in_mad_buf;
	in_sa_mad = (void *)in_mad->data;
	out_sa_mad = get_data_ptr(out_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        UMAD_SA_ATTR_PATH_REC, 0);

	/**
	 * Due to OpenSM bug (issue #335016) SM won't return
	 * table of all shared P_Keys, it will return only the first
	 * shared P_Key, So we send path_rec over each P_Key in the P_Key
	 * table. SM will return path record if P_Key is shared or else None.
	 * Once SM bug will be fixed, this loop should be removed.
	 **/
	for (i = 0; ; i++) {
		if (pkey_index_to_pkey(umad_res, i, &pkey))
			break;
		if (!pkey)
			continue;

		/* Mark components: DLID, SLID, PKEY */
		out_sa_mad->comp_mask = htobe64(1 << 4 | 1 << 5 | 1 << 13);
		path_rec = (struct ib_path_rec *)out_sa_mad->data;
		path_rec->slid = htobe16(local_port_lid);
		path_rec->dlid = htobe16(dest_port_lid);
		path_rec->pkey = pkey;

		len = send_and_get(umad_res->portid, umad_res->agent, &out_mad,
				   (struct srp_ib_user_mad *)in_mad,
				   node_table_response_size);
		if (len < 0)
			goto err;

		path_rec = (struct ib_path_rec *)in_sa_mad->data;
		pkeys[num_pkeys++] = be16toh(path_rec->pkey);
	}

	free(in_mad_buf);
	return num_pkeys;
err:
	free(in_mad_buf);
	return -1;
}

static int do_dm_port_list(struct resources *res)
{
	struct umad_resources 	       *umad_res = res->umad_res;
	uint8_t                        *in_mad_buf;
	struct srp_ib_user_mad		out_mad;
	struct ib_user_mad	       *in_mad;
	struct umad_sa_packet	       *out_sa_mad, *in_sa_mad;
	struct srp_sa_port_info_rec    *port_info;
	ssize_t len;
	int size;
	int i, j,num_pkeys;
	uint16_t pkeys[SRP_MAX_SHARED_PKEYS];
	uint64_t guid;

	in_mad_buf = malloc(sizeof(struct ib_user_mad) +
			    node_table_response_size);
	if (!in_mad_buf)
		return -ENOMEM;

	in_mad     = (void *) in_mad_buf;
	in_sa_mad  = (void *) in_mad->data;
	out_sa_mad = get_data_ptr(out_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        UMAD_SA_ATTR_PORT_INFO_REC, SRP_SM_CAP_MASK_MATCH_ATTR_MOD);

	out_sa_mad->mad_hdr.method = UMAD_SA_METHOD_GET_TABLE;
	out_sa_mad->comp_mask      = htobe64(1 << 7); /* Capability mask */
	out_sa_mad->rmpp_hdr.rmpp_version = UMAD_RMPP_VERSION;
	out_sa_mad->rmpp_hdr.rmpp_type = 1;
	port_info		   = (void *) out_sa_mad->data;
	port_info->capability_mask = htobe32(SRP_IS_DM); /* IsDM */

	len = send_and_get(umad_res->portid, umad_res->agent, &out_mad,
			   (struct srp_ib_user_mad *) in_mad,
			   node_table_response_size);
	if (len < 0) {
		free(in_mad_buf);
		return len;
	}

	size = ib_get_attr_size(in_sa_mad->attr_offset);
	if (!size) {
		if (config->verbose) {
			printf("Query did not find any targets\n");
		}
		free(in_mad_buf);
		return 0;
	}

	for (i = 0; (i + 1) * size <= len - MAD_RMPP_HDR_SIZE; ++i) {
		port_info = (void *) in_sa_mad->data + i * size;
		if (get_node(umad_res, be16toh(port_info->endport_lid), &guid))
			continue;

		num_pkeys = get_shared_pkeys(res, be16toh(port_info->endport_lid),
					     pkeys);
		if (num_pkeys < 0) {
			pr_err("failed to get shared P_Keys with LID %#x\n",
			       be16toh(port_info->endport_lid));
			free(in_mad_buf);
			return num_pkeys;
		}

		for (j = 0; j < num_pkeys; ++j)
			do_port(res, pkeys[j], be16toh(port_info->endport_lid),
				be64toh(port_info->subnet_prefix), guid);
	}

	free(in_mad_buf);
	return 0;
}

void handle_port(struct resources *res, uint16_t pkey, uint16_t lid, uint64_t h_guid)
{
	struct umad_resources *umad_res = res->umad_res;
	uint64_t subnet_prefix;
	int isdm;

	pr_debug("enter handle_port for lid %#x\n", lid);
	if (get_port_info(umad_res, lid, &subnet_prefix, &isdm))
		return;

	if (!isdm)
		return;

	do_port(res, pkey, lid, subnet_prefix, h_guid);
}


static int do_full_port_list(struct resources *res)
{
	struct umad_resources 	       *umad_res = res->umad_res;
	uint8_t                        *in_mad_buf;
	struct srp_ib_user_mad		out_mad;
	struct ib_user_mad	       *in_mad;
	struct umad_sa_packet	       *out_sa_mad, *in_sa_mad;
	struct srp_sa_node_rec	       *node;
	ssize_t len;
	int size;
	int i, j, num_pkeys;
	uint16_t pkeys[SRP_MAX_SHARED_PKEYS];

	in_mad_buf = malloc(sizeof(struct ib_user_mad) +
			    node_table_response_size);
	if (!in_mad_buf)
		return -ENOMEM;

	in_mad     = (void *) in_mad_buf;
	in_sa_mad  = (void *) in_mad->data;
	out_sa_mad = get_data_ptr(out_mad);

	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        UMAD_SA_ATTR_NODE_REC, 0);

	out_sa_mad->mad_hdr.method = UMAD_SA_METHOD_GET_TABLE;
	out_sa_mad->comp_mask     = 0; /* Get all end ports */
	out_sa_mad->rmpp_hdr.rmpp_version = UMAD_RMPP_VERSION;
	out_sa_mad->rmpp_hdr.rmpp_type = 1;

	len = send_and_get(umad_res->portid, umad_res->agent, &out_mad,
			   (struct srp_ib_user_mad *) in_mad,
			   node_table_response_size);
	if (len < 0) {
		free(in_mad_buf);
		return len;
	}

	size = be16toh(in_sa_mad->attr_offset) * 8;

	for (i = 0; (i + 1) * size <= len - MAD_RMPP_HDR_SIZE; ++i) {
		node = (void *) in_sa_mad->data + i * size;

		num_pkeys = get_shared_pkeys(res, be16toh(node->lid),
					     pkeys);
		if (num_pkeys < 0) {
			pr_err("failed to get shared P_Keys with LID %#x\n",
			       be16toh(node->lid));
			free(in_mad_buf);
			return num_pkeys;
		}

		for (j = 0; j < num_pkeys; ++j)
			(void) handle_port(res, pkeys[j], be16toh(node->lid),
					   be64toh(node->port_guid));
	}

	free(in_mad_buf);
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
 	printf(" Report current targets and stop 	: %d\n", conf->once);
	if (conf->rules_file)
		printf(" Reads rules from 			: %s\n", conf->rules_file);
	if (conf->print_initiator_ext)
		printf(" Print initiator_ext\n");
	else
		printf(" Do not print initiator_ext\n");
	if (conf->recalc_time)
		printf(" Performs full target rescan every %d seconds\n", conf->recalc_time);
	else
		printf(" No full target rescan\n");
	if (conf->retry_timeout)
		printf(" Retries to connect to existing target after %d seconds\n", conf->retry_timeout);
	else
		printf(" Do not retry to connect to existing targets\n");
	printf(" ------------------------------------------------\n");
}

static char *copy_till_comma(char *d, char *s, int len, int base)
{
	int i=0;

	while (strchr(", \t\n", *s) == NULL) {
		if (i == len)
			return NULL;
		if ((base == 16 && isxdigit(*s)) || (base == 10 && isdigit(*s))) {
			*d=*s;
			++d;
			++s;
			++i;
		} else
			return NULL;
	}
	*d='\0';

	if (*s == '\n')
		return s;

	++s;
	return s;
}

static char *parse_main_option(struct rule *rule, char *ptr)
{
	struct option_info {
		const char *name;
		size_t offset;
		size_t len;
		int base;
	};
#define OPTION_INFO(n, base) { #n "=", offsetof(struct rule, n),	\
			sizeof(((struct rule *)NULL)->n), base}
	static const struct option_info opt_info[] = {
		OPTION_INFO(id_ext, 16),
		OPTION_INFO(ioc_guid, 16),
		OPTION_INFO(dgid, 16),
		OPTION_INFO(service_id, 16),
		OPTION_INFO(pkey, 16),
	};
	int i, optnamelen;
	char *ptr2 = NULL;

	for (i = 0; i < sizeof(opt_info) / sizeof(opt_info[0]); i++) {
		optnamelen = strlen(opt_info[i].name);
		if (strncmp(ptr, opt_info[i].name, optnamelen) == 0) {
			ptr2 = copy_till_comma((char *)rule
					       + opt_info[i].offset,
					       ptr + optnamelen,
					       opt_info[i].len - 1,
					       opt_info[i].base);
			break;
		}
	}

	return ptr2;
}

/*
 * Return values:
 *  -1 if the output buffer is not large enough.
 *   0 if an unsupported option has been encountered.
 * > 0 if parsing succeeded.
 */
static int parse_other_option(struct rule *rule, char *ptr)
{
	static const char *const opt[] = {
		"allow_ext_sg=",
		"cmd_sg_entries=",
		"comp_vector=",
		"max_cmd_per_lun=",
		"max_sect=",
		"queue_size=",
		"sg_tablesize=",
		"tl_retry_count=",
	};

	char *ptr2 = NULL, *optr, option[17];
	int i, optnamelen, len, left;

	optr = rule->options;
	left = sizeof(rule->options);
	len = strlen(optr);
	optr += len;
	left -= len;
	for (i = 0; i < sizeof(opt)/sizeof(opt[0]); ++i) {
		optnamelen = strlen(opt[i]);
		if (strncmp(ptr, opt[i], optnamelen) != 0)
			continue;
		ptr2 = copy_till_comma(option, ptr + optnamelen,
				       sizeof(option) - 1, 10);
		if (!ptr2)
			return -1;
		len = snprintf(optr, left, ",%s%s", opt[i], option);
		optr += len;
		left -= len;
		if (left <= 0)
			return -1;
		break;
	}
	return ptr2 ? ptr2 - ptr : 0;
}

static int get_rules_file(struct config_t *conf)
{
	int line_number = 1, len, line_number_for_output, ret = -1;
	char line[255];
	char *ptr, *ptr2;
	struct rule *rule;
	FILE *infile = fopen(conf->rules_file, "r");

	if (infile == NULL) {
		pr_debug("Could not find rules file %s, going with default\n",
			 conf->rules_file);
		return 0;
	}

	while (fgets(line, sizeof(line), infile) != NULL) {
		if (line[0] != '#' && line[0] != '\n')
			line_number++;
	}

	if (fseek(infile, 0L, SEEK_SET) != 0) {
		pr_err("internal error while seeking %s\n", conf->rules_file);
		goto out;
	}

	conf->rules = malloc(sizeof(struct rule) * line_number);

	rule = &conf->rules[0] - 1;
	line_number_for_output = 0;
	while (fgets(line, sizeof(line), infile) != NULL) {
		line_number_for_output++;
		if (line[0] == '#' || line[0] == '\n')
			continue;

		rule++;
		switch (line[0]) {
		case 'a':
		case 'A':
			rule->allow = 1;
			break;
		case 'd':
		case 'D':
			rule->allow = 0;
			break;
		default:
			pr_err("Bad syntax in rules file %s line %d:"
			       " line should start with 'a' or 'd'\n",
			       conf->rules_file, line_number_for_output);
			goto out;
		}

		rule->id_ext[0] = '\0';
		rule->ioc_guid[0] = '\0';
		rule->dgid[0] = '\0';
		rule->service_id[0] = '\0';
		rule->pkey[0] = '\0';
		rule->options[0] = '\0';

		ptr = &line[1];
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		while (*ptr != '\n') {
			ptr2 = parse_main_option(rule, ptr);
			if (!ptr2 && rule->allow) {
				len = parse_other_option(rule, ptr);
				if (len < 0) {
					pr_err("Buffer overflow triggered by"
					       " rules file %s line %d\n",
					       conf->rules_file,
					       line_number_for_output);
					goto out;
				}
				ptr2 = len ? ptr + len : NULL;
			}

			if (ptr2 == NULL) {
				pr_err("Bad syntax in rules file %s line %d\n",
				       conf->rules_file, line_number_for_output);
				goto out;
			}
			ptr = ptr2;

			while (*ptr == ' ' || *ptr == '\t')
				ptr++;
		}
	}
	rule++;
	rule->id_ext[0] = '\0';
	rule->ioc_guid[0] = '\0';
	rule->dgid[0] = '\0';
	rule->service_id[0] = '\0';
	rule->pkey[0] = '\0';
	rule->options[0] = '\0';
	rule->allow = 1;
	ret = 0;

out:
	fclose(infile);

	return ret;
}

static int set_conf_dev_and_port(char *umad_dev, struct config_t *conf)
{
	int ret;

	if (umad_dev) {
		char *ibport;

		ret = translate_umad_to_ibdev_and_port(umad_dev,
						       &conf->dev_name,
						       &ibport);
		if (ret) {
			pr_err("Fail to translate umad to ibdev and port\n");
			goto out;
		}
		conf->port_num = atoi(ibport);
		if (conf->port_num == 0) {
			pr_err("Bad port number %s\n", ibport);
			ret = -1;
		}
		free(ibport);
	} else {
		umad_ca_t ca;
		umad_port_t port;

		ret = umad_get_ca(NULL, &ca);
		if (ret) {
			pr_err("Failed to get default CA\n");
			goto out;
		}

		ret = umad_get_port(ca.ca_name, 0, &port);
		if (ret) {
			pr_err("Failed to get default port for CA %s\n",
			       ca.ca_name);
			umad_release_ca(&ca);
			goto out;
		}
		conf->dev_name = strdup(ca.ca_name);
		conf->port_num = port.portnum;
		umad_release_port(&port);
		umad_release_ca(&ca);
		pr_debug("Using device %s port %d\n", conf->dev_name,
			 conf->port_num);
	}
out:
	return ret;
}

static const struct option long_opts[] = {
	{ "systemd",        0, NULL, 'S' },
	{}
};
static const char short_opts[] = "caveod:i:j:p:t:r:R:T:l:Vhnf:";

/* Check if the --systemd options was passed in very early so we can setup
 * logging properly.
 */
static bool is_systemd(int argc, char *argv[])
{
	while (1) {
		int c;

		c = getopt_long(argc, argv, short_opts, long_opts, NULL);
		if (c == -1)
			break;
		if (c == 'S')
			return true;

	}
	return false;
}

static int get_config(struct config_t *conf, int argc, char *argv[])
{
	/* set defaults */
	char* umad_dev = NULL;
	int ret;

	conf->port_num			= 1;
	conf->num_of_oust		= 10;
	conf->dev_name	 		= NULL;
	conf->cmd	 		= 0;
	conf->once	 		= 0;
	conf->execute	 		= 0;
	conf->all	 		= 0;
	conf->verbose	 		= 0;
	conf->debug_verbose    		= 0;
	conf->timeout	 		= 5000;
	conf->mad_retries 		= 3;
	conf->recalc_time 		= 0;
	conf->retry_timeout 		= 20;
	conf->add_target_file  		= NULL;
	conf->print_initiator_ext	= 0;
	conf->rules_file		= SRP_DEAMON_CONFIG_FILE;
	conf->rules			= NULL;
	conf->tl_retry_count		= 0;

	optind = 1;
	while (1) {
		int c;

		c = getopt_long(argc, argv, short_opts, long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			umad_dev = optarg;
			break;
		case 'i':
			conf->dev_name = strdup(optarg);
			if (!conf->dev_name) {
				pr_err("Fail to alloc space for dev_name\n");
				return -ENOMEM;
			}
			break;
		case 'p':
			conf->port_num = atoi(optarg);
			if (conf->port_num == 0) {
				pr_err("Bad port number %s\n", optarg);
				return -1;
			}
			break;
		case 'j': {
			char dev[32];
			int port_num;

			if (sscanf(optarg, "%31[^:]:%d", dev, &port_num) != 2) {
				pr_err("Bad dev:port specification %s\n",
				       optarg);
				return -1;
			}
			conf->dev_name = strdup(dev);
			conf->port_num = port_num;
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
		case 'n':
			++conf->print_initiator_ext;
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
		case 'T':
			conf->retry_timeout = atoi(optarg);
			if (conf->retry_timeout == 0 && strcmp(optarg, "0")) {
				pr_err("Bad retry Timeout value- %s.\n", optarg);
				return -1;
			}
			break;
		case 'f':
			conf->rules_file = optarg;
			break;
		case 'l':
			conf->tl_retry_count = atoi(optarg);
			if (conf->tl_retry_count < 2 ||
			    conf->tl_retry_count > 7) {
				pr_err("Bad tl_retry_count argument (%d), "
				       "must be 2 <= tl_retry_count <= 7\n",
				       conf->tl_retry_count);
				return -1;
			}
			break;
		case 'S':
			break;
		case 'h':
		default:
			usage(argv[0]);
			return -1;
		}
	}

	initialize_sysfs();

	if (conf->dev_name == NULL) {
		ret = set_conf_dev_and_port(umad_dev, conf);
	        if (ret) {
	                pr_err("Failed to build config\n");
	                return ret;
	        }
	}
	ret = asprintf(&conf->add_target_file,
		       "%s/class/infiniband_srp/srp-%s-%d/add_target", sysfs_path,
		       conf->dev_name, conf->port_num);
	if (ret < 0) {
		pr_err("error while allocating add_target\n");
		return ret;
	}

	if (get_rules_file(conf))
		return -1;

	return 0;
}

static void free_config(struct config_t *conf)
{
	free(conf->dev_name);
	free(conf->add_target_file);
	free(conf->rules);
	free(conf);
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

	if (umad_res->portid >= 0) {
		if (umad_res->agent >= 0)
			umad_unregister(umad_res->portid, umad_res->agent);
		umad_close_port(umad_res->portid);
	}

	umad_done();
}

static int umad_resources_create(struct umad_resources *umad_res)
{

	int ret;

	ret = asprintf(&umad_res->port_sysfs_path, "%s/class/infiniband/%s/ports/%d",
		       sysfs_path, config->dev_name, config->port_num);

	if (ret < 0) {
		umad_res->port_sysfs_path = NULL;
		return -ENOMEM;
	}

	umad_res->portid = umad_open_port(config->dev_name, config->port_num);
	if (umad_res->portid < 0) {
		pr_err("umad_open_port failed for device %s port %d\n",
		       config->dev_name, config->port_num);
		return -ENXIO;
	}

	umad_res->agent = umad_register(umad_res->portid, UMAD_CLASS_SUBN_ADM,
					   UMAD_SA_CLASS_VERSION,
					   UMAD_RMPP_VERSION, NULL);
	if (umad_res->agent < 0) {
		pr_err("umad_register failed\n");
		return umad_res->agent;
	}

	return 0;
}

static void *run_thread_retry_to_connect(void *res_in)
{
	struct resources *res = (struct resources *)res_in;
	struct target_details *target;
	time_t sleep_time;

	pthread_mutex_lock(&res->sync_res->retry_mutex);
	while (!res->sync_res->stop_threads) {
		if (retry_list_is_empty(res->sync_res))
			pthread_cond_wait(&res->sync_res->retry_cond,
					  &res->sync_res->retry_mutex);
		while (!res->sync_res->stop_threads &&
		       (target = pop_from_retry_list(res->sync_res)) != NULL) {
			pthread_mutex_unlock(&res->sync_res->retry_mutex);
			sleep_time = target->retry_time - time(NULL);

			if (sleep_time > 0)
				srp_sleep(sleep_time, 0);

			add_non_exist_target(target);
			free(target);
			pthread_mutex_lock(&res->sync_res->retry_mutex);
		}
	}
	/* empty retry_list */
	while ((target = pop_from_retry_list(res->sync_res)))
		free(target);
	pthread_mutex_unlock(&res->sync_res->retry_mutex);

	pr_debug("retry_to_connect thread ended\n");

	pthread_exit(NULL);
}

static void free_res(struct resources *res)
{
	void *status;

	if (!res)
		return;

	if (res->sync_res) {
		pthread_mutex_lock(&res->sync_res->retry_mutex);
		res->sync_res->stop_threads = 1;
		pthread_cond_signal(&res->sync_res->retry_cond);
		pthread_mutex_unlock(&res->sync_res->retry_mutex);
	}

	if (res->ud_res)
		modify_qp_to_err(res->ud_res->qp);

	if (res->reconnect_thread) {
		pthread_kill(res->reconnect_thread, SIGINT);
		pthread_join(res->reconnect_thread, &status);
	}
	if (res->async_ev_thread) {
		pthread_kill(res->async_ev_thread, SIGINT);
		pthread_join(res->async_ev_thread, &status);
	}
	if (res->trap_thread) {
		pthread_kill(res->trap_thread, SIGINT);
		pthread_join(res->trap_thread, &status);
	}
	if (res->sync_res)
		sync_resources_cleanup(res->sync_res);
	if (res->ud_res)
		ud_resources_destroy(res->ud_res);
	if (res->umad_res)
		umad_resources_destroy(res->umad_res);
	free(res);
}

static struct resources *alloc_res(void)
{
	struct all_resources {
		struct resources	res;
		struct ud_resources	ud_res;
		struct umad_resources	umad_res;
		struct sync_resources	sync_res;
	};

	struct all_resources *res;
	int ret;

	res = calloc(1, sizeof(*res));
	if (!res)
		goto err;

	umad_resources_init(&res->umad_res);
	ret = umad_resources_create(&res->umad_res);
	if (ret)
		goto err;
	res->res.umad_res = &res->umad_res;

	ud_resources_init(&res->ud_res);
	ret = ud_resources_create(&res->ud_res);
	if (ret)
		goto err;
	res->res.ud_res = &res->ud_res;
	res->umad_res.ib_ctx = res->ud_res.ib_ctx;

	ret = sync_resources_init(&res->sync_res);
	if (ret)
		goto err;
	res->res.sync_res = &res->sync_res;

	if (!config->once) {
		ret = pthread_create(&res->res.trap_thread, NULL,
				     run_thread_get_trap_notices, &res->res);
		if (ret)
			goto err;

		ret = pthread_create(&res->res.async_ev_thread, NULL,
				     run_thread_listen_to_events, &res->res);
		if (ret)
			goto err;
	}

	if (config->retry_timeout && !config->once) {
		ret = pthread_create(&res->res.reconnect_thread, NULL,
				     run_thread_retry_to_connect, &res->res);
		if (ret)
			goto err;
	}

	return &res->res;
err:
	if (res)
		free_res(&res->res);
	return NULL;
}

/* *c = *a - *b. See also the BSD macro timersub(). */
static void ts_sub(const struct timespec *a, const struct timespec *b,
		   struct timespec *res)
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_nsec = a->tv_nsec - b->tv_nsec;
	if (res->tv_nsec < 0) {
		res->tv_sec--;
		res->tv_nsec += 1000 * 1000 * 1000;
	}
}

static void cleanup_wakeup_fd(void)
{
	struct sigaction sa = {};

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_DFL;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SRP_CATAS_ERR, &sa, NULL);

	close(wakeup_pipe[1]);
	close(wakeup_pipe[0]);
	wakeup_pipe[0] = -1;
	wakeup_pipe[1] = -1;
}

static int setup_wakeup_fd(void)
{
	struct sigaction sa = {};
	int ret;

	ret = pipe2(wakeup_pipe, O_NONBLOCK | O_CLOEXEC);
	if (ret < 0) {
		pr_err("could not create pipe\n");
		return -1;
	}

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = signal_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SRP_CATAS_ERR, &sa, NULL);
	return 0;
}

static int ibsrpdm(int argc, char *argv[])
{
	char* umad_dev = NULL;
	struct resources *res;
	int ret;

	s_log_dest = log_to_stderr;

	config = calloc(1, sizeof(*config));
	config->num_of_oust = 10;
	config->timeout = 5000;
	config->mad_retries = 3;
	config->all = 1;
	config->once = 1;

	while (1) {
		int c;

		c = getopt(argc, argv, "cd:h:v");
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			++config->cmd;
			break;
		case 'd':
			umad_dev = optarg;
			break;
		case 'v':
			++config->debug_verbose;
			break;
		case 'h':
		default:
			fprintf(stderr,
				"Usage: %s [-vc] [-d <umad device>]\n",
				argv[0]);
			return 1;
		}
	}

	initialize_sysfs();

	ret = set_conf_dev_and_port(umad_dev, config);
	if (ret) {
		pr_err("Failed to build config\n");
		goto out;
	}

	umad_init();
	res = alloc_res();
	if (!res) {
		ret = 1;
		pr_err("Resource allocation failed\n");
		goto umad_done;
	}
	ret = recalc(res);
	if (ret)
		pr_err("Querying SRP targets failed\n");

	free_res(res);
umad_done:
	umad_done();
out:
	free_config(config);

	return ret;
}

int main(int argc, char *argv[])
{
	int			ret;
	struct resources       *res;
	uint16_t                lid, sm_lid;
	uint16_t 		pkey;
	union umad_gid 		gid;
	struct target_details  *target;
	int			subscribed;
	int			lockfd = -1;
	int			received_signal = 0;
	bool                    systemd;

#ifndef __CHECKER__
	/*
	 * Hide these checks for sparse because these checks fail with
	 * older versions of sparse.
	 */
	BUILD_ASSERT(sizeof(struct ib_path_rec) == 64);
	BUILD_ASSERT(sizeof(struct ib_inform_info) == 36);
	BUILD_ASSERT(sizeof(struct ib_mad_notice_attr) == 80);
	BUILD_ASSERT(offsetof(struct ib_mad_notice_attr, generic.trap_num) ==
		     4);
	BUILD_ASSERT(offsetof(struct ib_mad_notice_attr, vend.dev_id) == 4);
	BUILD_ASSERT(offsetof(struct ib_mad_notice_attr, ntc_64_67.gid) == 16);
	BUILD_ASSERT(offsetof(struct ib_mad_notice_attr,
			      ntc_144.new_cap_mask) == 16);
#endif
	BUILD_ASSERT(sizeof(struct srp_sa_node_rec) == 108);
	BUILD_ASSERT(sizeof(struct srp_sa_port_info_rec) == 58);
	BUILD_ASSERT(sizeof(struct srp_dm_iou_info) == 132);
	BUILD_ASSERT(sizeof(struct srp_dm_ioc_prof) == 128);

	if (strcmp(argv[0] + max_t(int, 0, strlen(argv[0]) - strlen("ibsrpdm")),
		   "ibsrpdm") == 0) {
		ret = ibsrpdm(argc, argv);
		goto out;
	}

	systemd = is_systemd(argc, argv);

	if (systemd)
		openlog(NULL, LOG_NDELAY | LOG_CONS | LOG_PID, LOG_DAEMON);
	else
		openlog("srp_daemon", LOG_PID, LOG_DAEMON);

	config = calloc(1, sizeof(*config));
	if (!config) {
 		pr_err("out of memory\n");
		ret = ENOMEM;
		goto close_log;
	}

	if (get_config(config, argc, argv)) {
		ret = EINVAL;
		goto free_config;
	}

	if (config->verbose)
		print_config(config);

	if (!config->once) {
		lockfd = check_process_uniqueness(config);
		if (lockfd < 0) {
			ret = EPERM;
			goto free_config;
		}
	}

	ret = setup_wakeup_fd();
	if (ret)
		goto cleanup_wakeup;

catas_start:
	subscribed = 0;

	ret = umad_init();
	if (ret < 0) {
		pr_err("umad_init failed\n");
		goto close_lockfd;
	}

	res = alloc_res();
	if (!res && received_signal == SRP_CATAS_ERR)
		pr_err("Device has not yet recovered from catas error\n");
	if (!res)
		goto clean_umad;

	/*
	 * alloc_res() fails while the HCA is recovering from a catastrophic
	 * error. Clear 'received_signal' after alloc_res() has succeeded to
	 * finish the alloc_res() retry loop.
	 */
	if (received_signal == SRP_CATAS_ERR) {
		pr_err("Device recovered from catastrophic error\n");
		received_signal = 0;
	}

	if (config->once) {
		ret = recalc(res);
		goto free_res;
	}

	while (received_signal == 0) {
		pthread_mutex_lock(&res->sync_res->mutex);
		if (__rescan_scheduled(res->sync_res)) {
			uint16_t port_lid;

			pthread_mutex_unlock(&res->sync_res->mutex);

			pr_debug("Starting a recalculation\n");
			port_lid = get_port_lid(res->ud_res->ib_ctx,
						config->port_num, &sm_lid);
			if (port_lid > 0 && port_lid < 0xc000 &&
			    (port_lid != res->ud_res->port_attr.lid ||
			     sm_lid != res->ud_res->port_attr.sm_lid)) {

				if (res->ud_res->ah) {
					ibv_destroy_ah(res->ud_res->ah);
					res->ud_res->ah = NULL;
				}
				ret = create_ah(res->ud_res);
				if (ret) {
					received_signal = get_received_signal(10, 0);
					goto kill_threads;
				}
			}

			if (res->ud_res->ah) {
				if (register_to_traps(res, 1))
					pr_err("Fail to register to traps, maybe there "
					       "is no SM running on fabric or IB port is down\n");
				else
					subscribed = 1;
			}

			clear_traps_list(res->sync_res);
			schedule_rescan(res->sync_res, config->recalc_time ?
					config->recalc_time : -1);

			/* empty retry_list */
			pthread_mutex_lock(&res->sync_res->retry_mutex);
			while ((target = pop_from_retry_list(res->sync_res)))
				free(target);
			pthread_mutex_unlock(&res->sync_res->retry_mutex);

			recalc(res);
		} else if (pop_from_list(res->sync_res, &lid, &gid, &pkey)) {
			pthread_mutex_unlock(&res->sync_res->mutex);
			if (lid) {
				uint64_t guid;
				ret = get_node(res->umad_res, lid, &guid);
				if (ret)
					/* unexpected error - do a full rescan */
					schedule_rescan(res->sync_res, 0);
				else
					handle_port(res, pkey, lid, guid);
			} else {
				ret = get_lid(res->umad_res, &gid, &lid);
				if (ret < 0)
					/* unexpected error - do a full rescan */
					schedule_rescan(res->sync_res, 0);
				else {
					pr_debug("lid is %#x\n", lid);

					srp_sleep(0, 100);
					handle_port(res, pkey, lid,
						    be64toh(ib_gid_get_guid(&gid)));
				}
			}
		} else {
			static const struct timespec zero;
			struct timespec now, delta;
			struct timespec recalc = {
				.tv_sec = config->recalc_time
			};
			struct timeval timeout;

			clock_gettime(CLOCK_MONOTONIC, &now);
			ts_sub(&res->sync_res->next_recalc_time, &now, &delta);
			pthread_mutex_unlock(&res->sync_res->mutex);

			if (ts_cmp(&zero, &delta, <=) &&
			    ts_cmp(&delta, &recalc, <))
				recalc = delta;
			timeout.tv_sec = recalc.tv_sec;
			timeout.tv_usec = recalc.tv_nsec / 1000 + 1;

			received_signal = get_received_signal(timeout.tv_sec,
							timeout.tv_usec) ? :
				received_signal;
		}
	}

	ret = 0;

kill_threads:
	switch (received_signal) {
	case SIGINT:
		pr_err("Got SIGINT\n");
		break;
	case SIGTERM:
		pr_err("Got SIGTERM\n");
		break;
	case SRP_CATAS_ERR:
		pr_err("Got SIG SRP_CATAS_ERR\n");
		break;
	case 0:
		break;
	default:
		pr_err("Got SIG???\n");
		break;
	}

	if (subscribed && received_signal != SRP_CATAS_ERR) {
		pr_err("Deregistering traps ...\n");
		register_to_traps(res, 0);
		pr_err("Finished trap deregistration.\n");
	}
free_res:
	free_res(res);
	/* Discard the SIGINT triggered by the free_res() implementation. */
	get_received_signal(0, 0);
clean_umad:
	umad_done();
	if (received_signal == SRP_CATAS_ERR) {
		/*
		 * Device got a catastrophic error. Let's wait a grace
		 * period and try to probe the device by attempting to
		 * allocate IB resources. Once it recovers, we will
		 * start all over again.
		 */
		received_signal = get_received_signal(10, 0) ? :
			received_signal;
		if (received_signal == SRP_CATAS_ERR)
			goto catas_start;
	}
close_lockfd:
	if (lockfd >= 0)
		close(lockfd);
cleanup_wakeup:
	cleanup_wakeup_fd();
free_config:
	free_config(config);
close_log:
	closelog();
out:
	exit(ret ? 1 : 0);
}

static int recalc(struct resources *res)
{
	struct umad_resources *umad_res = res->umad_res;
	int  mask_match;
	char val[7];
	int ret;

	ret = srpd_sys_read_string(umad_res->port_sysfs_path, "sm_lid", val, sizeof val);
	if (ret < 0) {
		pr_err("Couldn't read SM LID\n");
		return ret;
	}

	umad_res->sm_lid = strtol(val, NULL, 0);
	if (umad_res->sm_lid == 0) {
		pr_err("SM LID is 0, maybe no SM is running\n");
		return -1;
	}

	ret = check_sm_cap(umad_res, &mask_match);
	if (ret < 0)
		return ret;

	if (mask_match) {
		pr_debug("Advanced SM, performing a capability query\n");
		ret = do_dm_port_list(res);
	} else {
		pr_debug("Old SM, performing a full node query\n");
		ret = do_full_port_list(res);
	}

	return ret;
}

static int get_lid(struct umad_resources *umad_res, union umad_gid *gid,
		   uint16_t *lid)
{
	struct srp_ib_user_mad		out_mad, in_mad;
	struct umad_sa_packet		*in_sa_mad  = get_data_ptr(in_mad);
	struct umad_sa_packet		*out_sa_mad = get_data_ptr(out_mad);
	struct ib_path_rec		*path_rec   = (struct ib_path_rec *) out_sa_mad->data;

	memset(&in_mad, 0, sizeof(in_mad));
	init_srp_sa_mad(&out_mad, umad_res->agent, umad_res->sm_lid,
		        UMAD_SA_ATTR_PATH_REC, 0);

	out_sa_mad->comp_mask = htobe64( 4 | 8 | 64 | 512 | 4096 );

	path_rec->sgid = *gid;
	path_rec->dgid = *gid;
	path_rec->reversible_numpath = 1;
	path_rec->hop_flow_raw = htobe32(1 << 31); /* rawtraffic=1 hoplimit = 0 */

	if (send_and_get(umad_res->portid, umad_res->agent, &out_mad, &in_mad, 0) < 0)
		return -1;

	path_rec = (struct ib_path_rec *) in_sa_mad->data;

	*lid = be16toh(path_rec->dlid);

	return 0;
}
