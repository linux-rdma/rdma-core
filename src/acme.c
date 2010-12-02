/*
 * Copyright (c) 2009-2010 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <osd.h>
#include <infiniband/verbs.h>
#include <infiniband/acm.h>
#include "libacm.h"

static char *dest_dir = ACM_DEST_DIR;
static char *addr_file = ACM_ADDR_FILE;
static char *opts_file = ACM_OPTS_FILE;

static char *dest_addr;
static char *src_addr;
static char addr_type = 'i';
static int verify;
static int make_addr;
static int make_opts;

struct ibv_context **verbs;
int dev_cnt;

extern int gen_addr_ip(FILE *f);

static void show_usage(char *program)
{
	printf("usage 1: %s\n", program);
	printf("   [-f addr_format] - i(p), n(ame), or l(id)\n");
	printf("                      default: 'i'\n");
	printf("   -s src_addr      - format defined by -f option\n");
	printf("   -d dest_addr     - format defined by -f option\n");
	printf("   [-v]             - verify ACM response against SA query response\n");
	printf("usage 2: %s\n", program);
	printf("   -A [addr_file]   - generate local address configuration file\n");
	printf("                      (default is %s)\n", ACM_ADDR_FILE);
	printf("   -O [opt_file]    - generate local acm_opts.cfg options file\n");
	printf("                      (default is %s)\n", ACM_OPTS_FILE);
	printf("   -D dest_dir      - specify destination directory for output files\n");
	printf("                      (default is %s)\n", ACM_DEST_DIR);
}

static void gen_opts_temp(FILE *f)
{
	fprintf(f, "# InfiniBand Multicast Communication Manager for clusters configuration file\n");
	fprintf(f, "#\n");
	fprintf(f, "# Use ib_acme utility with -O option to automatically generate a sample\n");
	fprintf(f, "# acm_opts.cfg file for the current system.\n");
	fprintf(f, "#\n");
	fprintf(f, "# Entry format is:\n");
	fprintf(f, "# name value\n");
	fprintf(f, "\n");
	fprintf(f, "# log_file:\n");
	fprintf(f, "# Specifies the location of the ACM service output.  The log file is used to\n");
	fprintf(f, "# assist with ACM service debugging and troubleshooting.  The log_file can\n");
	fprintf(f, "# be set to 'stdout', 'stderr', or the name of a file.\n");
	fprintf(f, "# Examples:\n");
	fprintf(f, "# log_file stdout\n");
	fprintf(f, "# log_file stderr\n");
	fprintf(f, "# log_file /var/log/ibacm.log\n");
	fprintf(f, "\n");
	fprintf(f, "log_file /var/log/ibacm.log\n");
	fprintf(f, "\n");
	fprintf(f, "# log_level:\n");
	fprintf(f, "# Indicates the amount of detailed data written to the log file.  Log levels\n");
	fprintf(f, "# should be one of the following values:\n");
	fprintf(f, "# 0 - basic configuration & errors\n");
	fprintf(f, "# 1 - verbose configuration & errors\n");
	fprintf(f, "# 2 - verbose operation\n");
	fprintf(f, "\n");
	fprintf(f, "log_level 0\n");
	fprintf(f, "\n");
	fprintf(f, "# lock_file:\n");
	fprintf(f, "# Specifies the location of the ACM lock file used to ensure that only a\n");
	fprintf(f, "# single instance of ACM is running.\n");
	fprintf(f, "\n");
	fprintf(f, "lock_file /var/lock/ibacm.pid\n");
	fprintf(f, "\n");
	fprintf(f, "# addr_prot:\n");
	fprintf(f, "# Default resolution protocol to resolve IP addresses into IB GIDs.\n");
	fprintf(f, "# Supported protocols are:\n");
	fprintf(f, "# acm - Use ACM multicast protocol, which is similar to ARP.\n");
	fprintf(f, "\n");
	fprintf(f, "addr_prot acm\n");
	fprintf(f, "\n");
	fprintf(f, "# route_prot:\n");
	fprintf(f, "# Default resolution protocol to resolve IB routing information.\n");
	fprintf(f, "# Supported protocols are:\n");
	fprintf(f, "# sa - Query SA for path record data and cache results.\n");
	fprintf(f, "# acm - Use ACM multicast protocol.\n");
	fprintf(f, "\n");
	fprintf(f, "route_prot sa\n");
	fprintf(f, "\n");
	fprintf(f, "# loopback_prot:\n");
	fprintf(f, "# Address and route resolution protocol to resolve local addresses\n");
	fprintf(f, "# Supported protocols are:\n");
	fprintf(f, "# none - Use same protocols defined for addr_prot and route_prot\n");
	fprintf(f, "# local - Resolve information used locally available data\n");
	fprintf(f, "\n");
	fprintf(f, "loopback_prot local\n");
	fprintf(f, "\n");
	fprintf(f, "# server_port:\n");
	fprintf(f, "# TCP port number that the server listens on.\n");
	fprintf(f, "# If this value is changed, then a corresponding change is required for\n");
	fprintf(f, "# client applications.\n");
	fprintf(f, "\n");
	fprintf(f, "server_port 6125\n");
	fprintf(f, "\n");
	fprintf(f, "# timeout:\n");
	fprintf(f, "# Additional time, in milliseconds, that the ACM service will wait for a\n");
	fprintf(f, "# response from a remote ACM service or the IB SA.  The actual request\n");
	fprintf(f, "# timeout is this value plus the subnet timeout.\n");
	fprintf(f, "\n");
	fprintf(f, "timeout 2000\n");
	fprintf(f, "\n");
	fprintf(f, "# retries:\n");
	fprintf(f, "# Number of times that the ACM service will retry a request.  This affects\n");
	fprintf(f, "# both ACM multicast messages and and IB SA messages.\n");
	fprintf(f, "\n");
	fprintf(f, "retries 2\n");
	fprintf(f, "\n");
	fprintf(f, "# resolve_depth:\n");
	fprintf(f, "# Specifies the maximum number of outstanding requests that can be in\n");
	fprintf(f, "# progress simultaneously.  A larger resolve depth allows for greater\n");
	fprintf(f, "# parallelism, but increases system resource usage and subnet load.\n");
	fprintf(f, "# If the number of pending requests is greater than the resolve_depth,\n");
	fprintf(f, "# the additional requests will automatically be queued until some of\n");
	fprintf(f, "# the previous requests complete.\n");
	fprintf(f, "\n");
	fprintf(f, "resolve_depth 1\n");
	fprintf(f, "\n");
	fprintf(f, "# sa_depth:\n");
	fprintf(f, "# Specifies the maximum number of outstanding requests to the SA that\n");
	fprintf(f, "# can be in progress simultaneously.  A larger SA depth allows for greater\n");
	fprintf(f, "# parallelism, but increases system resource usage and SA load.\n");
	fprintf(f, "# If the number of pending SA requests is greater than the sa_depth,\n");
	fprintf(f, "# the additional requests will automatically be queued until some of\n");
	fprintf(f, "# the previous requests complete.  The number of outstanding SA requests\n");
	fprintf(f, "# is separate from the specified resolve_depth.\n");
	fprintf(f, "\n");
	fprintf(f, "sa_depth 1\n");
	fprintf(f, "\n");
	fprintf(f, "# send_depth:\n");
	fprintf(f, "# Specifies the number of outstanding send operations that can\n");
	fprintf(f, "# be in progress simultaneously.  A larger send depth consumes\n");
	fprintf(f, "# more system resources, but increases subnet load.  The send_depth\n");
	fprintf(f, "# is in addition to resolve_depth and sa_depth, and limits the\n");
	fprintf(f, "# transfer of responses.\n");
	fprintf(f, "\n");
	fprintf(f, "send_depth 1\n");
	fprintf(f, "\n");
	fprintf(f, "# recv_depth:\n");
	fprintf(f, "# Specifies the number of buffers allocated and ready to receive remote\n");
	fprintf(f, "# requests.  A larger receive depth consumes more system resources, but\n");
	fprintf(f, "# can avoid dropping requests due to insufficient receive buffers.\n");
	fprintf(f, "\n");
	fprintf(f, "recv_depth 1024\n");
	fprintf(f, "\n");
	fprintf(f, "# min_mtu:\n");
	fprintf(f, "# Indicates the minimum MTU supported by the ACM service.  The ACM service\n");
	fprintf(f, "# negotiates to use the largest MTU available between both sides of a\n");
	fprintf(f, "# connection.  It is most efficient and recommended that min_mtu be set\n");
	fprintf(f, "# to the largest MTU value supported by all nodes in a cluster.\n");
	fprintf(f, "\n");
	fprintf(f, "min_mtu 2048\n");
	fprintf(f, "\n");
	fprintf(f, "# min_rate:\n");
	fprintf(f, "# Indicates the minimum link rate, in Gbps, supported by the ACM service.\n");
	fprintf(f, "# The ACM service negotiates to use the highest rate available between both\n");
	fprintf(f, "# sides of a connection.  It is most efficient and recommended that the\n");
	fprintf(f, "# min_rate be set to the largest rate supported by all nodes in a cluster.\n");
	fprintf(f, "\n");
	fprintf(f, "min_rate 10\n");
	fprintf(f, "\n");
}

static int open_dir(void)
{
	mkdir(dest_dir, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (chdir(dest_dir)) {
		printf("Failed to open directory %s: %s\n", dest_dir, strerror(errno));
		return -1;
	}
	return 0;
}

static int gen_opts(void)
{
	FILE *f;

	printf("Generating %s/%s\n", dest_dir, opts_file);
	if (open_dir() || !(f = fopen(opts_file, "w"))) {
		printf("Failed to open option configuration file: %s\n", strerror(errno));
		return -1;
	}

	gen_opts_temp(f);
	fclose(f);
	return 0;
}

static void gen_addr_temp(FILE *f)
{
	fprintf(f, "# InfiniBand Communication Management Assistant for clusters address file\n");
	fprintf(f, "#\n");
	fprintf(f, "# Use ib_acme utility with -G option to automatically generate a sample\n");
	fprintf(f, "# acm_addr.cfg file for the current system.\n");
	fprintf(f, "#\n");
	fprintf(f, "# Entry format is:\n");
	fprintf(f, "# address device port pkey\n");
	fprintf(f, "#\n");
	fprintf(f, "# The address may be one of the following:\n");
	fprintf(f, "# host_name - ascii character string, up to 31 characters\n");
	fprintf(f, "# address - IPv4 or IPv6 formatted address\n");
	fprintf(f, "#\n");
	fprintf(f, "# device name - struct ibv_device name\n");
	fprintf(f, "# port number - valid port number on device (numbering starts at 1)\n");
	fprintf(f, "# pkey - partition key in hex (can specify 'default' for pkey 0xFFFF)\n");
	fprintf(f, "#\n");
	fprintf(f, "# Up to 4 addresses can be associated with a given <device, port, pkey> tuple\n");
	fprintf(f, "#\n");
	fprintf(f, "# Samples:\n");
	fprintf(f, "# node31      ibv_device0 1 default\n");
	fprintf(f, "# node31-1    ibv_device0 1 0x00FF\n");
	fprintf(f, "# node31-2    ibv_device0 2 0x00FF\n");
	fprintf(f, "# 192.168.0.1 ibv_device0 1 0xFFFF\n");
	fprintf(f, "# 192.168.0.2 ibv_device0 2 default\n");
}

static int open_verbs(void)
{
	struct ibv_device **dev_array;
	int i, ret;

	dev_array = ibv_get_device_list(&dev_cnt);
	if (!dev_array) {
		printf("ibv_get_device_list - no devices present?\n");
		return -1;
	}

	verbs = malloc(sizeof(struct ibv_context *) * dev_cnt);
	if (!verbs) {
		ret = -1;
		goto err1;
	}

	for (i = 0; i < dev_cnt; i++) {
		verbs[i] = ibv_open_device(dev_array[i]);
		if (!verbs) {
			printf("ibv_open_device - failed to open device\n");
			ret = -1;
			goto err2;
		}
	}

	ibv_free_device_list(dev_array);
	return 0;

err2:
	while (i--)
		ibv_close_device(verbs[i]);
	free(verbs);
err1:
	ibv_free_device_list(dev_array);
	return ret;
}

static void close_verbs(void)
{
	int i;

	for (i = 0; i < dev_cnt; i++)
		ibv_close_device(verbs[i]);
	free(verbs);
}

static int gen_addr_names(FILE *f)
{
	struct ibv_device_attr dev_attr;
	struct ibv_port_attr port_attr;
	int i, index, ret, found_active;
	char host_name[256];
	uint8_t p;

	ret = gethostname(host_name, sizeof host_name);
	if (ret) {
		printf("gethostname error: %d\n", ret);
		return ret;
	}
	strtok(host_name, ".");

	found_active = 0;
	index = 1;
	for (i = 0; i < dev_cnt; i++) {
		ret = ibv_query_device(verbs[i], &dev_attr);
		if (ret)
			break;

		for (p = 1; p <= dev_attr.phys_port_cnt; p++) {
			if (!found_active) {
				ret = ibv_query_port(verbs[i], p, &port_attr);
				if (!ret && port_attr.state == IBV_PORT_ACTIVE) {
					printf("%s %s %d default\n",
						host_name, verbs[i]->device->name, p);
					fprintf(f, "%s %s %d default\n",
						host_name, verbs[i]->device->name, p);
					found_active = 1;
				}
			}

			printf("%s-%d %s %d default\n",
				host_name, index, verbs[i]->device->name, p);
			fprintf(f, "%s-%d %s %d default\n",
				host_name, index++, verbs[i]->device->name, p);
		}
	}

	return ret;
}

static int gen_addr(void)
{
	FILE *f;
	int ret;

	printf("Generating %s/%s\n", dest_dir, addr_file);
	if (open_dir() || !(f = fopen(addr_file, "w"))) {
		printf("Failed to open address configuration file: %s\n", strerror(errno));
		return -1;
	}

	ret = open_verbs();
	if (ret) {
		goto out1;
	}

	gen_addr_temp(f);
	ret = gen_addr_names(f);
	if (ret) {
		printf("Failed to auto generate host names in config file\n");
		goto out2;
	}

	ret = gen_addr_ip(f);
	if (ret) {
		printf("Failed to auto generate IP addresses in config file\n");
		goto out2;
	}

out2:
	close_verbs();
out1:
	fclose(f);
	return ret;
}

static void show_path(struct ibv_path_record *path)
{
	char gid[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];
	uint32_t fl_hop;

	printf("Path information\n");
	inet_ntop(AF_INET6, path->dgid.raw, gid, sizeof gid);
	printf("  dgid: %s\n", gid);
	inet_ntop(AF_INET6, path->sgid.raw, gid, sizeof gid);
	printf("  sgid: %s\n", gid);
	printf("  dlid: 0x%x\n", ntohs(path->dlid));
	printf("  slid: 0x%x\n", ntohs(path->slid));
	fl_hop = ntohl(path->flowlabel_hoplimit);
	printf("  flow label: 0x%x\n", fl_hop >> 8);
	printf("  hop limit: %d\n", (uint8_t) fl_hop);
	printf("  tclass: %d\n", path->tclass);
	printf("  reverisible: %d\n", path->reversible_numpath >> 7);
	printf("  pkey: 0x%x\n", ntohs(path->pkey));
	printf("  sl: %d\n", ntohs(path->qosclass_sl) & 0xF);
	printf("  mtu: %d\n", path->mtu & 0x1F);
	printf("  rate: %d\n", path->rate & 0x1F);
	printf("  packet lifetime: %d\n", path->packetlifetime & 0x1F);
}

static int resolve_ip(struct ibv_path_record *path)
{
	struct ibv_path_data *paths;
	struct sockaddr_in src, dest;
	int ret, count;

	src.sin_family = AF_INET;
	ret = inet_pton(AF_INET, src_addr, &src.sin_addr);
	if (ret <= 0) {
		printf("inet_pton error on source address (%s): 0x%x\n", src_addr, ret);
		return ret;
	}

	dest.sin_family = AF_INET;
	ret = inet_pton(AF_INET, dest_addr, &dest.sin_addr);
	if (ret <= 0) {
		printf("inet_pton error on destination address (%s): 0x%x\n", dest_addr, ret);
		return ret;
	}

	ret = ib_acm_resolve_ip((struct sockaddr *) &src, (struct sockaddr *) &dest,
		&paths, &count);
	if (ret) {
		printf("ib_acm_resolve_ip failed: 0x%x\n", ret);
		return ret;
	}

	*path = paths[0].path;
	ib_acm_free_paths(paths);
	return 0;
}

static int resolve_name(struct ibv_path_record *path)
{
	struct ibv_path_data *paths;
	int ret, count;

	ret = ib_acm_resolve_name(src_addr, dest_addr, &paths, &count);
	if (ret) {
		printf("ib_acm_resolve_name failed: 0x%x\n", ret);
		return ret;
	}

	*path = paths[0].path;
	ib_acm_free_paths(paths);
	return 0;
}

static int resolve_lid(struct ibv_path_record *path)
{
	int ret;

	path->slid = htons((uint16_t) atoi(src_addr));
	path->dlid = htons((uint16_t) atoi(dest_addr));
	path->reversible_numpath = IBV_PATH_RECORD_REVERSIBLE | 1;

	ret = ib_acm_resolve_path(path, 0);
	if (ret)
		printf("ib_acm_resolve_path failed: 0x%x\n", ret);

	return ret;
}

static int verify_resolve(struct ibv_path_record *path)
{
	int ret;

	ret = ib_acm_resolve_path(path, ACM_FLAGS_QUERY_SA);
	if (ret)
		printf("SA verification: failed 0x%x\n", ret);
	else
		printf("SA verification: success\n");

	return ret;
}

static int resolve(char *program)
{
	struct ibv_path_record path;
	int ret;

	ret = libacm_init();
	if (ret) {
		printf("Unable to contact ib_acm service\n");
		return ret;
	}

	switch (addr_type) {
	case 'i':
		ret = resolve_ip(&path);
		break;
	case 'n':
		ret = resolve_name(&path);
		break;
	case 'l':
		memset(&path, 0, sizeof path);
		ret = resolve_lid(&path);
		break;
	default:
		show_usage(program);
		exit(1);
	}

	if (!ret)
		show_path(&path);

	if (verify)
		ret = verify_resolve(&path);

	libacm_cleanup();
	return ret;
}

char *opt_arg(int argc, char **argv)
{
	if (optarg)
		return optarg;

	if ((optind < argc) && (argv[optind][0] != '-'))
		return argv[optind];

	return NULL;
}

int CDECL_FUNC main(int argc, char **argv)
{
	int op, ret;

	ret = osd_init();
	if (ret)
		goto out;

	while ((op = getopt(argc, argv, "f:s:d:vA::O::D:")) != -1) {
		switch (op) {
		case 'f':
			addr_type = optarg[0];
			break;
		case 's':
			src_addr = optarg;
			break;
		case 'd':
			dest_addr = optarg;
			break;
		case 'v':
			verify = 1;
			break;
		case 'A':
			make_addr = 1;
			if (opt_arg(argc, argv))
				addr_file = opt_arg(argc, argv);
			break;
		case 'O':
			make_opts = 1;
			if (opt_arg(argc, argv))
				opts_file = opt_arg(argc, argv);
			break;
		case 'D':
			dest_dir = optarg;
			break;
		default:
			show_usage(argv[0]);
			exit(1);
		}
	}

	if ((src_addr && !dest_addr) || (dest_addr && !src_addr) ||
		(!src_addr && !dest_addr && !make_addr && !make_opts)) {
		show_usage(argv[0]);
		exit(1);
	}

	if (src_addr)
		ret = resolve(argv[0]);

	if (!ret && make_addr)
		ret = gen_addr();

	if (!ret && make_opts)
		ret = gen_opts();

out:
	printf("return status 0x%x\n", ret);
	return ret;
}
