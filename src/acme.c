/*
 * Copyright (c) 2009-2010 Intel Corporation.  All rights reserved.
 * Copyright (c) 2013 Mellanox Technologies LTD. All rights reserved.
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
#include "acm_util.h"

static char *dest_dir = ACM_CONF_DIR;
static char *addr_file = ACM_ADDR_FILE;
static char *opts_file = ACM_OPTS_FILE;

static char *dest_addr;
static char *src_addr;
static char *svc_arg = "localhost";
static char *dest_arg;
static char *src_arg;
static char addr_type = 'u';
static int verify;
static int nodelay;
static int repetitions = 1;

enum perf_query_output {
	PERF_QUERY_NONE,
	PERF_QUERY_ROW,
	PERF_QUERY_COL
};
static enum perf_query_output perf_query;
int verbose;

struct ibv_context **verbs;
int dev_cnt;

extern int gen_addr_ip(FILE *f);
extern char **parse(char *args, int *count);

#define VPRINT(format, ...) do { if (verbose) printf(format, ## __VA_ARGS__ ); } while (0)

static void show_usage(char *program)
{
	printf("usage 1: %s\n", program);
	printf("Query specified ibacm service for data\n");
	printf("   [-f addr_format] - i(p), n(ame), l(id), g(gid), or u(nspecified)\n");
	printf("                      address format for -s and -d options, default: 'u'\n");
	printf("   [-s src_addr]    - source address for path queries\n");
	printf("   [-d dest_addr]   - destination addresses for path queries\n");
	printf("   [-v]             - verify ACM response against SA query response\n");
	printf("   [-c]             - read ACM cached data only\n");
	printf("   [-P]             - query performance data from destination service\n");
	printf("   [-S svc_addr]    - address of ACM service, default: local service\n");
	printf("   [-C repetitions] - repeat count for resolution\n");
	printf("usage 2: %s\n", program);
	printf("Generate default ibacm service configuration and option files\n");
	printf("   -A [addr_file]   - generate local address configuration file\n");
	printf("                      (default is %s)\n", ACM_ADDR_FILE);
	printf("   -O [opt_file]    - generate local ibacm_opts.cfg options file\n");
	printf("                      (default is %s)\n", ACM_OPTS_FILE);
	printf("   -D dest_dir      - specify destination directory for output files\n");
	printf("                      (default is %s)\n", ACM_CONF_DIR);
	printf("   -V               - enable verbose output\n");
}

static void gen_opts_temp(FILE *f)
{
	fprintf(f, "# InfiniBand Communication Manager Assistant for clusters configuration file\n");
	fprintf(f, "#\n");
	fprintf(f, "# Use ib_acme utility with -O option to automatically generate a sample\n");
	fprintf(f, "# ibacm_opts.cfg file for the current system.\n");
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
	fprintf(f, "lock_file /var/run/ibacm.pid\n");
	fprintf(f, "\n");
	fprintf(f, "# addr_prot:\n");
	fprintf(f, "# Default resolution protocol to resolve IP addresses into IB GIDs.\n");
	fprintf(f, "# Supported protocols are:\n");
	fprintf(f, "# acm - Use ACM multicast protocol, which is similar to ARP.\n");
	fprintf(f, "\n");
	fprintf(f, "addr_prot acm\n");
	fprintf(f, "\n");
	fprintf(f, "# addr_timeout:\n");
	fprintf(f, "# Number of minutes to maintain IP address to GID mapping before\n");
	fprintf(f, "# repeating address resolution.  A value of -1 indicates that the\n");
	fprintf(f, "# mapping will not time out.\n");
	fprintf(f, "# 1 hour = 60, 1 day = 1440, 1 week = 10080, 1 month ~ 43200");
	fprintf(f, "\n");
	fprintf(f, "addr_timeout 1440\n");
	fprintf(f, "\n");
	fprintf(f, "# route_prot:\n");
	fprintf(f, "# Default resolution protocol to resolve IB routing information.\n");
	fprintf(f, "# Supported protocols are:\n");
	fprintf(f, "# sa - Query SA for path record data and cache results.\n");
	fprintf(f, "# acm - Use ACM multicast protocol.\n");
	fprintf(f, "\n");
	fprintf(f, "route_prot sa\n");
	fprintf(f, "\n");
	fprintf(f, "# route_timeout:\n");
	fprintf(f, "# Number of minutes to maintain IB routing information before\n");
	fprintf(f, "# repeating route resolution.  A value of -1 indicates that the\n");
	fprintf(f, "# mapping will not time out.  However, the route will\n");
	fprintf(f, "# automatically time out when the address times out.\n");
	fprintf(f, "# 1 hour = 60, 1 day = 1440, 1 week = 10080, 1 month ~ 43200");
	fprintf(f, "\n");
	fprintf(f, "route_timeout -1\n");
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
	fprintf(f, "# be in progress simultaneously.  A larger send depth allows for\n");
	fprintf(f, "# greater parallelism, but consumes more system resources and subnet load.\n");
	fprintf(f, "# The send_depth is in addition to resolve_depth and sa_depth, and limits\n");
	fprintf(f, "# the transfer of responses.\n");
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
	fprintf(f, "# route_preload:\n");
	fprintf(f, "# Specifies if the ACM routing cache should be preloaded, or built on demand.\n");
	fprintf(f, "# If preloaded, indicates the method used to build the cache.\n");
	fprintf(f, "# Supported preload values are:\n");
	fprintf(f, "# none - The routing cache is not pre-built (default)\n");
	fprintf(f, "# opensm_full_v1 - OpenSM 'full' path records dump file format (version 1)\n");
	fprintf(f, "\n");
	fprintf(f, "route_preload none\n");
	fprintf(f, "\n");
	fprintf(f, "# route_data_file:\n");
	fprintf(f, "# Specifies the location of the route data file to use when preloading\n");
	fprintf(f, "# the ACM cache.  This option is only valid if route_preload\n");
	fprintf(f, "# indicates that routing data should be read from a file.\n");
	fprintf(f, "# Default is ACM_CONF_DIR/ibacm_route.data\n");
	fprintf(f, "# route_data_file /etc/rdma/ibacm_route.data\n");
	fprintf(f, "\n");
	fprintf(f, "# addr_preload:\n");
	fprintf(f, "# Specifies if the ACM address cache should be preloaded, or built on demand.\n");
	fprintf(f, "# If preloaded, indicates the method used to build the cache.\n");
	fprintf(f, "# Supported preload values are:\n");
	fprintf(f, "# none - The address cache is not pre-built (default)\n");
	fprintf(f, "# acm_hosts - ACM address to GID file format\n");
	fprintf(f, "\n");
	fprintf(f, "addr_preload none\n");
	fprintf(f, "\n");
	fprintf(f, "# addr_data_file:\n");
	fprintf(f, "# Specifies the location of the address data file to use when preloading\n");
	fprintf(f, "# the ACM cache.  This option is only valid if addr_preload\n");
	fprintf(f, "# indicates that address data should be read from a file.\n");
	fprintf(f, "# Default is ACM_CONF_DIR/ibacm_hosts.data\n");
	fprintf(f, "# addr_data_file /etc/rdma/ibacm_hosts.data\n");
	fprintf(f, "\n");
	fprintf(f, "# support_ips_in_addr_cfg:\n");
	fprintf(f, "# If 1 continue to read IP addresses from ibacm_addr.cfg\n");
	fprintf(f, "# Default is 0 \"no\"\n");
	fprintf(f, "# support_ips_in_addr_cfg 0\n");
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

	VPRINT("Generating %s/%s\n", dest_dir, opts_file);
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
	fprintf(f, "# Use ib_acme utility with -A option to automatically generate a sample\n");
	fprintf(f, "# ibacm_addr.cfg file for the current system.\n");
	fprintf(f, "#\n");
	fprintf(f, "# Entry format is:\n");
	fprintf(f, "# address device port pkey\n");
	fprintf(f, "#\n");
	fprintf(f, "# NOTE: IP addresses are now automatically read and monitored on the system.\n");
	fprintf(f, "#       Therefore they are no longer required in this file.\n");
	fprintf(f, "#\n");
	fprintf(f, "# The address may be one of the following:\n");
	fprintf(f, "# host_name - ascii character string, up to 31 characters\n");
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
		if (!verbs[i]) {
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
					VPRINT("%s %s %d default\n",
						host_name, verbs[i]->device->name, p);
					fprintf(f, "%s %s %d default\n",
						host_name, verbs[i]->device->name, p);
					found_active = 1;
				}
			}

			VPRINT("%s-%d %s %d default\n",
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

	VPRINT("Generating %s/%s\n", dest_dir, addr_file);
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
	printf("  dlid: %u\n", ntohs(path->dlid));
	printf("  slid: %u\n", ntohs(path->slid));
	fl_hop = ntohl(path->flowlabel_hoplimit);
	printf("  flow label: 0x%x\n", fl_hop >> 8);
	printf("  hop limit: %d\n", (uint8_t) fl_hop);
	printf("  tclass: %d\n", path->tclass);
	printf("  reversible: %d\n", path->reversible_numpath >> 7);
	printf("  pkey: 0x%x\n", ntohs(path->pkey));
	printf("  sl: %d\n", ntohs(path->qosclass_sl) & 0xF);
	printf("  mtu: %d\n", path->mtu & 0x1F);
	printf("  rate: %d\n", path->rate & 0x1F);
	printf("  packet lifetime: %d\n", path->packetlifetime & 0x1F);
}

static uint32_t get_resolve_flags()
{
	uint32_t flags = 0;

	if (nodelay)
		flags |= ACM_FLAGS_NODELAY;

	return flags;
}

static int inet_any_pton(char *addr, struct sockaddr *sa)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int ret;

	sin = (struct sockaddr_in *) sa;
	sa->sa_family = AF_INET;
	ret = inet_pton(AF_INET, addr, &sin->sin_addr);
	if (ret <= 0) {
		sin6 = (struct sockaddr_in6 *) sa;
		sa->sa_family = AF_INET6;
		ret = inet_pton(AF_INET6, src_addr, &sin6->sin6_addr);
	}

	return ret;
}

static int resolve_ip(struct ibv_path_record *path)
{
	struct ibv_path_data *paths;
	struct sockaddr_storage src, dest;
	struct sockaddr *saddr;
	int ret, count;

	if (src_addr) {
		saddr = (struct sockaddr *) &src;
		ret = inet_any_pton(src_addr, saddr);
		if (ret <= 0) {
			printf("inet_pton error on source address (%s): 0x%x\n", src_addr, ret);
			return -1;
		}
	} else {
		saddr = NULL;
	}

	ret = inet_any_pton(dest_addr, (struct sockaddr *) &dest);
	if (ret <= 0) {
		printf("inet_pton error on destination address (%s): 0x%x\n", dest_addr, ret);
		return -1;
	}

	if (src_addr && src.ss_family != dest.ss_family) {
		printf("source and destination address families don't match\n");
		return -1;
	}

	ret = ib_acm_resolve_ip(saddr, (struct sockaddr *) &dest,
		&paths, &count, get_resolve_flags(), (repetitions == 1));
	if (ret) {
		printf("ib_acm_resolve_ip failed: %s\n", strerror(errno));
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

	ret = ib_acm_resolve_name(src_addr, dest_addr, &paths, &count, get_resolve_flags(), (repetitions == 1));
	if (ret) {
		printf("ib_acm_resolve_name failed: %s\n", strerror(errno));
		return ret;
	}

	*path = paths[0].path;
	ib_acm_free_paths(paths);
	return 0;
}

static int resolve_lid(struct ibv_path_record *path)
{
	int ret;

	if (src_addr)
		path->slid = htons((uint16_t) atoi(src_addr));
	path->dlid = htons((uint16_t) atoi(dest_addr));
	path->reversible_numpath = IBV_PATH_RECORD_REVERSIBLE | 1;

	ret = ib_acm_resolve_path(path, get_resolve_flags());
	if (ret)
		printf("ib_acm_resolve_path failed: %s\n", strerror(errno));

	return ret;
}

static int resolve_gid(struct ibv_path_record *path)
{
	int ret;

	if (src_addr) {
		ret = inet_pton(AF_INET6, src_addr, &path->sgid);
		if (ret <= 0) {
			printf("inet_pton error on source address (%s): 0x%x\n",
			       src_addr, ret);
			return ret ? ret : -1;
		}
	}

	ret = inet_pton(AF_INET6, dest_addr, &path->dgid);
	if (ret <= 0) {
		printf("inet_pton error on dest address (%s): 0x%x\n", dest_addr, ret);
		return ret ? ret : -1;
	}

	path->reversible_numpath = IBV_PATH_RECORD_REVERSIBLE | 1;
	ret = ib_acm_resolve_path(path, get_resolve_flags());
	if (ret)
		printf("ib_acm_resolve_path failed: %s\n", strerror(errno));

	return ret;
}

static int verify_resolve(struct ibv_path_record *path)
{
	int ret;

	ret = ib_acm_resolve_path(path, ACM_FLAGS_QUERY_SA);
	if (ret)
		printf("SA verification: failed %s\n", strerror(errno));
	else
		printf("SA verification: success\n");

	return ret;
}

static char *get_dest(char *arg, char *format)
{
	static char addr[64];
	struct addrinfo hint, *res;
	const char *ai;
	int ret;

	if (!arg || addr_type != 'u') {
		*format = addr_type;
		return arg;
	}

	if ((inet_pton(AF_INET, arg, addr) > 0) || (inet_pton(AF_INET6, arg, addr) > 0)) {
		*format = 'i';
		return arg;
	}

	memset(&hint, 0, sizeof hint);
	hint.ai_protocol = IPPROTO_TCP;
	ret = getaddrinfo(arg, NULL, &hint, &res);
	if (ret) {
		*format = 'l';
		return arg;
	}

	if (res->ai_family == AF_INET) {
		ai = inet_ntop(AF_INET, &((struct sockaddr_in *) res->ai_addr)->sin_addr,
				addr, sizeof addr);
	} else {
		ai = inet_ntop(AF_INET6, &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr,
				addr, sizeof addr);
	}
	freeaddrinfo(res);

	if (ai) {
		*format = 'i';
		return addr;
	} else {
		*format = 'n';
		return arg;
	}
}

static void resolve(char *svc)
{
	char **dest_list, **src_list;
	struct ibv_path_record path;
	int ret = 0, d = 0, s = 0, i;
	char dest_type;

	dest_list = parse(dest_arg, NULL);
	if (!dest_list) {
		printf("Unable to parse destination argument\n");
		return;
	}

	src_list = src_arg ? parse(src_arg, NULL) : NULL;

	printf("Service: %s\n", svc);
	for (dest_addr = get_dest(dest_list[d], &dest_type); dest_addr;
	     dest_addr = get_dest(dest_list[++d], &dest_type)) {
		s = 0;
		src_addr = src_list ? src_list[s] : NULL;
		do {
			printf("Destination: %s\n", dest_addr);
			if (src_addr)
				printf("Source: %s\n", src_addr);
			for (i = 0; i < repetitions; i++) {
				switch (dest_type) {
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
				case 'g':
					memset(&path, 0, sizeof path);
					ret = resolve_gid(&path);
					break;
				default:
					break;
				}
			}

			if (!ret)
				show_path(&path);

			if (verify)
				ret = verify_resolve(&path);
			printf("\n");

			if (src_list)
				src_addr = src_list[++s];
		} while (src_addr);
	}

	free(dest_list);
}

static void query_perf(char *svc)
{
	static int lables;
	int ret, cnt, i;
	uint64_t *counters;

	ret = ib_acm_query_perf(&counters, &cnt);
	if (ret) {
		printf("%s: Failed to query perf data %s\n", svc, strerror(errno));
		return;
	}

	if (perf_query == PERF_QUERY_ROW) {
		if (!lables) {
			for (i = 0; i < cnt - 1; i++)
				printf("%s,", ib_acm_cntr_name(i));
			printf("%s\n", ib_acm_cntr_name(i));
			lables = 1;
		}
		printf("%s,", svc);
		for (i = 0; i < cnt - 1; i++)
			printf("%llu,", (unsigned long long) counters[i]);
		printf("%llu\n", (unsigned long long) counters[i]);
	} else {
		printf("%s\n", svc);
		for (i = 0; i < cnt; i++) {
			printf("%s : ", ib_acm_cntr_name(i));
			printf("%llu\n", (unsigned long long) counters[i]);
		}
	}
	ib_acm_free_perf(counters);
}

static int query_svcs(void)
{
	char **svc_list;
	int ret, i;

	svc_list = parse(svc_arg, NULL);
	if (!svc_list) {
		printf("Unable to parse service list argument\n");
		return -1;
	}

	for (i = 0; svc_list[i]; i++) {
		ret = ib_acm_connect(svc_list[i]);
		if (ret) {
			printf("%s,unable to contact service: %s\n",
				svc_list[i], strerror(errno));
			continue;
		}

		if (dest_arg)
			resolve(svc_list[i]);

		if (perf_query)
			query_perf(svc_list[i]);

		ib_acm_disconnect();
	}

	free(svc_list);
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
	int make_addr = 0;
	int make_opts = 0;

	ret = osd_init();
	if (ret)
		goto out;

	while ((op = getopt(argc, argv, "f:s:d:vcA::O::D:P::S:C:V")) != -1) {
		switch (op) {
		case 'f':
			addr_type = optarg[0];
			if (addr_type != 'i' && addr_type != 'n' &&
			    addr_type != 'l' && addr_type != 'g')
				goto show_use;
			break;
		case 's':
			src_arg = optarg;
			break;
		case 'd':
			dest_arg = optarg;
			break;
		case 'v':
			verify = 1;
			break;
		case 'c':
			nodelay = 1;
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
		case 'P':
			if (opt_arg(argc, argv) && !strnicmp("col", opt_arg(argc, argv), 3))
				perf_query = PERF_QUERY_COL;
			else
				perf_query = PERF_QUERY_ROW;
			break;
		case 'S':
			svc_arg = optarg;
			break;
		case 'C':
			repetitions = atoi(optarg);
			if (!repetitions)
				repetitions = 1;
			break;
		case 'V':
			verbose = 1;
			break;
		default:
			goto show_use;
		}
	}

	if ((src_arg && !dest_arg) ||
	    (!src_arg && !dest_arg && !perf_query && !make_addr && !make_opts))
		goto show_use;

	if (dest_arg || perf_query)
		ret = query_svcs();

	if (!ret && make_addr)
		ret = gen_addr();

	if (!ret && make_opts)
		ret = gen_opts();

	osd_close();
out:
	if (verbose || !(make_addr || make_opts) || ret)
		printf("return status 0x%x\n", ret);
	return ret;

show_use:
	show_usage(argv[0]);
	exit(1);
}
