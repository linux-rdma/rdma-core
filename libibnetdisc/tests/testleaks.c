/*
 * Copyright (c) 2004-2007 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2007 Xsigo Systems Inc.  All rights reserved.
 * Copyright (c) 2008 Lawrence Livermore National Lab.  All rights reserved.
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
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <inttypes.h>

#include <infiniband/ibnetdisc.h>

static const char *argv0 = "iblinkinfotest";
static FILE *f;

static void usage(void)
{
	fprintf(stderr,
		"Usage: %s [-hclp -D <direct route> -C <ca_name> -P <ca_port>]\n"
		"   Report link speed and connection for each port of each switch which is active\n"
		"   -h This help message\n"
		"   -i <iters> Number of iterations to run (default -1 == infinate)\n"
		"   -f <dr_path> specify node to start \"from\"\n"
		"   -n <hops> Number of hops to include away from specified node\n"
		"   -t <timeout_ms> timeout for any single fabric query\n"
		"   -s show errors\n"
		"   -C <ca_name> use selected Channel Adaptor name for queries\n"
		"   -P <ca_port> use selected channel adaptor port for queries\n"
		"   --debug print debug messages\n", argv0);
	exit(-1);
}

int main(int argc, char **argv)
{
	struct ibnd_config config = { 0 };
	int rc = 0;
	char *ca = NULL;
	int ca_port = 0;
	ibnd_fabric_t *fabric = NULL;
	char *from = NULL;
	ib_portid_t port_id;
	int iters = -1;

	static char const str_opts[] = "S:D:n:C:P:t:shuf:i:";
	static const struct option long_opts[] = {
		{"S", 1, NULL, 'S'},
		{"D", 1, NULL, 'D'},
		{"num-hops", 1, NULL, 'n'},
		{"ca-name", 1, NULL, 'C'},
		{"ca-port", 1, NULL, 'P'},
		{"timeout", 1, NULL, 't'},
		{"show", 0, NULL, 's'},
		{"help", 0, NULL, 'h'},
		{"usage", 0, NULL, 'u'},
		{"debug", 0, NULL, 2},
		{"from", 1, NULL, 'f'},
		{"iters", 1, NULL, 'i'},
		{}
	};

	f = stdout;

	argv0 = argv[0];

	while (1) {
		int ch = getopt_long(argc, argv, str_opts, long_opts, NULL);
		if (ch == -1)
			break;
		switch (ch) {
		case 2:
			config.debug++;
			break;
		case 'f':
			from = strdup(optarg);
			break;
		case 'C':
			ca = strdup(optarg);
			break;
		case 'P':
			ca_port = strtoul(optarg, NULL, 0);
			break;
		case 'n':
			config.max_hops = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			iters = (int)strtol(optarg, NULL, 0);
			break;
		case 't':
			config.timeout_ms = strtoul(optarg, NULL, 0);
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	while (iters == -1 || iters-- > 0) {
		if (from) {
			/* only scan part of the fabric */
			str2drpath(&(port_id.drpath), from, 0, 0);
			if ((fabric = ibnd_discover_fabric(ca, ca_port,
							   &port_id, &config))
			    == NULL) {
				fprintf(stderr, "discover failed\n");
				rc = 1;
				goto close_port;
			}
		} else if ((fabric = ibnd_discover_fabric(ca, ca_port, NULL,
							  &config)) == NULL) {
			fprintf(stderr, "discover failed\n");
			rc = 1;
			goto close_port;
		}

		ibnd_destroy_fabric(fabric);
	}

close_port:
	exit(rc);
}
