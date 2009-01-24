/*
 * Copyright (c) 2006-2007 The Regents of the University of California.
 * Copyright (c) 2004-2006 Voltaire, Inc. All rights reserved.
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

/**
 * Define common functions which can be included in the various C based diags.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <config.h>
#include <getopt.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>
#include <ibdiag_common.h>
#include <ibdiag_version.h>

int ibdebug;
int ibverbose;
char *ibd_ca;
int ibd_ca_port;
int ibd_dest_type = IB_DEST_LID;
ib_portid_t *ibd_sm_id;
int ibd_timeout;

static ib_portid_t sm_portid = {0};

static const char *prog_name;
static const char *prog_args;
static const char **prog_examples;
static struct option *long_opts;
static const struct ibdiag_opt *opts_map[256];

static void pretty_print(int start, int width, const char *str)
{
	int len = width - start;
	const char *p, *e;

	while (1) {
		while(isspace(*str))
			str++;
		p = str;
		do {
			e = p + 1;
			p = strchr(e, ' ');
		} while (p && p - str < len);
		if (!p) {
			fprintf(stderr, "%s", str);
			break;
		}
		if (e - str == 1)
			e = p;
		fprintf(stderr, "%.*s\n%*s", e - str, str, start, "");
		str = e;
	}
}

void ibdiag_show_usage()
{
	struct option *o = long_opts;
	int n;

	fprintf(stderr, "\nUsage: %s [options] %s\n\n", prog_name,
		prog_args ? prog_args : "");

	if (long_opts[0].name)
		fprintf(stderr, "Options:\n");
	for (o = long_opts; o->name; o++) {
		const struct ibdiag_opt *io = opts_map[o->val];
		n = fprintf(stderr, "  --%s", io->name);
		if (isprint(io->letter))
			n += fprintf(stderr, ", -%c", io->letter);
		if (io->has_arg)
			n += fprintf(stderr, " %s",
				     io->arg_tmpl ? io->arg_tmpl : "<val>");
		if (io->description && *io->description) {
			n += fprintf(stderr, "%*s  ", 24 - n > 0 ? 24 - n : 0, "");
			pretty_print(n, 74, io->description);
		}
		fprintf(stderr, "\n");
	}

	if (prog_examples) {
		const char **p;
		fprintf(stderr, "\nExamples:\n");
		for (p = prog_examples; *p && **p; p++)
			fprintf(stderr, "  %s %s\n", prog_name, *p);
	}

	fprintf(stderr, "\n");

	exit(2);
}

static int process_opt(int ch, char *optarg)
{
	int val;

	switch (ch) {
	case 'h':
	case 'u':
		ibdiag_show_usage();
		break;
	case 'V':
		fprintf(stderr, "%s %s\n", prog_name, get_build_version());
		exit(2);
	case 'e':
		madrpc_show_errors(1);
		break;
	case 'v':
		ibverbose++;
		break;
	case 'd':
		ibdebug++;
		madrpc_show_errors(1);
		umad_debug(ibdebug - 1);
		break;
	case 'C':
		ibd_ca = optarg;
		break;
	case 'P':
		ibd_ca_port = strtoul(optarg, 0, 0);
		break;
	case 'D':
		ibd_dest_type = IB_DEST_DRPATH;
		break;
	case 'L':
		ibd_dest_type = IB_DEST_LID;
		break;
	case 'G':
		ibd_dest_type = IB_DEST_GUID;
		break;
	case 't':
		val = strtoul(optarg, 0, 0);
		madrpc_set_timeout(val);
		ibd_timeout = val;
		break;
	case 's':
		if (ib_resolve_portid_str(&sm_portid, optarg, IB_DEST_LID, 0) < 0)
			IBERROR("cannot resolve SM destination port %s", optarg);
		ibd_sm_id = &sm_portid;
		break;
	default:
		return -1;
	}

	return 0;
}

static const struct ibdiag_opt common_opts[] = {
	{ "Ca", 'C', 1, "<ca>", "Ca name to use"},
	{ "Port", 'P', 1, "<port>", "Ca port number to use"},
	{ "Direct", 'D', 0, NULL, "use Direct address argument"},
	{ "Lid", 'L', 0, NULL, "use LID address argument"},
	{ "Guid", 'G', 0, NULL, "use GUID address argument"},
	{ "timeout", 't', 1, "<ms>", "timeout in ms"},
	{ "sm_port", 's', 1, "<lid>", "SM port lid" },
	{ "errors", 'e', 0, NULL, "show send and receive errors" },
	{ "verbose", 'v', 0, NULL, "increase verbosity level" },
	{ "debug", 'd', 0, NULL, "raise debug level" },
	{ "usage", 'u', 0, NULL, "usage message" },
	{ "help", 'h', 0, NULL, "help message" },
	{ "version", 'V', 0, NULL, "show version" },
	{}
};

static void make_opt(struct option *l, const struct ibdiag_opt *o,
		     const struct ibdiag_opt *map[])
{
	l->name = o->name;
	l->has_arg = o->has_arg;
	l->flag = NULL;
	l->val = o->letter;
	if (!map[l->val])
		map[l->val] = o;
}

static struct option *make_long_opts(const char *exclude_str,
				     const struct ibdiag_opt *custom_opts,
				     const struct ibdiag_opt *map[])
{
	struct option *long_opts, *l;
	const struct ibdiag_opt *o;
	unsigned n = 0;

	if (custom_opts)
		for (o = custom_opts; o->name; o++)
			n++;

	long_opts = malloc((sizeof(common_opts)/sizeof(common_opts[0]) + n) *
			   sizeof(*long_opts));
	if (!long_opts)
		return NULL;

	l = long_opts;

	if (custom_opts)
		for (o = custom_opts; o->name; o++)
			make_opt(l++, o, map);

	for (o = common_opts; o->name; o++) {
		if (exclude_str && strchr(exclude_str, o->letter))
			continue;
		make_opt(l++, o, map);
	}

	memset(l, 0, sizeof(*l));

	return long_opts;
}

static void make_str_opts(const struct option *o, char *p, unsigned size)
{
	int i, n = 0;

	for (n = 0; o->name  && n + 2 + o->has_arg < size; o++) {
		p[n++] = o->val;
		for (i = 0; i < o->has_arg; i++)
			p[n++] = ':';
	}
	p[n] = '\0';
}

int ibdiag_process_opts(int argc, char * const argv[], void *cxt,
			const char *exclude_common_str,
			const struct ibdiag_opt custom_opts[],
			int (*custom_handler)(void *cxt, int val, char *optarg),
			const char *usage_args, const char *usage_examples[])
{
	char str_opts[1024];
	const struct ibdiag_opt *o;

	memset(opts_map, 0, sizeof(opts_map));

	prog_name = argv[0];
	prog_args = usage_args;
	prog_examples = usage_examples;

	long_opts = make_long_opts(exclude_common_str, custom_opts, opts_map);
	if (!long_opts)
		return -1;

	make_str_opts(long_opts, str_opts, sizeof(str_opts));

	while (1) {
		int ch = getopt_long(argc, argv, str_opts, long_opts, NULL);
		if ( ch == -1 )
			break;
		o = opts_map[ch];
		if (!o)
			ibdiag_show_usage();
		if (custom_handler) {
			if (custom_handler(cxt, ch, optarg) &&
			    process_opt(ch, optarg))
				ibdiag_show_usage();
		} else if (process_opt(ch, optarg))
			ibdiag_show_usage();
	}

	free(long_opts);

	return 0;
}

void iberror(const char *fn, char *msg, ...)
{
	char buf[512];
	va_list va;
	int n;

	va_start(va, msg);
	n = vsprintf(buf, msg, va);
	va_end(va);
	buf[n] = 0;

	if (ibdebug)
		printf("%s: iberror: [pid %d] %s: failed: %s\n",
		       prog_name ? prog_name : "", getpid(), fn, buf);
	else
		printf("%s: iberror: failed: %s\n",
		       prog_name ? prog_name : "", buf);

	exit(-1);
}

const char *get_build_version(void)
{
	return "BUILD VERSION: " IBDIAG_VERSION " Build date: " __DATE__ " " __TIME__;
}
