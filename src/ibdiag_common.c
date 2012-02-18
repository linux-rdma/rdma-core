/*
 * Copyright (c) 2006-2007 The Regents of the University of California.
 * Copyright (c) 2004-2009 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2002-2010 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 1996-2003 Intel Corporation. All rights reserved.
 * Copyright (c) 2009 HNR Consulting. All rights reserved.
 * Copyright (c) 2011 Lawrence Livermore National Security. All rights reserved.
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
#include <limits.h>
#include <sys/stat.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>
#include <ibdiag_common.h>
#include <ibdiag_version.h>

int ibverbose;
enum MAD_DEST ibd_dest_type = IB_DEST_LID;
ib_portid_t *ibd_sm_id;
static ib_portid_t sm_portid = { 0 };

/* general config options */
#define IBDIAG_CONFIG_GENERAL IBDIAG_CONFIG_PATH"/ibdiag.conf"
char *ibd_ca = NULL;
int ibd_ca_port = 0;
int ibd_timeout = 0;
uint32_t ibd_ibnetdisc_flags = IBND_CONFIG_MLX_EPI;

static const char *prog_name;
static const char *prog_args;
static const char **prog_examples;
static struct option *long_opts;
static const struct ibdiag_opt *opts_map[256];

const static char *get_build_version(void)
{
	return "BUILD VERSION: " IBDIAG_VERSION " Build date: " __DATE__ " "
	    __TIME__;
}

static void pretty_print(int start, int width, const char *str)
{
	int len = width - start;
	const char *p, *e;

	while (1) {
		while (isspace(*str))
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
		fprintf(stderr, "%.*s\n%*s", (int)(e - str), str, start, "");
		str = e;
	}
}

static inline int val_str_true(const char *val_str)
{
	return ((strncmp(val_str, "TRUE", strlen("TRUE")) == 0) ||
		(strncmp(val_str, "true", strlen("true")) == 0));
}

void read_ibdiag_config(const char *file)
{
	char buf[1024];
	FILE *config_fd = NULL;
	char *p_prefix, *p_last;
	char *name;
	char *val_str;
	struct stat statbuf;

	/* silently ignore missing config file */
	if (stat(file, &statbuf))
		return;

	config_fd = fopen(file, "r");
	if (!config_fd)
		return;

	while (fgets(buf, sizeof buf, config_fd) != NULL) {
		p_prefix = strtok_r(buf, "\n", &p_last);
		if (!p_prefix)
			continue; /* ignore blank lines */

		if (*p_prefix == '#')
			continue; /* ignore comment lines */

		name = strtok_r(p_prefix, "=", &p_last);
		val_str = strtok_r(NULL, "\n", &p_last);

		if (strncmp(name, "CA", strlen("CA")) == 0) {
			free(ibd_ca);
			ibd_ca = strdup(val_str);
		} else if (strncmp(name, "Port", strlen("Port")) == 0) {
			ibd_ca_port = strtoul(val_str, NULL, 0);
		} else if (strncmp(name, "timeout", strlen("timeout")) == 0) {
			ibd_timeout = strtoul(val_str, NULL, 0);
		} else if (strncmp(name, "MLX_EPI", strlen("MLX_EPI")) == 0) {
			if (val_str_true(val_str)) {
				ibd_ibnetdisc_flags |= IBND_CONFIG_MLX_EPI;
			} else {
				ibd_ibnetdisc_flags &= ~IBND_CONFIG_MLX_EPI;
			}
		}
	}

	fclose(config_fd);
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
			n += fprintf(stderr, "%*s  ", 24 - n > 0 ? 24 - n : 0,
				     "");
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
	char *endp;
	long val;

	switch (ch) {
	case 'z':
		read_ibdiag_config(optarg);
		break;
	case 'h':
	case 'u':
		ibdiag_show_usage();
		break;
	case 'V':
		fprintf(stderr, "%s %s\n", prog_name, get_build_version());
		exit(0);
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
		errno = 0;
		val = strtol(optarg, &endp, 0);
		if (errno || (endp && *endp != '\0') || val <= 0 ||
		    val > INT_MAX)
			IBERROR("Invalid timeout \"%s\".  Timeout requires a "
				"positive integer value < %d.", optarg, INT_MAX);
		else {
			madrpc_set_timeout((int)val);
			ibd_timeout = (int)val;
		}
		break;
	case 's':
		/* srcport is not required when resolving via IB_DEST_LID */
		if (ib_resolve_portid_str_via(&sm_portid, optarg, IB_DEST_LID,
					      0, NULL) < 0)
			IBERROR("cannot resolve SM destination port %s",
				optarg);
		ibd_sm_id = &sm_portid;
		break;
	default:
		return -1;
	}

	return 0;
}

static const struct ibdiag_opt common_opts[] = {
	{"config", 'z', 1, "<config>", "use config file, default: " IBDIAG_CONFIG_GENERAL},
	{"Ca", 'C', 1, "<ca>", "Ca name to use"},
	{"Port", 'P', 1, "<port>", "Ca port number to use"},
	{"Direct", 'D', 0, NULL, "use Direct address argument"},
	{"Lid", 'L', 0, NULL, "use LID address argument"},
	{"Guid", 'G', 0, NULL, "use GUID address argument"},
	{"timeout", 't', 1, "<ms>", "timeout in ms"},
	{"sm_port", 's', 1, "<lid>", "SM port lid"},
	{"errors", 'e', 0, NULL, "show send and receive errors"},
	{"verbose", 'v', 0, NULL, "increase verbosity level"},
	{"debug", 'd', 0, NULL, "raise debug level"},
	{"usage", 'u', 0, NULL, "usage message"},
	{"help", 'h', 0, NULL, "help message"},
	{"version", 'V', 0, NULL, "show version"},
	{0}
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

	long_opts = malloc((sizeof(common_opts) / sizeof(common_opts[0]) + n) *
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
	unsigned i, n = 0;

	for (n = 0; o->name && n + 2 + o->has_arg < size; o++) {
		p[n++] = (char)o->val;
		for (i = 0; i < (unsigned)o->has_arg; i++)
			p[n++] = ':';
	}
	p[n] = '\0';
}

int ibdiag_process_opts(int argc, char *const argv[], void *cxt,
			const char *exclude_common_str,
			const struct ibdiag_opt custom_opts[],
			int (*custom_handler) (void *cxt, int val,
					       char *optarg),
			const char *usage_args, const char *usage_examples[])
{
	char str_opts[1024];
	const struct ibdiag_opt *o;

	prog_name = argv[0];
	prog_args = usage_args;
	prog_examples = usage_examples;

	long_opts = make_long_opts(exclude_common_str, custom_opts, opts_map);
	if (!long_opts)
		return -1;

	read_ibdiag_config(IBDIAG_CONFIG_GENERAL);

	make_str_opts(long_opts, str_opts, sizeof(str_opts));

	while (1) {
		int ch = getopt_long(argc, argv, str_opts, long_opts, NULL);
		if (ch == -1)
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

char *
conv_cnt_human_readable(uint64_t val64, float *val, int data)
{
	uint64_t tmp = val64;
	int ui = 0;
	int div = 1;

	tmp /= 1024;
	while (tmp) {
		ui++;
		tmp /= 1024;
		div *= 1024;
	}

	*val = (float)(val64);
	if (data) {
		*val *= 4;
		if (*val/div > 1024) {
			ui++;
			div *= 1024;
		}
	}
	*val /= div;

	if (data) {
		switch (ui) {
			case 0:
				return ("B");
			case 1:
				return ("KB");
			case 2:
				return ("MB");
			case 3:
				return ("GB");
			case 4:
				return ("TB");
			case 5:
				return ("PB");
			case 6:
				return ("EB");
			default:
				return ("");
		}
	} else {
		switch (ui) {
			case 0:
				return ("");
			case 1:
				return ("K");
			case 2:
				return ("M");
			case 3:
				return ("G");
			case 4:
				return ("T");
			case 5:
				return ("P");
			case 6:
				return ("E");
			default:
				return ("");
		}
	}
	return ("");
}

int is_mlnx_ext_port_info_supported(uint32_t devid)
{
	if (ibd_ibnetdisc_flags & IBND_CONFIG_MLX_EPI) {
		if (devid == 0xc738)
			return 1;
		if (devid >= 0x1003 && devid <= 0x1010)
			return 1;
	}
	return 0;
}

/* define a common SA query structure
 * This is by no means optimal but it moves the saquery functionality out of
 * the saquery tool and provides it to other utilities.
 */
bind_handle_t sa_get_bind_handle(void)
{
	struct ibmad_port * srcport;
	bind_handle_t handle;
	int mgmt_classes[2] = { IB_SMI_CLASS, IB_SMI_DIRECT_CLASS };

	srcport = mad_rpc_open_port(ibd_ca, ibd_ca_port, mgmt_classes, 2);
	if (!srcport) {
		IBWARN("Failed to open '%s' port '%d'", ibd_ca, ibd_ca_port);
		return (NULL);
	}

	handle = calloc(1, sizeof(*handle));
	if (!handle)
		IBPANIC("calloc failed");

	ib_resolve_smlid_via(&handle->dport, ibd_timeout, srcport);
	if (!handle->dport.lid) {
		IBWARN("No SM found.");
		free(handle);
		return (NULL);
	}

	handle->dport.qp = 1;
	if (!handle->dport.qkey)
		handle->dport.qkey = IB_DEFAULT_QP1_QKEY;

	handle->srcport = srcport;
	handle->fd = mad_rpc_portid(srcport);
	handle->agent = umad_register(handle->fd, IB_SA_CLASS, 2, 1, NULL);

	return handle;
}

void sa_free_bind_handle(bind_handle_t h)
{
	umad_unregister(h->fd, h->agent);
	mad_rpc_close_port(h->srcport);
	free(h);
}

int sa_query(bind_handle_t h, uint8_t method,
		    uint16_t attr, uint32_t mod, uint64_t comp_mask,
		    uint64_t sm_key, void *data, struct sa_query_result *result)
{
	ib_rpc_t rpc;
	void *umad, *mad;
	int ret, offset, len = 256;

	memset(&rpc, 0, sizeof(rpc));
	rpc.mgtclass = IB_SA_CLASS;
	rpc.method = method;
	rpc.attr.id = attr;
	rpc.attr.mod = mod;
	rpc.mask = comp_mask;
	rpc.datasz = IB_SA_DATA_SIZE;
	rpc.dataoffs = IB_SA_DATA_OFFS;

	umad = calloc(1, len + umad_size());
	if (!umad)
		IBPANIC("cannot alloc mem for umad: %s\n", strerror(errno));

	mad_build_pkt(umad, &rpc, &h->dport, NULL, data);

	mad_set_field64(umad_get_mad(umad), 0, IB_SA_MKEY_F, sm_key);

	if (ibdebug > 1)
		xdump(stdout, "SA Request:\n", umad_get_mad(umad), len);

	ret = umad_send(h->fd, h->agent, umad, len, ibd_timeout, 0);
	if (ret < 0) {
		IBWARN("umad_send failed: attr %u: %s\n",
			attr, strerror(errno));
		free(umad);
		return (-ret);
	}

recv_mad:
	ret = umad_recv(h->fd, umad, &len, ibd_timeout);
	if (ret < 0) {
		if (errno == ENOSPC) {
			umad = realloc(umad, umad_size() + len);
			goto recv_mad;
		}
		IBWARN("umad_recv failed: attr 0x%x: %s\n", attr,
			strerror(errno));
		free(umad);
		return (-ret);
	}

	if ((ret = umad_status(umad)))
		return ret;

	mad = umad_get_mad(umad);

	if (ibdebug > 1)
		xdump(stdout, "SA Response:\n", mad, len);

	method = (uint8_t) mad_get_field(mad, 0, IB_MAD_METHOD_F);
	offset = mad_get_field(mad, 0, IB_SA_ATTROFFS_F);
	result->status = mad_get_field(mad, 0, IB_MAD_STATUS_F);
	result->p_result_madw = mad;
	if (result->status != IB_SA_MAD_STATUS_SUCCESS)
		result->result_cnt = 0;
	else if (method != IB_MAD_METHOD_GET_TABLE)
		result->result_cnt = 1;
	else if (!offset)
		result->result_cnt = 0;
	else
		result->result_cnt = (len - IB_SA_DATA_OFFS) / (offset << 3);

	return 0;
}

void sa_free_result_mad(struct sa_query_result *result)
{
	if (result->p_result_madw) {
		free((uint8_t *) result->p_result_madw - umad_size());
		result->p_result_madw = NULL;
	}
}

void *sa_get_query_rec(void *mad, unsigned i)
{
	int offset = mad_get_field(mad, 0, IB_SA_ATTROFFS_F);
	return (uint8_t *) mad + IB_SA_DATA_OFFS + i * (offset << 3);
}

static const char *ib_sa_error_str[] = {
	"SA_NO_ERROR",
	"SA_ERR_NO_RESOURCES",
	"SA_ERR_REQ_INVALID",
	"SA_ERR_NO_RECORDS",
	"SA_ERR_TOO_MANY_RECORDS",
	"SA_ERR_REQ_INVALID_GID",
	"SA_ERR_REQ_INSUFFICIENT_COMPONENTS",
	"SA_ERR_REQ_DENIED",
	"SA_ERR_STATUS_PRIO_SUGGESTED",
	"SA_ERR_UNKNOWN"
};

#define ARR_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define SA_ERR_UNKNOWN (ARR_SIZE(ib_sa_error_str) - 1)

static inline const char *ib_sa_err_str(IN uint8_t status)
{
	if (status > SA_ERR_UNKNOWN)
		status = SA_ERR_UNKNOWN;
	return (ib_sa_error_str[status]);
}

void sa_report_err(int status)
{
	int st = status & 0xff;
	char sm_err_str[64] = { 0 };
	char sa_err_str[64] = { 0 };

	if (st)
		sprintf(sm_err_str, " SM(%s)", ib_get_err_str(st));

	st = status >> 8;
	if (st)
		sprintf(sa_err_str, " SA(%s)", ib_sa_err_str((uint8_t) st));

	fprintf(stderr, "ERROR: Query result returned 0x%04x, %s%s\n",
		status, sm_err_str, sa_err_str);
}

static unsigned int get_max(unsigned int num)
{
	unsigned r = 0;		// r will be lg(num)

	while (num >>= 1)	// unroll for more speed...
		r++;

	return (1 << r);
}

void get_max_msg(char *width_msg, char *speed_msg, int msg_size, ibnd_port_t * port)
{
	char buf[64];
	uint32_t max_speed = 0;
	uint32_t cap_mask, rem_cap_mask, fdr10;
	uint8_t *info;

	uint32_t max_width = get_max(mad_get_field(port->info, 0,
						   IB_PORT_LINK_WIDTH_SUPPORTED_F)
				     & mad_get_field(port->remoteport->info, 0,
						     IB_PORT_LINK_WIDTH_SUPPORTED_F));
	if ((max_width & mad_get_field(port->info, 0,
				       IB_PORT_LINK_WIDTH_ACTIVE_F)) == 0)
		// we are not at the max supported width
		// print what we could be at.
		snprintf(width_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F,
				      buf, 64, &max_width));

	if (port->node->type == IB_NODE_SWITCH)
		info = (uint8_t *)&port->node->ports[0]->info;
	else
		info = (uint8_t *)&port->info;
	cap_mask = mad_get_field(info, 0, IB_PORT_CAPMASK_F);

	if (port->remoteport->node->type == IB_NODE_SWITCH)
		info = (uint8_t *)&port->remoteport->node->ports[0]->info;
	else
		info = (uint8_t *)&port->remoteport->info;
	rem_cap_mask = mad_get_field(info, 0, IB_PORT_CAPMASK_F);
	if (cap_mask & CL_NTOH32(IB_PORT_CAP_HAS_EXT_SPEEDS) &&
	    rem_cap_mask & CL_NTOH32(IB_PORT_CAP_HAS_EXT_SPEEDS))
		goto check_ext_speed;
check_fdr10_supp:
	fdr10 = (mad_get_field(port->ext_info, 0,
			       IB_MLNX_EXT_PORT_LINK_SPEED_SUPPORTED_F) & FDR10)
		&& (mad_get_field(port->remoteport->ext_info, 0,
				  IB_MLNX_EXT_PORT_LINK_SPEED_SUPPORTED_F) & FDR10);
	if (fdr10)
		goto check_fdr10_active;

	max_speed = get_max(mad_get_field(port->info, 0,
					  IB_PORT_LINK_SPEED_SUPPORTED_F)
			    & mad_get_field(port->remoteport->info, 0,
					    IB_PORT_LINK_SPEED_SUPPORTED_F));
	if ((max_speed & mad_get_field(port->info, 0,
				       IB_PORT_LINK_SPEED_ACTIVE_F)) == 0)
		// we are not at the max supported speed
		// print what we could be at.
		snprintf(speed_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F,
				      buf, 64, &max_speed));
	return;

check_ext_speed:
	if (mad_get_field(port->info, 0,
			  IB_PORT_LINK_SPEED_EXT_SUPPORTED_F) == 0 ||
	    mad_get_field(port->remoteport->info, 0,
			  IB_PORT_LINK_SPEED_EXT_SUPPORTED_F) == 0)
		goto check_fdr10_supp;
	max_speed = get_max(mad_get_field(port->info, 0,
					  IB_PORT_LINK_SPEED_EXT_SUPPORTED_F)
			    & mad_get_field(port->remoteport->info, 0,
					    IB_PORT_LINK_SPEED_EXT_SUPPORTED_F));
	if ((max_speed & mad_get_field(port->info, 0,
				       IB_PORT_LINK_SPEED_EXT_ACTIVE_F)) == 0)
		// we are not at the max supported extended speed
		// print what we could be at.
		snprintf(speed_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_SPEED_EXT_ACTIVE_F,
				      buf, 64, &max_speed));
	return;

check_fdr10_active:
	if ((mad_get_field(port->ext_info, 0,
			   IB_MLNX_EXT_PORT_LINK_SPEED_ACTIVE_F) & FDR10) == 0)
		snprintf(speed_msg, msg_size, "Could be FDR10");
}
