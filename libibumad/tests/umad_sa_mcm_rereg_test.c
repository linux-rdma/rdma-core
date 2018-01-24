/*
 * Copyright (c) 2017 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2006-2009 Voltaire, Inc. All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

#include <infiniband/umad.h>
#include <infiniband/umad_sa_mcm.h>

#define info(fmt, ...) fprintf(stderr, "INFO: " fmt, ## __VA_ARGS__)
#define err(fmt, ...) fprintf(stderr, "ERR: " fmt, ## __VA_ARGS__)
#ifdef NOISY_DEBUG
#define dbg(fmt, ...) fprintf(stderr, "DBG: " fmt, ## __VA_ARGS__)
#else
#define dbg(fmt, ...) {}
#endif

#define DEFAULT_TIMEOUT 100		/* milliseconds */
#define MAX_PORT_GUIDS 64

/* Use null MGID to request SA assigned MGID */
static const uint8_t null_mgid[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static int create, join, leave;
static uint8_t rate = 0xff, mtu = 0xff, sl = 0xff;
static umad_port_t umad_port;

struct guid_trid {
	uint8_t gid[16];
	__be64 guid;
	uint64_t trid[2];
};

static void build_user_mad_addr(uint8_t *umad)
{
	umad_set_addr(umad, umad_port.sm_lid, 1, umad_port.sm_sl, UMAD_QKEY);

	/*
	 * The following 2 umad calls are redundant
	 * as umad was originally cleared to
	 */
	umad_set_grh(umad, NULL);
	umad_set_pkey(umad, 0);		/* just pkey index 0 for now !!! */
}

static void build_mcm_rec(struct umad_sa_packet *sa, uint8_t method,
			  const uint8_t mgid[], const uint8_t port_gid[],
			  uint64_t tid, int creat)
{
	struct umad_sa_mcmember_record *mcm;

	memset(sa, 0, sizeof(*sa));

	sa->mad_hdr.base_version = UMAD_BASE_VERSION;
	sa->mad_hdr.mgmt_class = UMAD_CLASS_SUBN_ADM;
	sa->mad_hdr.class_version = UMAD_SA_CLASS_VERSION;
	sa->mad_hdr.method = method;
	sa->mad_hdr.tid = htobe64(tid);
	sa->mad_hdr.attr_id = htons(UMAD_SA_ATTR_MCMEMBER_REC);
	if (creat)
		sa->comp_mask = htobe64(UMAD_SA_MCM_COMP_MASK_MGID |
					UMAD_SA_MCM_COMP_MASK_PORT_GID |
					UMAD_SA_MCM_COMP_MASK_QKEY |
					UMAD_SA_MCM_COMP_MASK_TCLASS |
					UMAD_SA_MCM_COMP_MASK_PKEY |
					UMAD_SA_MCM_COMP_MASK_SL |
					UMAD_SA_MCM_COMP_MASK_FLOW_LABEL |
					UMAD_SA_MCM_COMP_MASK_JOIN_STATE);
	else
		sa->comp_mask = htobe64(UMAD_SA_MCM_COMP_MASK_MGID |
					UMAD_SA_MCM_COMP_MASK_PORT_GID |
					UMAD_SA_MCM_COMP_MASK_JOIN_STATE);

	mcm = (struct umad_sa_mcmember_record *) sa->data;
	memcpy(mcm->mgid, mgid, sizeof(mcm->mgid));
	memcpy(mcm->portgid, port_gid, sizeof(mcm->portgid));
	umad_sa_mcm_set_join_state(mcm, UMAD_SA_MCM_JOIN_STATE_FULL_MEMBER);
	if (creat) {
		mcm->qkey = htonl(0xb1b);
		/* assume full default partition (in index 0) */
		mcm->pkey = htons(0xffff);
		if (rate != 0xff) {
			sa->comp_mask |=
				htobe64(UMAD_SA_MCM_COMP_MASK_RATE_SEL |
					UMAD_SA_MCM_COMP_MASK_RATE);
			mcm->rate = (UMAD_SA_SELECTOR_EXACTLY <<
				     UMAD_SA_SELECTOR_SHIFT) |
				    (rate & UMAD_SA_RATE_MTU_PKT_LIFE_MASK);
		}
		if (mtu != 0xff) {
			sa->comp_mask |= htobe64(UMAD_SA_MCM_COMP_MASK_MTU_SEL |
						 UMAD_SA_MCM_COMP_MASK_MTU);
			mcm->mtu = (UMAD_SA_SELECTOR_EXACTLY <<
				    UMAD_SA_SELECTOR_SHIFT) |
				   (mtu & UMAD_SA_RATE_MTU_PKT_LIFE_MASK);
		}
		if (sl != 0xff) {
			sa->comp_mask |= htobe64(UMAD_SA_MCM_COMP_MASK_SL);
			mcm->sl_flow_hop =
				umad_sa_mcm_set_sl_flow_hop(sl, 0, 0);
		}
	}
}

static int mcm_send(int portid, int agentid, uint8_t *umad, int len, int tmo,
		    uint8_t method, const uint8_t mgid[],
		    struct guid_trid *entry, int creat)
{
	struct umad_sa_packet *sa = umad_get_mad(umad);

	build_mcm_rec(sa, method, mgid, entry->gid, entry->trid[0], creat);
	if (umad_send(portid, agentid, umad, len, tmo, 0) < 0) {
		err("umad_send %s failed: %s\n",
		    (method == UMAD_METHOD_GET) ? "query" : "non query",
		    strerror(errno));
		return -1;
	}
	dbg("umad_send %d: tid = 0x%" PRIx64 "\n", method,
	    be64toh(sa->mad_hdr.tid));

	return 0;
}

static int rereg_port_gid(int portid, int agentid,
			  uint8_t *umad, int len, int tmo,
			  const uint8_t mgid[], struct guid_trid *entry)
{
	struct umad_sa_packet *sa = umad_get_mad(umad);

	build_mcm_rec(sa, UMAD_SA_METHOD_DELETE, mgid,
		      entry->gid, entry->trid[0], 0);
	if (umad_send(portid, agentid, umad, len, tmo, 0) < 0) {
		err("umad_send leave failed: %s\n", strerror(errno));
		return -1;
	}
	dbg("umad_send leave: tid = 0x%" PRIx64 "\n", be64toh(sa->mad_hdr.tid));
	entry->trid[0] = be64toh(sa->mad_hdr.tid);	/* for agent ID */

	sa->mad_hdr.method = UMAD_METHOD_SET;
	sa->mad_hdr.tid = htobe64(entry->trid[1]);
	if (umad_send(portid, agentid, umad, len, tmo, 0) < 0) {
		err("umad_send join failed: %s\n", strerror(errno));
		return -1;
	}
	dbg("umad_send join: tid = 0x%" PRIx64 "\n", be64toh(sa->mad_hdr.tid));
	entry->trid[1] = be64toh(sa->mad_hdr.tid);	/* for agent ID */

	return 0;
}

static int rereg_send_all(int portid, int agentid, int tmo,
			  const uint8_t mgid[], struct guid_trid *list,
			  unsigned int cnt)
{
	uint8_t *umad;
	int len = sizeof(struct umad_hdr) + UMAD_LEN_DATA;
	unsigned int i, sent = 0;
	int ret;

	info("%s... cnt = %u\n", __func__, cnt);

	umad = calloc(1, len + umad_size());
	if (!umad) {
		err("cannot alloc mem for umad: %s\n", strerror(errno));
		return -1;
	}
	build_user_mad_addr(umad);

	for (i = 0; i < cnt; i++) {
		ret = rereg_port_gid(portid, agentid, umad, len, tmo,
				     mgid, &list[i]);
		if (ret < 0) {
			err("%s: rereg_port_gid guid 0x%016" PRIx64
			    " failed\n", __func__, be64toh(list[i].guid));
			continue;
		}
		sent++;
	}

	info("%s: sent %u of %u requests\n", __func__, sent * 2, cnt * 2);

	free(umad);

	return 0;
}

static int mcm_recv(int portid, uint8_t *umad, int length, int tmo)
{
	int ret, retry = 0;
	int len = length;
#ifdef NOISY_DEBUG
	struct umad_hdr *mad;
#endif

	while ((ret = umad_recv(portid, umad, &len, tmo)) < 0 &&
	       errno == ETIMEDOUT) {
		if (retry++ > 3)
			return 0;
	}
	if (ret < 0) {
		err("umad_recv %d failed: %s\n", ret, strerror(errno));
		return -1;
	}

#ifdef NOISY_DEBUG
	mad = umad_get_mad(umad);
#endif
	dbg("umad_recv (retries %d), tid = 0x%" PRIx64
	    ": len = %d, status = %d\n", retry,
	    be64toh(mad->tid), len, umad_status(umad));

	return 1;
}

static int rereg_recv_all(int portid, int agentid, int tmo,
			  const uint8_t mgid[], struct guid_trid *list,
			  unsigned int cnt)
{
	uint8_t *umad;
	struct umad_hdr *mad;
	int len = sizeof(struct umad_hdr) + UMAD_LEN_DATA;
	uint64_t trid;
	unsigned int n, i, j;
	uint16_t status;
	uint8_t method;

	info("%s...\n", __func__);

	umad = calloc(1, len + umad_size());
	if (!umad) {
		err("cannot alloc mem for umad: %s\n", strerror(errno));
		return -1;
	}
	mad = umad_get_mad(umad);

	n = 0;
	while (mcm_recv(portid, umad, len, tmo) > 0) {
		dbg("%s: done %d\n", __func__, n);
		n++;

		method = mad->method;
		status = ntohs(mad->status);
		trid = be64toh(mad->tid);

		if (status)
			dbg("MAD status 0x%x, method 0x%x\n", status, method);

		if (status &&
		    (method == UMAD_METHOD_GET_RESP ||
		     method == UMAD_SA_METHOD_DELETE_RESP)) {
			for (i = 0; i < cnt; i++)
				for (j = 0; j < 2; j++)
					if (trid == list[i].trid[j])
						break;
			if (i == cnt) {
				err("cannot find trid 0x%" PRIx64
				    ", status 0x%x, method 0x%x\n",
				    trid, status, method);
				continue;
			}
			info("guid 0x%016" PRIx64
			     ": status 0x%x, method 0x%x. Retrying\n",
			     be64toh(list[i].guid), status, method);
			rereg_port_gid(portid, agentid, umad, len, tmo,
				       mgid, &list[i]);
		}
	}

	info("%s: got %u responses\n", __func__, n);

	free(umad);
	return 0;
}

static int query_all(int portid, int agentid, int tmo, uint8_t method,
		     const uint8_t mgid[], struct guid_trid *list,
		     int creat, unsigned int cnt)
{
	uint8_t *umad;
	struct umad_hdr *mad;
	int len = sizeof(struct umad_hdr) + UMAD_LEN_DATA;
	unsigned int i, sent = 0;
	int ret;
	uint16_t status;
	uint8_t mcgid[16];

	info("%s...\n", __func__);

	memcpy(mcgid, mgid, 16);

	umad = calloc(1, len + umad_size());
	if (!umad) {
		err("cannot alloc mem for umad: %s\n", strerror(errno));
		return -1;
	}
	build_user_mad_addr(umad);
	mad = umad_get_mad(umad);

	for (i = 0; i < cnt; i++) {
		ret = mcm_send(portid, agentid, umad, len, tmo,
			       method, mcgid, &list[i], creat);
		if (ret < 0) {
			err("%s: mcm_send failed\n", __func__);
			continue;
		}
		sent++;

		ret = mcm_recv(portid, umad, len, tmo);
		if (ret < 0) {
			err("%s: mcm_recv failed\n", __func__);
			continue;
		}

		status = ntohs(mad->status);
		if (status)
			info(
			    "guid 0x%016" PRIx64 ": status 0x%x, method 0x%x\n",
			    be64toh(list[i].guid), status, mad->method);
		else if (creat && i == 0) {
			if (memcmp(mgid, null_mgid, 16) == 0) {
				struct umad_sa_packet *sa = (void *) mad;
				struct umad_sa_mcmember_record *mcm;

				mcm = (struct umad_sa_mcmember_record *)
					sa->data;
				memcpy(mcgid, mcm->mgid, 16);
			}
		}
	}

	info("%s: %u of %u queried\n", __func__, sent, cnt);

	free(umad);
	return 0;
}

static int test_port(const char *guid_file, int portid, int agentid, int tmo,
		     const uint8_t mgid[])
{
	char line[256];
	FILE *f;
	uint8_t port_gid[16];
	uint64_t guidho;
	__be64 prefix, guid;
	uint64_t trid;
	struct guid_trid *list;
	int i = 0, j;

	list = calloc(MAX_PORT_GUIDS, sizeof(*list));
	if (!list) {
		err("cannot alloc mem for guid/trid list: %s\n",
		    strerror(errno));
		return -1;
	}

	f = fopen(guid_file, "r");
	if (!f) {
		err("cannot open %s: %s\n", guid_file, strerror(errno));
		free(list);
		return -1;
	}

	trid = 0x12345678;	/* starting tid */
	prefix = umad_port.gid_prefix;

	while (fgets(line, sizeof(line), f)) {
		guidho = strtoull(line, NULL, 0);
		guid = htobe64(guidho);
		memcpy(&port_gid[0], &prefix, 8);
		memcpy(&port_gid[8], &guid, 8);

		list[i].guid = guid;
		memcpy(list[i].gid, port_gid, sizeof(list[i].gid));
		for (j = 0; j < 2; j++)
			list[i].trid[j] = trid++;

		if (++i >= MAX_PORT_GUIDS)
			break;
	}
	fclose(f);

	if (create)
		query_all(portid, agentid, tmo, UMAD_METHOD_SET,
			  mgid, list, 1, i);
	else if (join)
		query_all(portid, agentid, tmo, UMAD_METHOD_SET,
			 mgid, list, 0, i);
	else if (leave)
		query_all(portid, agentid, tmo, UMAD_SA_METHOD_DELETE,
			  mgid, list, 0, i);
	else {
		/* no operation specified - default to rereg */
		rereg_send_all(portid, agentid, tmo, mgid, list, i);
		rereg_recv_all(portid, agentid, tmo, mgid, list, i);

		query_all(portid, agentid, tmo, UMAD_METHOD_GET,
			  mgid, list, 0, i);
	}

	free(list);
	return 0;
}

static void show_usage(const char *prog_name)
{
	fprintf(stderr,
		"%s [-C <ca_name>] [-P <ca_port>] [-F <port_guid_file>] [-t <timeout_ms>] [-g <mgid>] [-c] [-j] [-l] [-r <rate>] [-m <mtu>] [-s <sl>] [-h]\n",
		prog_name);
	fprintf(stderr,
		"	-C <ca_name>	use the specified ca_name\n");
	fprintf(stderr,
		"	-P <ca_port>	use the specific ca_port\n");
	fprintf(stderr,
		"	-F <port_guid_file>	use the specified port_guid_file\n");
	fprintf(stderr,
		"				defaults to port_guids.lst\n");
	fprintf(stderr,
		"	-t <timeout_ms>	override the default timeout of 100 milliseconds\n");
	fprintf(stderr,
		"	-g <mgid>	MGID of MC group in IPv6 format\n");
	fprintf(stderr,
		"			defaults to IPv4 broadcast group if not specified\n");
	fprintf(stderr,
		"			To create SA assigned group, use either :: or 0:0:0:0:0:0:0:0\n");
	fprintf(stderr, "	-c		create MC group with ports\n");
	fprintf(stderr, "	-j		join ports to MC group\n");
	fprintf(stderr,
		"	-l		remove ports from MC group (leave)\n");
	fprintf(stderr,
		"	operation defaults to reregister ports if none if c, j, l are specified\n\n");
	fprintf(stderr,
		"	-r <rate>	Encoded rate value (for create)\n");
	fprintf(stderr,
		"	-m <mtu>	Encoded mtu value (for create)\n");
	fprintf(stderr, "	-s <sl>		SL (for create)\n");
	fprintf(stderr, "	-h		show this usage message\n");
}

int main(int argc, char **argv)
{
	char *ibd_ca = NULL;
	int ibd_ca_port = 0;
	const char *guid_file = "port_guids.list";
	int tmo = DEFAULT_TIMEOUT;
	int c, portid, agentid;
	const char *prog_name;
	const char *const optstring = "F:C:P:t:g:cjlr:m:s:h";
	/* IPoIB broadcast group (for full default pkey) */
	uint8_t mgid[16] = {
		0xff, 0x12, 0x40, 0x1b, 0xff, 0xff, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
	};

	prog_name = argv[0];
	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'C':
			ibd_ca = optarg;
			break;
		case 'P':
			ibd_ca_port = strtoul(optarg, NULL, 0);
			break;
		case 'F':
			guid_file = optarg;
			break;
		case 't':
			tmo = atoi(optarg);
			break;
		case 'g':
			if (inet_pton(AF_INET6, optarg, &mgid) <= 0) {
				fprintf(stderr, "mgid could not be parsed\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'c':
			create = 1;
			break;
		case 'j':
			join = 1;
			break;
		case 'l':
			leave = 1;
			break;
		case 'r':
			rate = atoi(optarg);
			break;
		case 'm':
			mtu = atoi(optarg);
			break;
		case 's':
			sl = atoi(optarg);
			break;
		case 'h':
			show_usage(prog_name);
			exit(EXIT_SUCCESS);
			break;
		default:
			fprintf(stderr, "Unrecognized option: -%c\n", optopt);
			show_usage(prog_name);
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (umad_get_port(ibd_ca, ibd_ca_port, &umad_port) < 0) {
		if (ibd_ca == NULL)
			err(
			   "umad_get_port failed for first IB CA port %d: %s\n",
			   ibd_ca_port, strerror(errno));
		else
			err("umad_get_port failed for CA %s port %d: %s\n",
			    ibd_ca, ibd_ca_port, strerror(errno));
		umad_done();
		return -1;
	}
	info("using %s port %d guid 0x%016" PRIx64 "\n",
	     umad_port.ca_name, umad_port.portnum,
	     be64toh(umad_port.port_guid));

	portid = umad_open_port(umad_port.ca_name, umad_port.portnum);
	if (portid < 0) {
		err("umad_open_port failed: %s\n", strerror(errno));
		umad_release_port(&umad_port);
		umad_done();
		return -1;
	}

	agentid = umad_register(portid, UMAD_CLASS_SUBN_ADM,
				UMAD_SA_CLASS_VERSION, 0, NULL);
	if (agentid < 0) {
		err("umad_register failed: %s\n", strerror(errno));
		umad_release_port(&umad_port);
		umad_close_port(portid);
		umad_done();
		return -1;
	}

	test_port(guid_file, portid, agentid, tmo, mgid);

	umad_release_port(&umad_port);
	umad_unregister(portid, agentid);
	umad_close_port(portid);
	umad_done();

	return 0;
}
