// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

/*
 * Print Cassini telemetry, one "name value@seconds.nanoseconds" per line,
 * the format the telemetry sysfs files used to have.
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <infiniband/verbs.h>
#include <infiniband/cxidv_telem.h>

static const char *const set_names[] = {
	[CXIDV_TELEM_SET_ETHTOOL] = "ethtool", [CXIDV_TELEM_SET_ATU] = "atu",
	[CXIDV_TELEM_SET_CQ] = "cq",	       [CXIDV_TELEM_SET_EE] = "ee",
	[CXIDV_TELEM_SET_HNI] = "hni",	       [CXIDV_TELEM_SET_IXE] = "ixe",
	[CXIDV_TELEM_SET_LPE] = "lpe",	       [CXIDV_TELEM_SET_MB] = "mb",
	[CXIDV_TELEM_SET_MST] = "mst",	       [CXIDV_TELEM_SET_OXE] = "oxe",
	[CXIDV_TELEM_SET_PARBS] = "parbs",     [CXIDV_TELEM_SET_PCT] = "pct",
	[CXIDV_TELEM_SET_PI] = "pi",
	[CXIDV_TELEM_SET_RMU] = "rmu",         [CXIDV_TELEM_SET_TOU] = "tou",
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-d DEVICE] [-a | -s SET | -i NAME[,NAME...]] [-l]\n"
		"  -a  all items defined on the device (default)\n"
		"  -s  a predefined set: ethtool, atu, cq, ee, hni, ixe, lpe, mb,\n"
		"      mst, oxe, parbs, pct, pi, rmu, tou\n"
		"  -i  the named items\n"
		"  -l  list item names without reading them\n",
		prog);
}

int main(int argc, char **argv)
{
	const char *devname = NULL, *setname = NULL, *names = NULL;
	struct ibv_counters_init_attr init_attr = {};
	struct ibv_device **list = NULL, *dev = NULL;
	const uint64_t *set_items = NULL;
	uint64_t *items = NULL, *values = NULL, *stamps = NULL;
	struct ibv_counters *counters = NULL;
	struct ibv_context *ctx = NULL;
	uint32_t count = 0, i;
	bool all = true, list_only = false, items_allocated = false;
	int opt, ret, exit_code = 1;

	while ((opt = getopt(argc, argv, "d:as:i:lh")) != -1) {
		switch (opt) {
		case 'd':
			devname = optarg;
			break;
		case 'a':
			all = true;
			break;
		case 's':
			setname = optarg;
			all = false;
			break;
		case 'i':
			names = optarg;
			all = false;
			break;
		case 'l':
			list_only = true;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (list_only) {
		for (i = 1; i < CXIDV_TELEM_COUNT; i++)
			printf("%s\n", cxidv_telem_name(i));
		return 0;
	}

	list = ibv_get_device_list(NULL);
	if (!list) {
		perror("ibv_get_device_list");
		goto out;
	}
	for (i = 0; list && list[i]; i++) {
		if (list[i]->transport_type != IBV_TRANSPORT_SLINGSHOT)
			continue;
		if (!devname || !strcmp(devname, ibv_get_device_name(list[i]))) {
			dev = list[i];
			break;
		}
	}
	if (!dev) {
		fprintf(stderr, "no Slingshot device found\n");
		goto out;
	}
	ctx = ibv_open_device(dev);
	if (!ctx) {
		perror("ibv_open_device");
		goto out;
	}
	ibv_free_device_list(list);
	list = NULL;
	counters = ibv_create_counters(ctx, &init_attr);
	if (!counters) {
		perror("ibv_create_counters");
		goto out;
	}

	if (setname) {
		for (i = 0; i < CXIDV_TELEM_SET_COUNT; i++)
			if (set_names[i] && !strcmp(set_names[i], setname))
				break;
		if (i == CXIDV_TELEM_SET_COUNT || cxidv_telem_get_set(i, &set_items, &count)) {
			fprintf(stderr, "unknown set %s\n", setname);
			goto out;
		}
		items = (uint64_t *)set_items;
	} else if (names) {
		char *copy = strdup(names), *tok, *save = NULL;
		int item;

		if (!copy) {
			perror("strdup");
			goto out;
		}
		items = calloc(strlen(names) + 1, sizeof(*items));
		if (!items) {
			perror("calloc");
			free(copy);
			goto out;
		}
		items_allocated = true;
		for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
			item = cxidv_telem_lookup(tok);
			if (item < 0) {
				fprintf(stderr, "unknown item %s\n", tok);
				free(copy);
				goto out;
			}
			items[count++] = item;
		}
		free(copy);
		if (!count) {
			fprintf(stderr, "no telemetry items selected\n");
			goto out;
		}
	} else if (all) {
		count = CXIDV_TELEM_COUNT;
	}

	if (!count) {
		fprintf(stderr, "no telemetry items selected\n");
		goto out;
	}
	values = calloc(count, sizeof(*values));
	stamps = calloc(count, sizeof(*stamps));
	if (!values || !stamps) {
		perror("calloc");
		goto out;
	}

	ret = ibv_read_counters_ex(counters, items, values, stamps, count, 0);
	if (ret) {
		fprintf(stderr, "ibv_read_counters_ex: %s\n", strerror(ret));
		goto out;
	}

	for (i = 0; i < count; i++) {
		uint32_t item = items ? items[i] : i;

		/* A zero timestamp marks an item this device doesn't have. */
		if (!stamps[i])
			continue;
		printf("%s %llu@%llu.%09llu\n", cxidv_telem_name(item),
		       (unsigned long long)values[i],
		       (unsigned long long)(stamps[i] / 1000000000ULL),
		       (unsigned long long)(stamps[i] % 1000000000ULL));
	}

	exit_code = 0;
out:
	free(stamps);
	free(values);
	if (items_allocated)
		free(items);
	if (counters)
		ibv_destroy_counters(counters);
	if (ctx)
		ibv_close_device(ctx);
	if (list)
		ibv_free_device_list(list);
	return exit_code;
}
