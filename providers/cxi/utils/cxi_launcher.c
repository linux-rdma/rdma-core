// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2026 Hewlett Packard Enterprise Development LP
 */

#define _GNU_SOURCE
#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <infiniband/cxidv.h>
#include <infiniband/verbs.h>
#include <ccan/array_size.h>

#define CXI_MAX_TRAFFIC_CLASS CXIDV_TC_ETH

struct cxirdma_state {
	struct cxidv_job_tc_attr tc_attr;
	uint32_t traffic_class;
	uint32_t allowed_tc_mask;
	uint32_t threads_per_task;
	uint16_t thread_defaults[CXIDV_SVC_RSRC_COUNT];
	bool create_tc;
	bool explicit_tc;
	bool list_tcs;
	bool dry_run;
	bool threads_per_task_set;
	uint32_t svc_id;
	uint32_t max_addr_entries;
	bool owns_svc;
	uint16_t vnis[CXIDV_SVC_MAX_VNIS];
	uint32_t vni_count;
	uid_t uid;
	uint32_t limits_mask;
	uint32_t explicit_reserved_mask;
	uint32_t thread_default_mask;
};

static const struct option cxirdma_options[] = {
	{ "device", required_argument, NULL, 'd' },
	{ "vni", required_argument, NULL, 'j' },
	{ "job-id", required_argument, NULL, 'j' },
	{ "uid", required_argument, NULL, 'u' },
	{ "service", required_argument, NULL, 'S' },
	{ "port", required_argument, NULL, 'i' },
	{ "gid-index", required_argument, NULL, 'g' },
	{ "max-addr-entries", required_argument, NULL, 1002 },
	{ "help", no_argument, NULL, 'h' },
	{ "tc", required_argument, NULL, 1000 },
	{ "create-tc", required_argument, NULL, 1000 },
	{ "allow-tc", required_argument, NULL, 1000 },
	{ "default-ptes", required_argument, NULL, 1000 },
	{ "default-txqs", required_argument, NULL, 1000 },
	{ "default-tgqs", required_argument, NULL, 1000 },
	{ "default-eqs", required_argument, NULL, 1000 },
	{ "default-cts", required_argument, NULL, 1000 },
	{ "default-acs", required_argument, NULL, 1000 },
	{ "default-tles", required_argument, NULL, 1000 },
	{ "default-les", required_argument, NULL, 1000 },
	{ "threads-per-task", required_argument, NULL, 1001 },
	{ "dry-run", no_argument, NULL, 1000 },
	{ "tc-ptes", required_argument, NULL, 1000 },
	{ "tc-txqs", required_argument, NULL, 1000 },
	{ "tc-tgqs", required_argument, NULL, 1000 },
	{ "tc-eqs", required_argument, NULL, 1000 },
	{ "tc-cts", required_argument, NULL, 1000 },
	{ "tc-tles", required_argument, NULL, 1000 },
	{ "tc-les", required_argument, NULL, 1000 },
	{ "tc-acs", required_argument, NULL, 1000 },
	{ "list-tcs", no_argument, NULL, 1000 },
	{}
};

static volatile sig_atomic_t child_group;
static volatile sig_atomic_t interrupted;

static void forward_signal(int number)
{
	int saved_errno = errno;

	interrupted = number;
	if (child_group)
		kill(-(pid_t)child_group, number);
	errno = saved_errno;
}

static int parse_number(const char *text, uint32_t maximum, uint32_t *value)
{
	char *end;
	unsigned long parsed;

	if (!text || !*text)
		return -1;
	errno = 0;
	parsed = strtoul(text, &end, 0);
	if (errno || *end || parsed > maximum || !isdigit((unsigned char)*text))
		return -1;
	*value = parsed;
	return 0;
}

static int parse_limit(const char *arg, struct cxidv_limits *limit, bool *reserved_specified)
{
	unsigned long max, res = 0;
	char *end;
	bool has_reserved = false;

	if (!arg || !*arg || *arg == '-')
		return -1;
	errno = 0;
	max = strtoul(arg, &end, 0);
	if (errno || max > UINT16_MAX)
		return -1;
	if (*end == ':') {
		has_reserved = true;
		arg = end + 1;
		if (!*arg || *arg == '-')
			return -1;
		errno = 0;
		res = strtoul(arg, &end, 0);
		if (errno || res > UINT16_MAX)
			return -1;
	}
	if (*end)
		return -1;

	limit->max = max;
	limit->res = res;
	*reserved_specified = has_reserved;
	return 0;
}

static int parse_tc(const char *arg, const char *option, uint32_t *out)
{
	unsigned long tc;
	char *end;

	if (!arg || !*arg || *arg == '-')
		return -1;
	errno = 0;
	tc = strtoul(arg, &end, 0);
	if (errno || *end || tc > CXI_MAX_TRAFFIC_CLASS) {
		fprintf(stderr, "--%s must be 0..%d\n", option, CXI_MAX_TRAFFIC_CLASS);
		return -1;
	}

	*out = tc;
	return 0;
}

static bool service_allows_vni(const struct cxidv_svc_attr *attr, uint16_t vni)
{
	unsigned int index;

	if (attr->vni_count) {
		if (attr->vni_count > CXIDV_SVC_MAX_VNIS)
			return false;
		for (index = 0; index < attr->vni_count; index++)
			if (attr->vnis[index] == vni)
				return true;
		return false;
	}
	if (attr->is_range)
		return vni >= attr->vnis[0] && vni <= attr->vnis[1];

	return false;
}

static int format_vni_list(const uint16_t *vnis, uint32_t count, char *buffer, size_t capacity)
{
	size_t used = 0;
	uint32_t index;

	for (index = 0; index < count; index++) {
		int length = snprintf(buffer + used, capacity - used, "%s%u", index ? "," : "",
				      vnis[index]);

		if (length < 0 || (size_t)length >= capacity - used)
			return -1;
		used += length;
	}
	return 0;
}

static int list_tcs(struct ibv_context *context)
{
	struct cxidv_tc_entry entries[32];
	uint32_t capacity = ARRAY_SIZE(entries);
	uint32_t count = 0;
	uint32_t shown;
	uint32_t i;
	int ret;

	ret = cxidv_query_tcs(context, entries, capacity, &count);
	if (ret) {
		fprintf(stderr, "couldn't query CXI traffic classes: %s\n", strerror(ret));
		return -1;
	}

	shown = count < capacity ? count : capacity;
	printf("%5s %7s %12s %14s %12s %14s %7s %7s %7s %7s %7s %7s\n", "TC", "TYPE", "RES_REQ",
	       "UNRES_REQ", "RES_RSP", "UNRES_RSP", "REQPCP", "RSPPCP", "OCUSET", "CQTC", "REQBC",
	       "FLAGS");
	for (i = 0; i < shown; i++)
		printf("%5u %7u %12u %14u %12u %14u %7u %7u %7u %7u %7u 0x%05x\n", entries[i].tc,
		       entries[i].tc_type, entries[i].res_req_dscp, entries[i].unres_req_dscp,
		       entries[i].res_rsp_dscp, entries[i].unres_rsp_dscp, entries[i].req_pcp,
		       entries[i].rsp_pcp, entries[i].ocuset, entries[i].cq_tc, entries[i].req_bc,
		       entries[i].flags);
	if (shown < count)
		printf("... %u more entries not shown\n", count - shown);

	return 0;
}

static int validate_tc_mask(struct ibv_context *context, uint32_t mask, bool create_tc)
{
	struct cxidv_tc_entry entries[32];
	uint32_t count = 0;
	uint32_t tc;
	int ret;

	if (create_tc)
		return 0;
	ret = cxidv_query_tcs(context, entries, ARRAY_SIZE(entries), &count);
	if (ret) {
		fprintf(stderr, "couldn't query CXI traffic classes: %s\n", strerror(ret));
		return -1;
	}

	for (tc = 0; tc <= CXI_MAX_TRAFFIC_CLASS; tc++) {
		uint32_t index;
		bool found = false;

		if (!(mask & (1U << tc)))
			continue;
		for (index = 0; index < count && index < ARRAY_SIZE(entries); index++) {
			if (entries[index].tc == tc) {
				found = true;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "traffic class %u is not configured\n", tc);
			return -1;
		}
	}
	return 0;
}

static int cxirdma_parse_option(void *priv, const char *name, const char *value)
{
	struct cxirdma_state *state = priv;

	if (!strcmp(name, "tc")) {
		state->explicit_tc = true;
		return parse_tc(value, name, &state->traffic_class);
	}
	if (!strcmp(name, "create-tc")) {
		state->create_tc = true;
		return parse_tc(value, name, &state->traffic_class);
	}
	if (!strcmp(name, "allow-tc")) {
		uint32_t tc;

		if (parse_tc(value, name, &tc))
			return -1;
		state->allowed_tc_mask |= 1U << tc;
		return 0;
	}
	if (!strcmp(name, "list-tcs")) {
		state->list_tcs = true;
		return 0;
	}
	if (!strcmp(name, "dry-run")) {
		state->dry_run = true;
		return 0;
	}

	{
		static const struct {
			const char *name;
			size_t offset;
		} limits[] = {
			{ "tc-ptes", offsetof(struct cxidv_job_tc_attr, ptes) },
			{ "tc-txqs", offsetof(struct cxidv_job_tc_attr, txqs) },
			{ "tc-tgqs", offsetof(struct cxidv_job_tc_attr, tgqs) },
			{ "tc-eqs", offsetof(struct cxidv_job_tc_attr, eqs) },
			{ "tc-cts", offsetof(struct cxidv_job_tc_attr, cts) },
			{ "tc-acs", offsetof(struct cxidv_job_tc_attr, acs) },
			{ "tc-tles", offsetof(struct cxidv_job_tc_attr, tles) },
			{ "tc-les", offsetof(struct cxidv_job_tc_attr, les) },
		};
		size_t i;
		bool reserved_specified;

		for (i = 0; i < ARRAY_SIZE(limits); i++) {
			if (strcmp(name, limits[i].name))
				continue;
			if (parse_limit(value,
					(struct cxidv_limits *)((char *)&state->tc_attr +
								limits[i].offset),
					&reserved_specified)) {
				fprintf(stderr, "--%s expects MAX[:RESERVED]\n", name);
				return -1;
			}
			state->limits_mask |= 1U << i;
			if (reserved_specified)
				state->explicit_reserved_mask |= 1U << i;
			else
				state->explicit_reserved_mask &= ~(1U << i);
			return 0;
		}
	}

	{
		static const struct {
			const char *name;
			enum cxidv_svc_resource resource;
		} defaults[] = {
			{ "default-ptes", CXIDV_SVC_PTES }, { "default-txqs", CXIDV_SVC_TXQS },
			{ "default-tgqs", CXIDV_SVC_TGQS }, { "default-eqs", CXIDV_SVC_EQS },
			{ "default-cts", CXIDV_SVC_CTS },   { "default-acs", CXIDV_SVC_ACS },
			{ "default-tles", CXIDV_SVC_TLES }, { "default-les", CXIDV_SVC_LES },
		};
		size_t index;
		uint32_t parsed;

		for (index = 0; index < ARRAY_SIZE(defaults); index++) {
			if (strcmp(name, defaults[index].name))
				continue;
			if (parse_number(value, UINT16_MAX, &parsed)) {
				fprintf(stderr, "--%s expects 0..%u\n", name, UINT16_MAX);
				return -1;
			}
			state->thread_defaults[defaults[index].resource] = parsed;
			state->thread_default_mask |= 1U << defaults[index].resource;
			return 0;
		}
	}

	fprintf(stderr, "unknown cxirdma option --%s\n", name);
	return -1;
}

static void print_service_plan(const struct cxirdma_state *state, const struct cxidv_svc_attr *attr)
{
	static const char *const names[CXIDV_SVC_RSRC_COUNT] = {
		"ptes", "txqs", "tgqs", "eqs", "cts", "acs", "tles", "les",
	};
	unsigned int index;

	printf("service=%s uid=%u tc_mask=0x%x\n", state->svc_id ? "reuse" : "create", state->uid,
	       attr->tc_mask);
	if (attr->vni_count) {
		printf("vnis=");
		for (index = 0; index < attr->vni_count; index++)
			printf("%s%u", index ? "," : "", attr->vnis[index]);
		printf("\n");
	} else if (attr->is_range) {
		printf("vnis=%u-%u\n", attr->vnis[0], attr->vnis[1]);
	} else if (attr->is_system_svc) {
		printf("vnis=restricted-empty\n");
	} else {
		printf("vnis=invalid\n");
	}
	for (index = 0; index < CXIDV_SVC_RSRC_COUNT; index++)
		printf("%s max=%u reserved=%u\n", names[index], attr->maximum[index],
		       attr->reserved[index]);
}

static int cxirdma_configure(void *priv, struct ibv_context *context, uint32_t job_id)
{
	struct cxirdma_state *state = priv;

	if (state->create_tc && state->explicit_tc) {
		fprintf(stderr, "--tc and --create-tc are mutually exclusive\n");
		return -1;
	}
	if (!(state->allowed_tc_mask & (1U << state->traffic_class))) {
		fprintf(stderr, "selected --tc must be included in --allow-tc grants\n");
		return -1;
	}
	if (validate_tc_mask(context, state->allowed_tc_mask, state->create_tc))
		return -1;

	{
		struct cxidv_svc_attr attr = {
			.vni_count = state->vni_count,
			.tc_mask = state->allowed_tc_mask,
			.uid = state->uid,
			.flags = state->create_tc ? CXIDV_SVC_CREATE_TC : 0,
		};
		const struct cxidv_limits *limits[] = {
			&state->tc_attr.ptes, &state->tc_attr.txqs, &state->tc_attr.tgqs,
			&state->tc_attr.eqs,  &state->tc_attr.cts,  &state->tc_attr.acs,
			&state->tc_attr.tles, &state->tc_attr.les,
		};
		unsigned int index;
		int ret;

		memcpy(attr.vnis, state->vnis, state->vni_count * sizeof(state->vnis[0]));
		if (state->svc_id) {
			if (state->limits_mask || state->threads_per_task_set) {
				fprintf(stderr, "limits cannot change a selected service\n");
				return -1;
			}
			ret = cxidv_query_svc(context, state->svc_id, &attr);
			if (ret || !(attr.flags & CXIDV_SVC_ENABLED) || attr.uid != state->uid ||
			    (attr.tc_mask & state->allowed_tc_mask) != state->allowed_tc_mask) {
				fprintf(stderr,
					"selected service does not grant the requested policy\n");
				return -1;
			}
			for (index = 0; index < state->vni_count; index++) {
				if (!service_allows_vni(&attr, state->vnis[index])) {
					fprintf(stderr, "selected service does not grant VNI %u\n",
						state->vnis[index]);
					return -1;
				}
			}
			if (state->create_tc) {
				fprintf(stderr, "--create-tc cannot change a selected service\n");
				return -1;
			}
			if (state->dry_run) {
				print_service_plan(state, &attr);
				return 0;
			}
		} else {
			struct cxidv_devinfo info;
			bool have_limits = state->limits_mask != 0 || state->threads_per_task_set;

			if (have_limits) {
				ret = cxidv_query_device(context, &info);
				if (ret)
					return -1;
				attr.maximum[CXIDV_SVC_PTES] = info.num_ptes;
				attr.maximum[CXIDV_SVC_TXQS] = info.num_txqs;
				attr.maximum[CXIDV_SVC_TGQS] = info.num_tgqs;
				attr.maximum[CXIDV_SVC_EQS] = info.num_eqs;
				attr.maximum[CXIDV_SVC_CTS] = info.num_cts;
				attr.maximum[CXIDV_SVC_ACS] = info.num_acs;
				attr.maximum[CXIDV_SVC_TLES] = info.num_tles;
				attr.maximum[CXIDV_SVC_LES] = info.num_les;
			}
			for (index = 0; index < CXIDV_SVC_RSRC_COUNT; index++) {
				uint32_t bit = 1U << index;
				uint16_t maximum = attr.maximum[index];
				uint64_t reservation = 0;
				bool reservation_set = state->threads_per_task_set;

				if (state->threads_per_task_set)
					reservation = (uint64_t)state->thread_defaults[index] *
						      state->threads_per_task;
				if (state->limits_mask & bit) {
					maximum = limits[index]->max;
					if ((state->explicit_reserved_mask & bit) ||
					    !state->threads_per_task_set) {
						reservation = limits[index]->res;
						reservation_set = true;
					}
				}
				if (reservation_set) {
					if (reservation > maximum && !state->threads_per_task_set) {
						fprintf(stderr,
							"--tc resource reservation exceeds maximum\n");
						return -1;
					}
					if (reservation > maximum) {
						fprintf(stderr,
							"resource %u reservation clamped to maximum %u\n",
							index, maximum);
						reservation = maximum;
					}
					attr.reserved[index] = reservation;
				}
				attr.maximum[index] = maximum;
				if (state->threads_per_task_set || (state->limits_mask & bit))
					attr.flags |= CXIDV_SVC_LIMITS;
			}
			if (state->dry_run) {
				print_service_plan(state, &attr);
				return 0;
			}
			ret = cxidv_alloc_svc(context, &attr, &state->svc_id);
			if (ret) {
				fprintf(stderr, "couldn't provision service for JobID %u: %s\n",
					job_id, strerror(ret));
				return -1;
			}
			state->owns_svc = true;
		}
	}

	/*
	 * The target picks its service from UET_SERVICE_ID; without this it
	 * falls back to the default service, which is not the one the binding
	 * just provisioned for this traffic class.
	 */
	if (state->svc_id) {
		char value[16];

		snprintf(value, sizeof(value), "%u", state->svc_id);
		if (setenv("UET_SERVICE_ID", value, 1)) {
			perror("setenv UET_SERVICE_ID");
			return -1;
		}
		if (setenv("SLINGSHOT_SVC_IDS", value, 1))
			return -1;
	}

	/*
	 * The service authorises the VNI, but QP creation still needs
	 * UET_TC to pick the same traffic class; ctx->tc_valid never
	 * survives exec() into the target process.
	 */
	{
		char value[16];

		snprintf(value, sizeof(value), "%u", state->traffic_class);
		if (setenv("UET_TC", value, 1)) {
			perror("setenv UET_TC");
			return -1;
		}
		snprintf(value, sizeof(value), "%x", state->allowed_tc_mask);
		if (setenv("SLINGSHOT_TCS", value, 1))
			return -1;
	}

	return 0;
}

static int cxirdma_cleanup(void *priv, struct ibv_context *context)
{
	struct cxirdma_state *state = priv;

	if (state->owns_svc) {
		int ret = cxidv_destroy_svc(context, state->svc_id);

		if (ret)
			fprintf(stderr, "couldn't destroy launcher service %u: %s\n", state->svc_id,
				strerror(ret));
		return ret;
	}
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s [options] -- command [args...]\n", program);
	printf("  -d, --device NAME        RDMA device\n");
	printf("  -j, --vni NUMBER         granted VNI; repeat up to %u times\n",
	       CXIDV_SVC_MAX_VNIS);
	printf("  -u, --uid NUMBER         child/service owner (default sudo user; 0=root)\n");
	printf("  -S, --service NUMBER     reuse a permitted service without destroying it\n");
	printf("  --tc NUMBER              existing TC (default best effort)\n");
	printf("  --allow-tc NUMBER        grant a TC; repeat to grant more classes\n");
	printf("  --create-tc NUMBER       provision a TC for the owned service\n");
	printf("  --tc-{ptes,txqs,tgqs,eqs,cts,acs,tles,les} MAX[:RESERVED]\n");
	printf("  --threads-per-task N     apply Slurm per-thread resource defaults\n");
	printf("  --default-{ptes,txqs,tgqs,eqs,cts,acs,tles,les} N\n");
	printf("  --dry-run                print policy without creating a service\n");
	printf("  -i, --port NUMBER        port (default 1)\n");
	printf("  -g, --gid-index NUMBER   GID index (default 0)\n");
	printf("  --max-addr-entries N     opt in to a job address table\n");
	printf("  --list-tcs               query traffic classes without launching\n");
}

static int child_environment(const struct cxirdma_state *state, int descriptor, const char *device)
{
	char value[32];
	char vni_list[CXIDV_SVC_MAX_VNIS * 6];

	snprintf(value, sizeof(value), "%u", state->vnis[0]);
	if (format_vni_list(state->vnis, state->vni_count, vni_list, sizeof(vni_list)) ||
	    setenv("UET_JOB_ID", value, 1) || setenv("SLINGSHOT_VNIS", vni_list, 1))
		return -1;
	snprintf(value, sizeof(value), "%d", descriptor);
	if (setenv("UET_JOB_FD", value, 1) || setenv("CXI_VERBS_DEVICE", device, 1))
		return -1;
	return 0;
}

static int native_device_name(struct ibv_context *context, char *name, size_t capacity)
{
	struct cxidv_devinfo info;
	struct dirent *entry;
	DIR *directory;
	int result = -1;

	if (cxidv_query_device(context, &info))
		return -1;
	directory = opendir("/sys/class/cxi");
	if (!directory)
		return -1;
	while ((entry = readdir(directory))) {
		char path[PATH_MAX];
		FILE *property;
		unsigned int nid;
		int parsed;

		if (strncmp(entry->d_name, "cxi", 3))
			continue;
		snprintf(path, sizeof(path), "/sys/class/cxi/%s/device/properties/nid",
			 entry->d_name);
		property = fopen(path, "r");
		if (!property)
			continue;
		parsed = fscanf(property, "%x", &nid);
		fclose(property);
		if (parsed != 1 || nid != info.nid)
			continue;
		if (strlen(entry->d_name) >= capacity)
			break;
		memcpy(name, entry->d_name, strlen(entry->d_name) + 1);
		result = 0;
		break;
	}
	closedir(directory);
	return result;
}

/*
 * Variables this tool defines for the child. Inherited values are removed so
 * a caller cannot make the child use a service or job it was not granted.
 */
static void scrub_environment(void)
{
	char **env;

	for (env = environ; env && *env;) {
		if (!strncmp(*env, "UET_", 4) || !strncmp(*env, "SLINGSHOT_", 10) ||
		    !strncmp(*env, "CXI_VERBS_", 10)) {
			char *name = strndup(*env, strcspn(*env, "="));

			if (!name)
				_exit(1);
			unsetenv(name);
			free(name);
			env = environ;
			continue;
		}
		env++;
	}
}

/* Close everything except stdio and the exported job grant. */
static int close_inherited_fds(int keep)
{
	struct dirent *entry;
	DIR *directory;
	int ret = 0;

#ifdef SYS_close_range
	unsigned int first = keep < 3 ? 3 : (unsigned int)keep + 1;

	if (keep > 3 && syscall(SYS_close_range, 3, keep - 1, 0))
		goto slow;
	if (!syscall(SYS_close_range, first, ~0U, 0))
		return 0;
slow:
#endif
	directory = opendir("/proc/self/fd");
	if (!directory)
		return -1;
	for (;;) {
		char *end;
		long number;

		errno = 0;
		entry = readdir(directory);
		if (!entry) {
			ret = errno ? -1 : 0;
			break;
		}
		number = strtol(entry->d_name, &end, 10);
		if (*end || number < 3 || number > INT_MAX ||
		    number == keep || number == dirfd(directory))
			continue;
		close((int)number);
	}
	closedir(directory);
	return ret;
}

/* Runs in the forked child, before anything of the user's runs. */
static int drop_privileges(uid_t uid, gid_t gid, const char *name)
{
	if (initgroups(name, gid) || setresgid(gid, gid, gid) || setresuid(uid, uid, uid))
		return -1;
	/* Explicit --uid 0 runs the job as root: nothing to take away. */
	if (!uid)
		return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ? -1 : 0;
	/* Irreversible: the real, effective and saved ids are all the user's. */
	if (setuid(0) == 0 || seteuid(0) == 0 || setgid(0) == 0)
		return -1;
	if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid)
		return -1;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) ||
	    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
		return -1;
	return 0;
}

int main(int argc, char **argv)
{
	struct cxirdma_state state = {
		.traffic_class = CXIDV_TC_BEST_EFFORT,
		.thread_defaults = { 6, 2, 1, 2, 1, 2, 1, 16 },
	};
	struct ibv_device **devices = NULL;
	struct ibv_device *device = NULL;
	struct ibv_context *context = NULL;
	struct ibv_job *job = NULL;
	struct ibv_job_attr job_attr = {
		.comp_mask = IBV_JOB_ATTR_ID | IBV_JOB_ATTR_PORT_NUM | IBV_JOB_ATTR_SGID_INDEX,
		.port_num = 1,
	};
	struct sigaction action = { .sa_handler = forward_signal };
	struct passwd *owner;
	const char *device_name = NULL;
	const char *sudo_uid = getenv("SUDO_UID");
	char *owner_name = NULL;
	char native_name[64];
	gid_t owner_gid;
	uint32_t value;
	bool uid_set = false;
	int descriptor = -1, result = 1, status, option_index, option;
	pid_t child;
	sigset_t blocked, previous;

	/*
	 * Root only, and never setuid or file-capability installed: the real
	 * uid must be 0 and the loader must not be in secure-exec mode.
	 */
	if (getuid() != 0 || geteuid() != 0 || getauxval(AT_SECURE)) {
		fprintf(stderr, "%s: must be run by root, not setuid\n", argv[0]);
		return 1;
	}
	/* Default target is the sudo invoker; root only if asked with --uid 0. */
	if (sudo_uid) {
		if (parse_number(sudo_uid, UINT32_MAX, &value))
			return 1;
		state.uid = value;
		uid_set = true;
	}
	scrub_environment();
	while ((option = getopt_long(argc, argv, "+d:j:u:S:i:g:h", cxirdma_options,
				     &option_index)) != -1) {
		if (option == 'h') {
			usage(argv[0]);
			return 0;
		}
		if (option == 'd') {
			device_name = optarg;
			continue;
		}
		if (option == 1000) {
			if (cxirdma_parse_option(&state, cxirdma_options[option_index].name,
						 optarg))
				return 1;
			continue;
		}
		if (option == 1001) {
			if (state.threads_per_task_set ||
			    parse_number(optarg, UINT32_MAX, &value) || !value) {
				fprintf(stderr, "--threads-per-task requires a positive integer\n");
				return 1;
			}
			state.threads_per_task = value;
			state.threads_per_task_set = true;
			continue;
		}
		if (option == 1002) {
			if (parse_number(optarg, UINT32_MAX, &value) || !value) {
				fprintf(stderr, "--max-addr-entries requires a positive integer\n");
				return 1;
			}
			state.max_addr_entries = value;
			continue;
		}
		if (parse_number(optarg, UINT32_MAX, &value))
			return 1;
		switch (option) {
		case 'j':
			if (!value || value > UINT16_MAX || state.vni_count == CXIDV_SVC_MAX_VNIS) {
				fprintf(stderr,
					"--vni requires a unique nonzero value; at most %u are allowed\n",
					CXIDV_SVC_MAX_VNIS);
				return 1;
			}
			for (uint32_t index = 0; index < state.vni_count; index++)
				if (state.vnis[index] == value) {
					fprintf(stderr, "duplicate --vni %u\n", value);
					return 1;
				}
			state.vnis[state.vni_count++] = value;
			break;
		case 'u':
			state.uid = value;
			uid_set = true;
			break;
		case 'S':
			if (!value)
				return 1;
			state.svc_id = value;
			break;
		case 'i':
			if (!value || value > UINT8_MAX)
				return 1;
			job_attr.port_num = value;
			break;
		case 'g':
			if (value > UINT8_MAX)
				return 1;
			job_attr.sgid_index = value;
			break;
		default:
			return 1;
		}
	}
	if ((!state.vni_count && !state.list_tcs) ||
	    (optind == argc && !state.list_tcs && !state.dry_run)) {
		usage(argv[0]);
		return 1;
	}
	if (state.vni_count)
		job_attr.id = state.vnis[0];
	if (state.max_addr_entries) {
		job_attr.comp_mask |= IBV_JOB_ATTR_MAX_ADDR_ENTRIES;
		job_attr.max_addr_entries = state.max_addr_entries;
	}
	if (state.thread_default_mask && !state.threads_per_task_set) {
		fprintf(stderr, "--default-* requires --threads-per-task\n");
		return 1;
	}
	if (!state.allowed_tc_mask)
		state.allowed_tc_mask = 1U << state.traffic_class;
	if (!(state.allowed_tc_mask & (1U << state.traffic_class))) {
		fprintf(stderr, "selected --tc must be included in --allow-tc grants\n");
		return 1;
	}
	if (!uid_set && !state.list_tcs) {
		fprintf(stderr, "no target user: run under sudo or pass --uid\n");
		return 1;
	}
	owner = getpwuid(state.uid);
	if (!owner)
		return 1;
	owner_gid = owner->pw_gid;
	owner_name = strdup(owner->pw_name);
	if (!owner_name)
		return 1;
	devices = ibv_get_device_list(NULL);
	if (!devices)
		goto out;
	for (size_t index = 0; devices[index]; index++) {
		if (devices[index]->transport_type != IBV_TRANSPORT_SLINGSHOT)
			continue;
		if (!device_name || !strcmp(device_name, ibv_get_device_name(devices[index]))) {
			device = devices[index];
			break;
		}
	}
	if (!device)
		goto out;
	context = ibv_open_device(device);
	if (!context)
		goto out;
	if (state.list_tcs) {
		result = list_tcs(context) ? 1 : 0;
		goto out;
	}
	if (native_device_name(context, native_name, sizeof(native_name)) ||
	    setenv("SLINGSHOT_DEVICES", native_name, 1)) {
		fprintf(stderr, "couldn't identify the native CXI device\n");
		goto out;
	}
	if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
	    sigaction(SIGHUP, &action, NULL))
		goto out;
	if (cxirdma_configure(&state, context, job_attr.id))
		goto out;
	if (state.dry_run) {
		result = 0;
		goto out;
	}
	job = ibv_alloc_job(context, &job_attr, NULL);
	if (!job || ibv_export_job(job, &descriptor))
		goto out;
	value = fcntl(descriptor, F_GETFD);
	if (value == (uint32_t)-1 || fcntl(descriptor, F_SETFD, value & ~FD_CLOEXEC))
		goto out;
	if (child_environment(&state, descriptor, ibv_get_device_name(device)))
		goto out;
	sigemptyset(&blocked);
	sigaddset(&blocked, SIGINT);
	sigaddset(&blocked, SIGTERM);
	sigaddset(&blocked, SIGHUP);
	if (sigprocmask(SIG_BLOCK, &blocked, &previous))
		goto out;
	child = fork();
	if (child == 0) {
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		/* The child must not keep the root-owned verbs context. */
		if (close_inherited_fds(descriptor) || setpgid(0, 0) ||
		    drop_privileges(state.uid, owner_gid, owner_name) ||
		    sigprocmask(SIG_SETMASK, &previous, NULL))
			_exit(126);
		execvp(argv[optind], &argv[optind]);
		perror("execvp");
		_exit(127);
	}
	if (child > 0) {
		setpgid(child, child);
		child_group = child;
	}
	sigprocmask(SIG_SETMASK, &previous, NULL);
	if (child < 0)
		goto out;
	if (interrupted)
		kill(-child, interrupted);
	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR)
			goto out;
	}
	child_group = 0;
	if (WIFEXITED(status))
		result = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		result = 128 + WTERMSIG(status);
out:
	if (descriptor >= 0)
		close(descriptor);
	if (job && ibv_dealloc_job(job)) {
		perror("deallocate launcher job");
		result = 1;
	}
	if (context && cxirdma_cleanup(&state, context))
		result = 1;
	if (context && ibv_close_device(context))
		result = 1;
	if (devices)
		ibv_free_device_list(devices);
	free(owner_name);
	return result;
}
