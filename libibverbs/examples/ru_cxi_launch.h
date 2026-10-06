/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

/*
 * Slingshot (CXI) devices need a service and job grant that only root can
 * create. cxi_launcher creates them and runs a command under the grant. A
 * program that finds no grant calls ru_cxi_relaunch() to run itself again
 * under the launcher; the second run finds UET_JOB_FD and carries on.
 */

#ifndef RU_CXI_LAUNCH_H
#define RU_CXI_LAUNCH_H

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef CXI_LAUNCHER_BINDIR
#define CXI_LAUNCHER_BINDIR "/usr/bin"
#endif

#define RU_CXI_MAX_ARGS 256

/* Returns 0 if already running under a grant, -1 on error; else never returns. */
static inline int ru_cxi_relaunch(const char *devname, uint32_t job_id, int port, int gidx,
				  uint32_t max_addr_entries)
{
	char exe[PATH_MAX], launcher[PATH_MAX + 16], cmdline[16384];
	const char *args[RU_CXI_MAX_ARGS + 16];
	char idbuf[16], portbuf[16], gidbuf[16], addrbuf[16];
	ssize_t len, total;
	size_t n = 0, i;
	int fd;

	if (getenv("UET_JOB_FD"))
		return 0;
	if (geteuid() != 0) {
		fprintf(stderr,
			"Slingshot jobs are set up by cxi_launcher, which must run as root; use sudo\n");
		return -1;
	}

	len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (len < 0 || (size_t)len == sizeof(exe) - 1) {
		if (len >= 0)
			errno = ENAMETOOLONG;
		perror("readlink /proc/self/exe");
		return -1;
	}
	exe[len] = 0;

	len = snprintf(launcher, sizeof(launcher), "%s/cxi_launcher", CXI_LAUNCHER_BINDIR);
	if (len < 0 || (size_t)len >= sizeof(launcher)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		perror("open /proc/self/cmdline");
		return -1;
	}
	total = 0;
	while ((len = read(fd, cmdline + total, sizeof(cmdline) - 1 - total)) > 0)
		total += len;
	if ((size_t)total == sizeof(cmdline) - 1) {
		char extra;

		len = read(fd, &extra, sizeof(extra));
		if (len > 0) {
			close(fd);
			errno = E2BIG;
			fprintf(stderr, "command line exceeds launcher capacity\n");
			return -1;
		}
	}
	close(fd);
	if (len < 0 || total <= 0) {
		fprintf(stderr, "couldn't read the command line\n");
		return -1;
	}
	if (cmdline[total - 1] != '\0') {
		errno = E2BIG;
		return -1;
	}
	cmdline[total] = 0;

	snprintf(idbuf, sizeof(idbuf), "%u", job_id);
	args[n++] = launcher;
	args[n++] = "-d";
	args[n++] = devname;
	args[n++] = "--vni";
	args[n++] = idbuf;
	if (port > 0) {
		snprintf(portbuf, sizeof(portbuf), "%d", port);
		args[n++] = "-i";
		args[n++] = portbuf;
	}
	if (gidx >= 0) {
		snprintf(gidbuf, sizeof(gidbuf), "%d", gidx);
		args[n++] = "-g";
		args[n++] = gidbuf;
	}
	if (max_addr_entries) {
		snprintf(addrbuf, sizeof(addrbuf), "%u", max_addr_entries);
		args[n++] = "--max-addr-entries";
		args[n++] = addrbuf;
	}
	/* Run as the sudo caller; a plain root login runs the job as root. */
	if (!getenv("SUDO_UID")) {
		args[n++] = "--uid";
		args[n++] = "0";
	}
	args[n++] = "--";
	args[n++] = exe;
	/* Skip argv[0] of the original command line. */
	i = strlen(cmdline) + 1;
	while (i < (size_t)total && n < RU_CXI_MAX_ARGS) {
		args[n++] = cmdline + i;
		i += strlen(cmdline + i) + 1;
	}
	if (i < (size_t)total) {
		fprintf(stderr, "too many arguments\n");
		return -1;
	}
	args[n] = NULL;

	execv(launcher, (char *const *)args);
	fprintf(stderr, "couldn't run %s: %s\n", launcher, strerror(errno));
	return -1;
}

#endif
