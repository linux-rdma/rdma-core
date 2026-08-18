/*
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
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
 */
#define _GNU_SOURCE
#include <config.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/sysctl.h>

#include "ibverbs.h"

static const char *sysfs_path;

const char *ibv_get_sysfs_path(void)
{
	const char *env = NULL;
	static const char slash_sys[] = "/sys";

	if (sysfs_path)
		return sysfs_path;

	/*
	 * Only follow use path passed in through the calling user's
	 * environment if we're not running SUID.
	 */
	if (getuid() == geteuid())
		env = getenv("SYSFS_PATH");

	if (env) {
		int len;
		char *dup;

		sysfs_path = dup = strndup(env, IBV_SYSFS_PATH_MAX);
		if (dup == NULL) {
			sysfs_path = slash_sys;
		} else {
			len = strlen(dup);
			while (len > 0 && dup[len - 1] == '/') {
				--len;
				dup[len] = '\0';
			}
		}
	} else
		sysfs_path = slash_sys;

	return sysfs_path;
}

static int sysctl_verbose = -1;

int ibv_read_sysfs_file(const char *dir, const char *file,
			char *buf, size_t size)
{
	char *path, *s, *r;
	int ret;
	size_t len;

	if (sysctl_verbose == -1)
		sysctl_verbose = getenv("IBVERBS_SYSCTL_VERBOSE") != NULL;

	if (asprintf(&path, "%s/%s", dir, file) < 0)
		return -1;

	if (sysctl_verbose)
		fprintf(stderr, "sysctl \"%s\": ", path);
	for (s = &path[0]; *s != '\0'; s++)
		if (*s == '/')
			*s = '.';

	len = size;
	ret = sysctlbyname(&path[1], buf, &len, NULL, 0);
	if (sysctl_verbose) {
		if (ret == -1) {
			fprintf(stderr, "error %d (%s)\n", errno,
			    strerror(errno));
		} else {
			r = alloca(len + 1);
			memcpy(r, buf, len);
			r[len] = '\0';
			fprintf(stderr, "%s\n", r);
		}
	}
	free(path);

	if (ret == -1)
		return -1;

	if (len > 0 && buf[len - 1] == '\n')
		buf[--len] = '\0';

	return len;
}

int ibv_read_ibdev_sysfs_file(char *buf, size_t size,
			      struct verbs_sysfs_dev *sysfs_dev,
			      const char *fnfmt, ...)
{
	char comp[IBV_SYSFS_PATH_MAX];
	va_list ap;

	va_start(ap, fnfmt);
	vsnprintf(comp, sizeof(comp), fnfmt, ap);
	va_end(ap);

	if (strcmp(comp, "device/modalias") == 0) {
		char path_device[IBV_SYSFS_PATH_MAX];
		char value[64];
		unsigned vendor;
		unsigned devid;

		snprintf(path_device, sizeof(path_device), "%s/%s/%s/device",
		    ibv_get_sysfs_path(), "class/infiniband_verbs",
		    sysfs_dev->sysfs_name);
		if (ibv_read_sysfs_file(path_device, "vendor", value,
		    sizeof(value)) < 0)
			return -1;
		vendor = strtoul(value, NULL, 0);
		if (ibv_read_sysfs_file(path_device, "device", value,
		    sizeof(value)) < 0)
			return -1;
		devid = strtoul(value, NULL, 0);
		snprintf(buf, size, "pci:v%08Xd%08Xsv", vendor, devid);
		return 1;
	}

	return -1;
}
