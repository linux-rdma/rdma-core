// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */
#define _GNU_SOURCE
#include <config.h>

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

int ibv_read_sysfs_file(const char *dir, const char *file,
			char *buf, size_t size)
{
	char *path, *s;
	int ret;
	size_t len;

	if (asprintf(&path, "%s/%s", dir, file) < 0)
		return -1;

	for (s = &path[0]; *s != '\0'; s++)
		if (*s == '/')
			*s = '.';

	len = size;
	ret = sysctlbyname(&path[1], buf, &len, NULL, 0);
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
	/* XXXKIB */
	return -1;
}
