/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <string.h>
#include <glob.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include "ibverbs.h"

#ifndef OPENIB_DRIVER_PATH_ENV
#  define OPENIB_DRIVER_PATH_ENV "OPENIB_DRIVER_PATH"
#endif

HIDDEN int abi_ver;

static const char default_path[] = DRIVER_PATH;
static const char *user_path;

static struct ibv_driver *driver_list;

static void load_driver(char *so_path)
{
	void *dlhandle;
	ibv_driver_init_func init_func;
	struct ibv_driver *driver;

	dlhandle = dlopen(so_path, RTLD_NOW);
	if (!dlhandle) {
		fprintf(stderr, PFX "Warning: couldn't load driver %s: %s\n",
			so_path, dlerror());
		return;
	}

	dlerror();
	init_func = dlsym(dlhandle, "ibv_driver_init");
	if (dlerror() != NULL || !init_func) {
		dlclose(dlhandle);
		return;
	}

	driver = malloc(sizeof *driver);
	if (!driver) {
		fprintf(stderr, PFX "Fatal: couldn't allocate driver for %s\n", so_path);
		dlclose(dlhandle);
		return;
	}

	driver->init_func = init_func;
	driver->next      = driver_list;
	driver_list       = driver;
}

static void find_drivers(const char *dir)
{
	size_t len = strlen(dir);
	glob_t so_glob;
	char *pat;
	int ret;
	int i;

	if (!len)
		return;

	while (len && dir[len - 1] == '/')
		--len;

	asprintf(&pat, "%.*s/*.so", (int) len, dir);

	ret = glob(pat, 0, NULL, &so_glob);
	free(pat);

	if (ret) {
		if (ret != GLOB_NOMATCH)
			fprintf(stderr, PFX "Warning: couldn't search %s\n", pat);
		return;
	}

	for (i = 0; i < so_glob.gl_pathc; ++i)
		load_driver(so_glob.gl_pathv[i]);

	globfree(&so_glob);
}

static struct ibv_device *init_drivers(const char *class_path,
				       const char *dev_name)
{
	struct ibv_driver *driver;
	struct ibv_device *dev;
	int abi_ver = 0;
	char sys_path[IBV_SYSFS_PATH_MAX];
	char ibdev_name[IBV_SYSFS_NAME_MAX];
	char ibdev_path[IBV_SYSFS_PATH_MAX];
	char value[8];
	enum ibv_node_type node_type;

	snprintf(sys_path, sizeof sys_path, "%s/%s",
		 class_path, dev_name);

	if (ibv_read_sysfs_file(sys_path, "abi_version", value, sizeof value) > 0)
		abi_ver = strtol(value, NULL, 10);

	if (ibv_read_sysfs_file(sys_path, "ibdev", ibdev_name, sizeof ibdev_name) < 0) {
		fprintf(stderr, PFX "Warning: no ibdev class attr for %s\n",
			sys_path);
		return NULL;
	}

	snprintf(ibdev_path, IBV_SYSFS_PATH_MAX, "%s/class/infiniband/%s",
		 ibv_get_sysfs_path(), ibdev_name);

	if (ibv_read_sysfs_file(ibdev_path, "node_type", value, sizeof value) < 0) {
		fprintf(stderr, PFX "Warning: no node_type attr for %s\n",
			ibdev_path);
		return NULL;
	}
	node_type = strtol(value, NULL, 10);
	if (node_type < IBV_NODE_CA || node_type > IBV_NODE_RNIC)
		node_type = IBV_NODE_UNKNOWN;

	for (driver = driver_list; driver; driver = driver->next) {
		dev = driver->init_func(sys_path, abi_ver);
		if (!dev)
			continue;

		dev->node_type = node_type;

		switch (node_type) {
		case IBV_NODE_CA:
		case IBV_NODE_SWITCH:
		case IBV_NODE_ROUTER:
			dev->transport_type = IBV_TRANSPORT_IB;
			break;
		case IBV_NODE_RNIC:
			dev->transport_type = IBV_TRANSPORT_IWARP;
			break;
		default:
			dev->transport_type = IBV_TRANSPORT_UNKNOWN;
			break;
		}

		strcpy(dev->dev_path, sys_path);
		strcpy(dev->dev_name, dev_name);
		strcpy(dev->name, ibdev_name);
		strcpy(dev->ibdev_path, ibdev_path);

		return dev;
	}

	fprintf(stderr, PFX "Warning: no userspace device-specific driver found for %s\n"
		"	driver search path: ", dev_name);
	if (user_path)
		fprintf(stderr, "%s:", user_path);
	fprintf(stderr, "%s\n", default_path);

	return NULL;
}

static int check_abi_version(const char *path)
{
	char value[8];

	if (ibv_read_sysfs_file(path, "class/infiniband_verbs/abi_version",
				value, sizeof value) < 0) {
		fprintf(stderr, PFX "Fatal: couldn't read uverbs ABI version.\n");
		return -1;
	}

	abi_ver = strtol(value, NULL, 10);

	if (abi_ver < IB_USER_VERBS_MIN_ABI_VERSION ||
	    abi_ver > IB_USER_VERBS_MAX_ABI_VERSION) {
		fprintf(stderr, PFX "Fatal: kernel ABI version %d "
			"doesn't match library version %d.\n",
			abi_ver, IB_USER_VERBS_MAX_ABI_VERSION);
		return -1;
	}

	return 0;
}

HIDDEN int ibverbs_init(struct ibv_device ***list)
{
	const char *sysfs_path;
	char *wr_path, *dir;
	char class_path[IBV_SYSFS_PATH_MAX];
	DIR *class_dir;
	struct dirent *dent;
	struct ibv_device *device;
	struct ibv_device **new_list;
	int num_devices = 0;
	int list_size = 0;

	*list = NULL;

	if (getenv("RDMAV_FORK_SAFE") || getenv("IBV_FORK_SAFE"))
		if (ibv_fork_init())
			fprintf(stderr, PFX "Warning: fork()-safety requested "
				"but init failed\n");

	find_drivers(default_path);

	/*
	 * Only follow use path passed in through the calling user's
	 * environment if we're not running SUID.
	 */
	if (getuid() == geteuid()) {
		user_path = getenv(OPENIB_DRIVER_PATH_ENV);
		if (user_path) {
			wr_path = strdupa(user_path);
			while ((dir = strsep(&wr_path, ";:")))
				find_drivers(dir);
		}
	}

	/*
	 * Now check if a driver is statically linked.  Since we push
	 * drivers onto our driver list, the last driver we find will
	 * be the first one we try.
	 */
	load_driver(NULL);

	sysfs_path = ibv_get_sysfs_path();
	if (!sysfs_path) {
		fprintf(stderr, PFX "Fatal: couldn't find sysfs mount.\n");
		return 0;
	}

	if (check_abi_version(sysfs_path))
		return 0;

	snprintf(class_path, sizeof class_path, "%s/class/infiniband_verbs",
		 sysfs_path);
	class_dir = opendir(class_path);
	if (!class_dir) {
		fprintf(stderr, PFX "Fatal: couldn't open sysfs class "
			"directory '%s'.\n", class_path);
		return 0;
	}

	while ((dent = readdir(class_dir))) {
		if (dent->d_name[0] == '.' || dent->d_type == DT_REG)
			continue;

		device = init_drivers(class_path, dent->d_name);
		if (!device)
			continue;

		if (list_size <= num_devices) {
			list_size = list_size ? list_size * 2 : 1;
			new_list = realloc(*list, list_size * sizeof (struct ibv_device *));
			if (!new_list)
				goto out;
			*list = new_list;
		}

		(*list)[num_devices++] = device;
	}

	closedir(class_dir);

out:
	return num_devices;
}
