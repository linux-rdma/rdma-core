/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2018 Mellanox Technologies, Ltd.  All rights reserved.
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
#ifndef _STATIC_LIBRARY_BUILD_
#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ccan/list.h>

#include "ibverbs.h"

struct ibv_driver_name {
	struct list_node entry;
	char *name;
};

static LIST_HEAD(driver_name_list);

static void read_config_file(const char *path)
{
	FILE *conf;
	char *line = NULL;
	char *config;
	char *field;
	size_t buflen = 0;
	ssize_t len;

	conf = fopen(path, "r" STREAM_CLOEXEC);
	if (!conf) {
		fprintf(stderr, PFX "Warning: couldn't read config file %s.\n",
			path);
		return;
	}

	while ((len = getline(&line, &buflen, conf)) != -1) {
		config = line + strspn(line, "\t ");
		if (config[0] == '\n' || config[0] == '#')
			continue;

		field = strsep(&config, "\n\t ");

		if (strcmp(field, "driver") == 0 && config != NULL) {
			struct ibv_driver_name *driver_name;

			config += strspn(config, "\t ");
			field = strsep(&config, "\n\t ");

			driver_name = malloc(sizeof(*driver_name));
			if (!driver_name) {
				fprintf(stderr,
					PFX
					"Warning: couldn't allocate driver name '%s'.\n",
					field);
				continue;
			}

			driver_name->name = strdup(field);
			if (!driver_name->name) {
				fprintf(stderr,
					PFX
					"Warning: couldn't allocate driver name '%s'.\n",
					field);
				free(driver_name);
				continue;
			}

			list_add(&driver_name_list, &driver_name->entry);
		} else
			fprintf(stderr,
				PFX
				"Warning: ignoring bad config directive '%s' in file '%s'.\n",
				field, path);
	}

	if (line)
		free(line);
	fclose(conf);
}

static void read_config(void)
{
	DIR *conf_dir;
	struct dirent *dent;
	char *path;

	conf_dir = opendir(IBV_CONFIG_DIR);
	if (!conf_dir) {
		fprintf(stderr,
			PFX "Warning: couldn't open config directory '%s'.\n",
			IBV_CONFIG_DIR);
		return;
	}

	while ((dent = readdir(conf_dir))) {
		struct stat buf;

		if (asprintf(&path, "%s/%s", IBV_CONFIG_DIR, dent->d_name) <
		    0) {
			fprintf(stderr,
				PFX
				"Warning: couldn't read config file %s/%s.\n",
				IBV_CONFIG_DIR, dent->d_name);
			goto out;
		}

		if (stat(path, &buf)) {
			fprintf(stderr,
				PFX
				"Warning: couldn't stat config file '%s'.\n",
				path);
			goto next;
		}

		if (!S_ISREG(buf.st_mode))
			goto next;

		read_config_file(path);
next:
		free(path);
	}

out:
	closedir(conf_dir);
}

static void load_driver(const char *name)
{
	char *so_name;
	void *dlhandle;

	/* If the name is an absolute path then open that path after appending
	 * the trailer suffix
	 */
	if (name[0] == '/') {
		if (asprintf(&so_name, "%s" VERBS_PROVIDER_SUFFIX, name) < 0)
			goto out_asprintf;
		dlhandle = dlopen(so_name, RTLD_NOW);
		if (!dlhandle)
			goto out_dlopen;
		free(so_name);
		return;
	}

	/* If configured with a provider plugin path then try that next */
	if (sizeof(VERBS_PROVIDER_DIR) > 1) {
		if (asprintf(&so_name,
			     VERBS_PROVIDER_DIR "/lib%s" VERBS_PROVIDER_SUFFIX,
			     name) < 0)
			goto out_asprintf;
		dlhandle = dlopen(so_name, RTLD_NOW);
		free(so_name);
		if (dlhandle)
			return;
	}

	/* Otherwise use the system library search path. This is the historical
	 * behavior of libibverbs
	 */
	if (asprintf(&so_name, "lib%s" VERBS_PROVIDER_SUFFIX, name) < 0)
		goto out_asprintf;
	dlhandle = dlopen(so_name, RTLD_NOW);
	if (!dlhandle)
		goto out_dlopen;
	free(so_name);
	return;

out_asprintf:
	fprintf(stderr, PFX "Warning: couldn't load driver '%s'.\n", name);
	return;
out_dlopen:
	fprintf(stderr, PFX "Warning: couldn't load driver '%s': %s\n", so_name,
		dlerror());
	free(so_name);
}

void load_drivers(void)
{
	struct ibv_driver_name *name, *next_name;
	const char *env;
	char *list, *env_name;

	read_config();

	/* Only use drivers passed in through the calling user's environment
	 * if we're not running setuid.
	 */
	if (getuid() == geteuid()) {
		if ((env = getenv("RDMAV_DRIVERS"))) {
			list = strdupa(env);
			while ((env_name = strsep(&list, ":;")))
				load_driver(env_name);
		} else if ((env = getenv("IBV_DRIVERS"))) {
			list = strdupa(env);
			while ((env_name = strsep(&list, ":;")))
				load_driver(env_name);
		}
	}

	list_for_each_safe (&driver_name_list, name, next_name, entry) {
		load_driver(name->name);
		free(name->name);
		free(name);
	}
}
#endif
