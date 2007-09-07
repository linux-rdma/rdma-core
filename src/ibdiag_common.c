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

#include "ibdiag_common.h"

FILE *
open_switch_map(char *switch_map)
{
	FILE *rc = NULL;

	if (switch_map != NULL) {
		rc = fopen(switch_map, "r");
		if (rc == NULL) {
			fprintf(stderr,
				"WARNING failed to open switch map \"%s\" (%s)\n",
				switch_map, strerror(errno));
		}
#ifdef HAVE_DEFAULT_SWITCH_MAP
	} else {
		rc = fopen(HAVE_DEFAULT_SWITCH_MAP, "r");
#endif /* HAVE_DEFAULT_SWITCH_MAP */
	}
	return (rc);
}

void
close_switch_map(FILE *fp)
{
	if (fp)
		fclose(fp);
}

char *
lookup_switch_name(FILE *switch_map_fp, uint64_t target_guid, char *nodedesc)
{
#define NAME_LEN (256)
	char     *line = NULL;
	size_t    len = 0;
	uint64_t  guid = 0;
	char     *rc = NULL;
	int       line_count = 0;

	if (switch_map_fp == NULL)
		goto done;

	rewind(switch_map_fp);
	for (line_count = 1;
		getline(&line, &len, switch_map_fp) != -1;
		line_count++) {
		line[len-1] = '\0';
		if (line[0] == '#')
			goto next_one;
		char *guid_str = strtok(line, "\"#");
		char *name = strtok(NULL, "\"#");
		if (!guid_str || !name)
			goto next_one;
		guid = strtoull(guid_str, NULL, 0);
		if (target_guid == guid) {
			rc = strdup(name);
			free (line);
			goto done;
		}
next_one:
		free (line);
		line = NULL;
	}
done:
	if (rc == NULL)
		rc = strdup(clean_nodedesc(nodedesc));
	return (rc);
}

void
iberror(const char *fn, char *msg, ...)
{
	char buf[512], *s;
	va_list va;
	int n;

	va_start(va, msg);
	n = vsprintf(buf, msg, va);
	va_end(va);
	buf[n] = 0;

	if ((s = strrchr(argv0, '/')))
		argv0 = s + 1;

	if (ibdebug)
		printf("%s: iberror: [pid %d] %s: failed: %s\n", argv0, getpid(), fn, buf);
	else
		printf("%s: iberror: failed: %s\n", argv0, buf);

	exit(-1);
}

char *
clean_nodedesc(char *nodedesc)
{
	int i = 0;

	nodedesc[63] = '\0';
	while (nodedesc[i]) {
		if (!isprint(nodedesc[i]))
			nodedesc[i] = ' ';
		i++;
	}

	return (nodedesc);
}
