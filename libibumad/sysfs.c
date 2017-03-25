/*
 * Copyright (c) 2004-2008 Voltaire Inc.  All rights reserved.
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
#include <config.h>

#include <endian.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "sysfs.h"

static int ret_code(void)
{
	int e = errno;

	if (e > 0)
		return -e;
	return e;
}

int sys_read_string(const char *dir_name, const char *file_name, char *str, int max_len)
{
	char path[256], *s;
	int fd, r;

	snprintf(path, sizeof(path), "%s/%s", dir_name, file_name);

	if ((fd = open(path, O_RDONLY)) < 0)
		return ret_code();

	if ((r = read(fd, (void *)str, max_len)) < 0) {
		int e = errno;
		close(fd);
		errno = e;
		return ret_code();
	}

	str[(r < max_len) ? r : max_len - 1] = 0;

	if ((s = strrchr(str, '\n')))
		*s = 0;

	close(fd);
	return 0;
}

int sys_read_guid(const char *dir_name, const char *file_name, __be64 *net_guid)
{
	char buf[32], *str, *s;
	uint64_t guid;
	int r, i;

	if ((r = sys_read_string(dir_name, file_name, buf, sizeof(buf))) < 0)
		return r;

	guid = 0;

	for (s = buf, i = 0; i < 4; i++) {
		if (!(str = strsep(&s, ": \t\n")))
			return -EINVAL;
		guid = (guid << 16) | (strtoul(str, NULL, 16) & 0xffff);
	}

	*net_guid = htobe64(guid);

	return 0;
}

int sys_read_gid(const char *dir_name, const char *file_name,
		 union umad_gid *gid)
{
	char buf[64], *str, *s;
	__be16 *ugid = (__be16 *) gid;
	int r, i;

	if ((r = sys_read_string(dir_name, file_name, buf, sizeof(buf))) < 0)
		return r;

	for (s = buf, i = 0; i < 8; i++) {
		if (!(str = strsep(&s, ": \t\n")))
			return -EINVAL;
		ugid[i] = htobe16(strtoul(str, NULL, 16) & 0xffff);
	}

	return 0;
}

int sys_read_uint64(const char *dir_name, const char *file_name, uint64_t * u)
{
	char buf[32];
	int r;

	if ((r = sys_read_string(dir_name, file_name, buf, sizeof(buf))) < 0)
		return r;

	*u = strtoull(buf, NULL, 0);

	return 0;
}

int sys_read_uint(const char *dir_name, const char *file_name, unsigned *u)
{
	char buf[32];
	int r;

	if ((r = sys_read_string(dir_name, file_name, buf, sizeof(buf))) < 0)
		return r;

	*u = strtoul(buf, NULL, 0);

	return 0;
}
