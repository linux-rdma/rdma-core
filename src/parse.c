/*
 * Copyright (c) 2009-2010 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *expand(char *basename, char *args, int *str_cnt, int *str_size)
{
	char buf[256];
	char *str_buf = NULL;
	char *token, *tmp;
	int from, to, width;
	int size = 0, cnt = 0;

	token = strtok(args, ",");
	do {
		from = atoi(token);
		tmp = index(token, '-');
		if (tmp) {
			to = atoi(tmp+1);
			width = tmp - token;
		} else {
			to = from;
			width = strlen(token);
		}

		while (from <= to) {
			snprintf(buf, sizeof buf, "%s%0*d", basename, width, from);
			str_buf = realloc(str_buf, size + strlen(buf)+1);
			strcpy(&str_buf[size], buf);

			from++;
			cnt++;
			size += strlen(buf)+1;
		}

		token = strtok(NULL, ",");
	} while (token);

	*str_size = size;
	*str_cnt = cnt;
	return str_buf;
}

char **parse(char *args, int *count)
{
	char **ptrs = NULL;
	char *str_buf, *cpy, *token, *next;
	int cnt = 0, str_size = 0;
	int i;

	/* make a copy that strtok can modify */
	cpy = strdup(args);
	if (!cpy)
		return NULL;

	if (args[0] == '[') {
		cpy[0] = '\0';
		token = cpy;
		next = strtok(cpy + 1, "]");
	} else {
		token = strtok(cpy, "[");
		next = strtok(NULL, "]");
	}

	if (!next) {
		str_size = strlen(token) + 1;
		str_buf = malloc(str_size);
		if (!str_buf)
			goto out_cpy;

		strcpy(str_buf, token);
		cnt = 1;
	} else {
		str_buf = expand(cpy, next, &cnt, &str_size);
	}

	ptrs = malloc((sizeof str_buf * (cnt + 1)) + str_size);
	if (!ptrs)
		goto out_str_buf;

	memcpy(&ptrs[cnt + 1], str_buf, str_size);

	ptrs[0] = (char*) &ptrs[cnt + 1];
	for (i = 1; i < cnt; i++)
		ptrs[i] = index(ptrs[i - 1], 0) + 1;
	ptrs[i] = NULL;

	if (count)
		*count = cnt;

out_str_buf:
        free(str_buf);
out_cpy:
	free(cpy);
	return ptrs;
}
