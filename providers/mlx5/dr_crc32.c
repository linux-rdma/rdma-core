/*
 * Copyright (c) 2019, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	Redistribution and use in source and binary forms, with or
 *	without modification, are permitted provided that the following
 *	conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

/*
 * Copyright (c) 2011-2015 Stephan Brumme. All rights reserved.
 * Slicing-by-16 contributed by Bulat Ziganshin
 *
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the author be held liable for any damages arising from the
 * of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software.
 * 2. If you use this software in a product, an acknowledgment in the product
 *    documentation would be appreciated but is not required.
 * 3. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 *
 * Taken from http://create.stephan-brumme.com/crc32/ and adapted.
 */

#include <stdlib.h>
#include <string.h>
#include "mlx5dv_dr.h"

#define DR_STE_CRC_POLY		0xEDB88320L

static uint32_t dr_ste_crc_tab32[8][256];

static void dr_crc32_calc_lookup_entry(uint32_t (*tbl)[256], uint8_t i,
				       uint8_t j)
{
	tbl[i][j] = (tbl[i-1][j] >> 8) ^ tbl[0][tbl[i-1][j] & 0xff];
}

void dr_crc32_init_table(void)
{
	uint32_t crc, i, j;

	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 0; j < 8; j++) {
			if (crc & 0x00000001L)
				crc = (crc >> 1) ^ DR_STE_CRC_POLY;
			else
				crc = crc >> 1;
		}
		dr_ste_crc_tab32[0][i] = crc;
	}

	/* Init CRC lookup tables according to crc_slice_8 algorithm */
	for (i = 0; i < 256; i++) {
		dr_crc32_calc_lookup_entry(dr_ste_crc_tab32, 1, i);
		dr_crc32_calc_lookup_entry(dr_ste_crc_tab32, 2, i);
		dr_crc32_calc_lookup_entry(dr_ste_crc_tab32, 3, i);
		dr_crc32_calc_lookup_entry(dr_ste_crc_tab32, 4, i);
		dr_crc32_calc_lookup_entry(dr_ste_crc_tab32, 5, i);
		dr_crc32_calc_lookup_entry(dr_ste_crc_tab32, 6, i);
		dr_crc32_calc_lookup_entry(dr_ste_crc_tab32, 7, i);
	}
}

/* Compute CRC32 (Slicing-by-8 algorithm) */
uint32_t dr_crc32_slice8_calc(const void *input_data, size_t length)
{
	const uint32_t *current = (const uint32_t *)input_data;
	const uint8_t *current_char;
	uint32_t crc = 0, one, two;

	if (!input_data)
		return 0;

	/* Process eight bytes at once (Slicing-by-8) */
	while (length >= 8) {
		one = *current++ ^ crc;
		two = *current++;

		crc = dr_ste_crc_tab32[0][(two >> 24) & 0xff]
			^ dr_ste_crc_tab32[1][(two >> 16) & 0xff]
			^ dr_ste_crc_tab32[2][(two >> 8) & 0xff]
			^ dr_ste_crc_tab32[3][two & 0xff]
			^ dr_ste_crc_tab32[4][(one >> 24) & 0xff]
			^ dr_ste_crc_tab32[5][(one >> 16) & 0xff]
			^ dr_ste_crc_tab32[6][(one >> 8) & 0xff]
			^ dr_ste_crc_tab32[7][one & 0xff];

		length -= 8;
	}

	current_char = (const uint8_t *)current;
	/* Remaining 1 to 7 bytes (standard algorithm) */
	while (length-- != 0)
		crc = (crc >> 8) ^ dr_ste_crc_tab32[0][(crc & 0xff)
			^ *current_char++];

	return ((crc>>24) & 0xff) | ((crc<<8) & 0xff0000) |
		((crc>>8) & 0xff00) | ((crc<<24) & 0xff000000);
}
