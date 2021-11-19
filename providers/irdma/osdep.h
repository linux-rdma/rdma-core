/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2021 Intel Corporation */
#ifndef IRDMA_OSDEP_H
#define IRDMA_OSDEP_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <util/udma_barrier.h>
#include <util/util.h>
#include <linux/types.h>
#include <inttypes.h>
#include <pthread.h>
#include <endian.h>

static inline void db_wr32(__u32 val, __u32 *wqe_word)
{
	*wqe_word = val;
}
#endif /* IRDMA_OSDEP_H */
