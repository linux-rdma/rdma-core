/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */
#ifndef DOORBELL_H
#define DOORBELL_H

#include <util/mmio.h>
#include "mthca.h"

static inline void mthca_write64(uint32_t val[2], void *reg)
{
	uint64_t doorbell = (((uint64_t)val[0]) << 32) | val[1];
	mmio_write64_be(reg, htobe64(doorbell));
}

#endif
